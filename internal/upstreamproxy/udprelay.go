package upstreamproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/transport"
)

// UDPRelayConfig configures a UDPRelay: forward UDP traffic aimed at
// LocalIP:Ports[i] to TargetHost:TargetPorts[i] (and back), through a
// SOCKS5 proxy's UDP ASSOCIATE. The relay mechanism itself (SOCKS5
// handshake, UDP ASSOCIATE, bidirectional datagram forwarding) is
// validated and generically correct -- see spike/udprelayunit for a real
// bidirectional round trip (client -> relay -> proxy -> echo server ->
// proxy -> relay -> client) through a real local SOCKS5 proxy (dante).
//
// # Known dead end: fronting a same-host charon's own IKEv2 traffic
//
// This does NOT work for making a same-host charon's SWu tunnel go through
// a proxy by having this relay present a local "fake ePDG" address on
// ports 500/4500 for charon to dial -- confirmed by reading strongSwan's
// own source (src/libcharon/network/receiver.c,
// src/libcharon/plugins/socket_default/socket_default_socket.c), not by
// assumption:
//
//  1. charon's socket-default plugin always binds 0.0.0.0 (wildcard) on
//     BOTH its IKE port and its NAT-T port at startup (open_socketpair),
//     regardless of charon.port/port_nat_t and regardless of whether any
//     connection ever actually floats to NAT-T. A wildcard bind on a port
//     claims that port on every local address, so nothing else on the
//     same host can bind port 500 or 4500 on ANY address while charon is
//     up -- moving charon off those ports (engine/swu/charon.Options.Port/
//     PortNATT) is the only way to free them for a relay.
//  2. But moving charon off 500/4500 breaks its own receiver: charon's
//     receive path (receiver.c's receive_packets) treats a packet as
//     ambiguous (could be ESP, could be IKE with a non-ESP marker) unless
//     EITHER its source OR its destination port is exactly 500 (the
//     IKEV2_UDP_PORT constant, not derived from charon.port). A first-ever
//     IKE_SA_INIT request has no non-ESP marker, so once charon's own port
//     is moved and the packet arrives via a proxy hop that used some other
//     ephemeral source port (which real SOCKS5 proxies do, confirmed
//     against dante), BOTH ports are non-500 and charon silently hands the
//     packet to its ESP callback instead of processing it as IKE --
//     confirmed with tcpdump (the packet physically arrives) plus a
//     bumped charon.filelog net level (nothing after "received packet";
//     no IKE processing is ever logged).
//  3. Even ignoring (2), IKEv2's NAT-T float target is hardcoded to port
//     4500 (IKEV2_NATT_PORT) on the peer side regardless of any
//     remote_port config, so a relay fronting the post-float exchange
//     would need port 4500 specifically too -- which is exactly the port
//     item (1) already says can't be freed without moving charon, which
//     item (2) says breaks receiving.
//
// None of this applies to fronting a genuinely remote peer (a real ePDG on
// a different machine never competes for this host's own port 500/4500,
// and its own receiver never sees our local port juggling) -- only to
// presenting a same-host relay as a stand-in for one, which would need
// real network-namespace isolation (a separate IP stack for charon, e.g.
// via a veth pair) to avoid both problems at once. That hasn't been built.
type UDPRelayConfig struct {
	ProxyAddr string
	Username  string
	Password  string

	// TargetHost is the real peer's address (e.g. an ePDG's FQDN or IP).
	// Resolved once, locally, when the relay starts -- resolution itself is
	// NOT proxied, only the UDP payloads are.
	TargetHost string

	// LocalIP is where the relay listens, once per entry in Ports.
	LocalIP string
	Ports   []int

	// TargetPorts maps each Ports[i] to the port to forward it to on
	// TargetHost. Defaults to Ports itself (the normal case: a real ePDG
	// listens on the same 500/4500 the relay presents) if left nil --
	// set explicitly only when the listen and forward-to ports must
	// differ, e.g. to work around the same-host conflict described above.
	TargetPorts []int

	// Logf receives one line for every change in the state of the proxy
	// association. Optional.
	Logf func(format string, args ...any)

	// retry replaces the retry policy for a lost proxy association; the zero
	// value keeps the transport's defaults.
	retry relayRetry
}

// relayRetry is the policy for making a lost proxy association again.
type relayRetry struct {
	maxAttempts int
	backoffBase time.Duration
	backoffMax  time.Duration
	minStable   time.Duration
}

// UDPRelayStats counts what a relay has done.
type UDPRelayStats struct {
	// Forwarded counts datagrams handed to the proxy for the target.
	Forwarded uint64
	// Returned counts datagrams delivered back to a local peer.
	Returned uint64
	// Dropped counts datagrams that could not be passed on: the proxy
	// association was down, or there was no local peer to return them to.
	Dropped uint64
	// Associations counts proxy associations made, the first one included.
	Associations uint64
}

// relayAssociateTimeout bounds the TCP connect and every SOCKS5 exchange.
const relayAssociateTimeout = 5 * time.Second

// UDPRelay is a running relay; call Close to tear it down.
//
// A relay stops on its own when the proxy association is lost and cannot be
// made again: Done is then closed and Err says why. It never keeps listening
// while silently forwarding nowhere.
type UDPRelay struct {
	tp     transport.DatagramTransport
	target net.IP
	logf   func(format string, args ...any)

	listeners   []*net.UDPConn
	targetPorts []int       // by listener index
	byTarget    map[int]int // target port -> listener index

	mu    sync.Mutex
	peers []*net.UDPAddr // by listener index: last-seen local peer (e.g. charon) to reply to
	err   error

	running  atomic.Bool
	stopOnce sync.Once
	stopped  chan struct{}
	done     chan struct{}

	forwarded atomic.Uint64
	returned  atomic.Uint64
	dropped   atomic.Uint64
}

// StartUDPRelay binds cfg.LocalIP on each of cfg.Ports, obtains a UDP
// association from the SOCKS5 proxy and starts pumping datagrams in both
// directions. It returns once the association is up, or with the reason it
// could not be made.
//
// The proxy side is the transport the tunnel itself uses, so the relay gets
// the same negotiation, the same handling of the advertised relay address,
// and re-association when the proxy drops the control connection.
func StartUDPRelay(ctx context.Context, cfg UDPRelayConfig) (*UDPRelay, error) {
	proxyAddr := strings.TrimSpace(cfg.ProxyAddr)
	if proxyAddr == "" {
		return nil, errors.New("upstreamproxy: UDPRelayConfig.ProxyAddr is required")
	}
	targetHost := strings.TrimSpace(cfg.TargetHost)
	if targetHost == "" {
		return nil, errors.New("upstreamproxy: UDPRelayConfig.TargetHost is required")
	}
	localIPText := strings.TrimSpace(cfg.LocalIP)
	if localIPText == "" {
		return nil, errors.New("upstreamproxy: UDPRelayConfig.LocalIP is required")
	}
	localIP := net.ParseIP(localIPText)
	if localIP == nil {
		// A name here would silently become the wildcard address.
		return nil, fmt.Errorf("upstreamproxy: UDPRelayConfig.LocalIP %q is not an IP address", localIPText)
	}
	if len(cfg.Ports) == 0 {
		return nil, errors.New("upstreamproxy: UDPRelayConfig.Ports is required")
	}
	targetPorts := cfg.TargetPorts
	if targetPorts == nil {
		targetPorts = cfg.Ports
	}
	if len(targetPorts) != len(cfg.Ports) {
		return nil, errors.New("upstreamproxy: UDPRelayConfig.TargetPorts must be the same length as Ports")
	}
	byTarget := make(map[int]int, len(targetPorts))
	for i, port := range targetPorts {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("upstreamproxy: target port %d is out of range", port)
		}
		if _, dup := byTarget[port]; dup {
			// Replies are routed back by the port they come from.
			return nil, fmt.Errorf("upstreamproxy: target port %d is listed twice", port)
		}
		byTarget[port] = i
	}
	for _, port := range cfg.Ports {
		if port < 0 || port > 65535 {
			return nil, fmt.Errorf("upstreamproxy: listen port %d is out of range", port)
		}
	}

	target, err := resolveRelayTarget(ctx, targetHost)
	if err != nil {
		return nil, fmt.Errorf("upstreamproxy: resolve target %s: %w", targetHost, err)
	}

	r := &UDPRelay{
		target:      target,
		logf:        cfg.Logf,
		targetPorts: append([]int(nil), targetPorts...),
		byTarget:    byTarget,
		peers:       make([]*net.UDPAddr, len(cfg.Ports)),
		stopped:     make(chan struct{}),
		done:        make(chan struct{}),
	}
	for _, port := range cfg.Ports {
		ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP, Port: port})
		if err != nil {
			r.closeListeners()
			return nil, fmt.Errorf("upstreamproxy: listen %s: %w", net.JoinHostPort(localIPText, strconv.Itoa(port)), err)
		}
		r.listeners = append(r.listeners, ln)
	}

	// The outcome of the first association attempt decides whether the relay
	// starts; later changes are only reported.
	first := make(chan error, 1)
	var firstOnce sync.Once
	tp, err := transport.NewSocks5UDPTransportWithOptions(transport.Socks5UDPOptions{
		ProxyAddr: proxyAddr,
		Username:  cfg.Username,
		Password:  cfg.Password,
		Timeout:   relayAssociateTimeout,

		MaxAttempts: cfg.retry.maxAttempts,
		BackoffBase: cfg.retry.backoffBase,
		BackoffMax:  cfg.retry.backoffMax,
		MinStable:   cfg.retry.minStable,

		OnEvent: func(ev transport.Socks5UDPEvent) {
			switch ev.Kind {
			case transport.Socks5UDPAssociated:
				firstOnce.Do(func() { first <- nil })
			case transport.Socks5UDPAttemptFailed, transport.Socks5UDPFailed:
				firstOnce.Do(func() { first <- ev.Err })
			}
			r.report(ev)
		},
	})
	if err != nil {
		r.closeListeners()
		return nil, fmt.Errorf("upstreamproxy: %w", err)
	}
	r.tp = tp

	var wg sync.WaitGroup
	wg.Add(len(r.listeners) + 1)
	for i := range r.listeners {
		go func(index int) {
			defer wg.Done()
			r.pumpLocalToRelay(index)
		}(i)
	}
	go func() {
		defer wg.Done()
		r.pumpRelayToLocal()
	}()
	go func() {
		wg.Wait()
		close(r.done)
	}()

	select {
	case err = <-first:
	case <-ctx.Done():
		err = context.Cause(ctx)
	}
	if err != nil {
		r.shutdown()
		<-r.done
		return nil, relayStartError(proxyAddr, err)
	}
	r.running.Store(true)
	return r, nil
}

// resolveRelayTarget resolves host locally, preferring IPv4 as the relay
// always has.
func resolveRelayTarget(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			return addr.IP, nil
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("no address found")
	}
	return addrs[0].IP, nil
}

func relayStartError(proxyAddr string, err error) error {
	var se *transport.Socks5Error
	if errors.As(err, &se) {
		switch se.Stage {
		case transport.Socks5StageConnect:
			return fmt.Errorf("upstreamproxy: dial proxy %s: %w", proxyAddr, err)
		case transport.Socks5StageHandshake:
			return fmt.Errorf("upstreamproxy: socks5 handshake: %w", err)
		}
	}
	return fmt.Errorf("upstreamproxy: socks5 udp associate: %w", err)
}

// report writes one line about a change in the proxy association.
func (r *UDPRelay) report(ev transport.Socks5UDPEvent) {
	if r.logf == nil {
		return
	}
	switch ev.Kind {
	case transport.Socks5UDPAssociated, transport.Socks5UDPReassociated:
		state := "ready"
		if ev.Kind == transport.Socks5UDPReassociated {
			state = "re-established"
		}
		r.logf("proxy association %s", state)
		if ev.Relay.Adjustment != transport.Socks5RelayAsAdvertised {
			r.logf("proxy advertised a relay address that needed interpreting (%s)", ev.Relay.Adjustment)
		}
		if ev.CredentialsIgnored {
			r.logf("proxy has no username/password support; the configured credentials are not used")
		}
	case transport.Socks5UDPAssociationLost:
		r.logf("proxy association lost; re-associating")
	case transport.Socks5UDPAttemptFailed:
		// The attempt that keeps the relay from starting is returned to the
		// caller of StartUDPRelay instead.
		if r.running.Load() {
			r.logf("proxy association attempt %d failed: %v", ev.Attempt, ev.Err)
		}
	case transport.Socks5UDPFailed:
		r.logf("proxy association could not be made again; relay stopping")
	}
}

// Close tears down every listener and the proxy association (closing the
// SOCKS5 control connection ends the UDP ASSOCIATE session server-side).
func (r *UDPRelay) Close() error {
	r.shutdown()
	<-r.done
	return nil
}

// Done is closed when the relay has stopped, whether by Close or because
// the proxy association was lost for good.
func (r *UDPRelay) Done() <-chan struct{} { return r.done }

// Err reports why the relay stopped on its own; it is nil while the relay
// runs and after a plain Close.
func (r *UDPRelay) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// LocalAddrs returns the addresses the relay listens on, in the order of
// UDPRelayConfig.Ports.
func (r *UDPRelay) LocalAddrs() []*net.UDPAddr {
	addrs := make([]*net.UDPAddr, 0, len(r.listeners))
	for _, ln := range r.listeners {
		if addr, ok := ln.LocalAddr().(*net.UDPAddr); ok {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// Stats returns the relay's counters.
func (r *UDPRelay) Stats() UDPRelayStats {
	stats := UDPRelayStats{
		Forwarded: r.forwarded.Load(),
		Returned:  r.returned.Load(),
		Dropped:   r.dropped.Load(),
	}
	if observable, ok := r.tp.(transport.Socks5UDPObservable); ok {
		stats.Associations = observable.Stats().Associations
	}
	return stats
}

func (r *UDPRelay) isStopped() bool {
	select {
	case <-r.stopped:
		return true
	default:
		return false
	}
}

func (r *UDPRelay) shutdown() {
	r.stopOnce.Do(func() {
		close(r.stopped)
		r.closeListeners()
		if r.tp != nil {
			_ = r.tp.Close()
		}
	})
}

func (r *UDPRelay) closeListeners() {
	for _, ln := range r.listeners {
		_ = ln.Close()
	}
}

// pumpLocalToRelay reads datagrams arriving at a local listener (from
// charon), remembers the sender so replies can be routed back, and
// forwards each one through the proxy to the target port that listener
// stands for (usually the same port -- see UDPRelayConfig.TargetPorts for
// the one case it isn't).
//
// A datagram that arrives while the proxy association is down is dropped,
// as on any lossy path: IKE retransmits.
func (r *UDPRelay) pumpLocalToRelay(index int) {
	ln := r.listeners[index]
	target := &net.UDPAddr{IP: r.target, Port: r.targetPorts[index]}
	buf := make([]byte, 65535)
	for {
		n, peer, err := ln.ReadFromUDP(buf)
		if err != nil {
			if r.isStopped() || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		r.mu.Lock()
		r.peers[index] = peer
		r.mu.Unlock()

		if _, err := r.tp.SendTo(buf[:n], target); err != nil {
			r.dropped.Add(1)
			continue
		}
		r.forwarded.Add(1)
	}
}

// pumpRelayToLocal reads datagrams coming back through the proxy, maps the
// target port each one came from back to the listener that forwards to it,
// and delivers the payload to the last-seen peer on that listener.
//
// The proxy side only fails once the association is lost for good, which
// ends the relay.
func (r *UDPRelay) pumpRelayToLocal() {
	buf := make([]byte, 65535)
	for {
		n, from, err := r.tp.RecvFrom(buf)
		if err != nil {
			if !r.isStopped() {
				r.mu.Lock()
				r.err = err
				r.mu.Unlock()
				r.shutdown()
			}
			return
		}
		if from == nil {
			r.dropped.Add(1)
			continue
		}
		index, ok := r.byTarget[from.Port]
		if !ok {
			r.dropped.Add(1) // from a port nothing was sent to: no peer to give it to
			continue
		}
		r.mu.Lock()
		peer := r.peers[index]
		r.mu.Unlock()
		if peer == nil {
			r.dropped.Add(1) // nothing has sent from this local port yet
			continue
		}
		if _, err := r.listeners[index].WriteToUDP(buf[:n], peer); err != nil {
			r.dropped.Add(1)
			continue
		}
		r.returned.Add(1)
	}
}
