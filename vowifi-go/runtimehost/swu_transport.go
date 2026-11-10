//go:build linux

package runtimehost

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	externalipsec "github.com/1239t/swu-go/pkg/ipsec"
	externalswu "github.com/1239t/swu-go/pkg/swu"
	"github.com/1239t/vowifi-go/runtimehost/ikev2"
	"github.com/1239t/vowifi-go/runtimehost/transport"
	"go.uber.org/zap"
)

// swuDatagramTransport adapts a datagram transport, in practice the SOCKS5
// UDP relay, to the transport interface of the SWu session: it adds and
// strips the non-ESP marker, sorts received datagrams into IKE and ESP, and
// turns relay state changes into the network events the session reacts to.
type swuDatagramTransport struct {
	tp        transport.DatagramTransport
	logger    *zap.Logger
	ikeCh     chan []byte
	espCh     chan []byte
	netEvents chan externalipsec.NetEvent
	closeOnce sync.Once
	done      chan struct{}

	mu         sync.RWMutex // guards remoteAddr, started and stopped
	remoteAddr *net.UDPAddr
	started    bool
	stopped    bool

	droppedIKE atomic.Uint64
	droppedESP atomic.Uint64
}

func newSWuDatagramTransport(tp transport.DatagramTransport, remoteAddr *net.UDPAddr, logger *zap.Logger) *swuDatagramTransport {
	if logger == nil {
		logger = zap.NewNop()
	}
	t := &swuDatagramTransport{
		tp:         tp,
		logger:     logger,
		remoteAddr: remoteAddr,
		ikeCh:      make(chan []byte, 100),
		espCh:      make(chan []byte, 1000),
		netEvents:  make(chan externalipsec.NetEvent, 10),
		done:       make(chan struct{}),
	}
	if observable, ok := tp.(transport.Socks5UDPObservable); ok {
		observable.SetEventHandler(t.onRelayEvent)
	}
	return t
}

func (t *swuDatagramTransport) Start() {
	t.mu.Lock()
	if t.started || t.stopped {
		t.mu.Unlock()
		return
	}
	t.started = true
	t.mu.Unlock()
	go t.readLoop()
}

// Stop closes the transport and its channels. It is safe to call without a
// preceding Start, which happens when session setup fails early.
func (t *swuDatagramTransport) Stop() {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		started := t.started
		t.stopped = true
		t.mu.Unlock()

		_ = t.tp.Close()
		if started {
			<-t.done
		}
		close(t.ikeCh)
		close(t.espCh)
		close(t.netEvents)
	})
}

func (t *swuDatagramTransport) isStopped() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.stopped
}

// remote returns the current peer address. The value is never modified in
// place, so callers may use it without holding the lock.
func (t *swuDatagramTransport) remote() *net.UDPAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.remoteAddr
}

func (t *swuDatagramTransport) SendIKE(data []byte) error {
	remote := t.remote()
	if remote == nil {
		return fmt.Errorf("swu proxy transport: remote address unavailable")
	}
	packet := data
	if remote.Port == 4500 {
		packet = append([]byte{0, 0, 0, 0}, data...)
	}
	_, err := t.tp.SendTo(packet, remote)
	return err
}

func (t *swuDatagramTransport) SendESP(data []byte) error {
	remote := t.remote()
	if remote == nil {
		return fmt.Errorf("swu proxy transport: remote address unavailable")
	}
	_, err := t.tp.SendTo(data, remote)
	return err
}

func (t *swuDatagramTransport) IKEPackets() <-chan []byte {
	return t.ikeCh
}

func (t *swuDatagramTransport) ESPPackets() <-chan []byte {
	return t.espCh
}

func (t *swuDatagramTransport) NetEventsChan() <-chan externalipsec.NetEvent {
	return t.netEvents
}

func (t *swuDatagramTransport) LocalPort() uint16 {
	if ua, ok := t.tp.LocalAddr().(*net.UDPAddr); ok && ua != nil {
		return uint16(ua.Port)
	}
	return 0
}

func (t *swuDatagramTransport) LocalIP() net.IP {
	if ua, ok := t.tp.LocalAddr().(*net.UDPAddr); ok && ua != nil {
		return append(net.IP(nil), ua.IP...)
	}
	return nil
}

func (t *swuDatagramTransport) RemoteIP() net.IP {
	remote := t.remote()
	if remote == nil || remote.IP == nil {
		return nil
	}
	return append(net.IP(nil), remote.IP...)
}

func (t *swuDatagramTransport) RemotePort() int {
	remote := t.remote()
	if remote == nil {
		return 0
	}
	return remote.Port
}

// SetRemotePort switches the peer port, as the session does when it moves
// from 500 to 4500. The address is replaced rather than edited because sends
// in progress still hold the previous one.
func (t *swuDatagramTransport) SetRemotePort(port int) {
	if port <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.remoteAddr == nil {
		return
	}
	updated := *t.remoteAddr
	updated.Port = port
	t.remoteAddr = &updated
}

func (t *swuDatagramTransport) LocalAddrString() string {
	if addr := t.tp.LocalAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

func (t *swuDatagramTransport) RelayAddrString() string {
	if rp, ok := t.tp.(interface{ RelayAddr() *net.UDPAddr }); ok {
		if relay := rp.RelayAddr(); relay != nil {
			return relay.String()
		}
	}
	return ""
}

func (t *swuDatagramTransport) RemoteAddrString() string {
	remote := t.remote()
	if remote == nil {
		return ""
	}
	return remote.String()
}

// emitNetEvent hands an event to the session without ever blocking the
// caller; the session only needs the most recent few.
func (t *swuDatagramTransport) emitNetEvent(ev externalipsec.NetEvent) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.stopped {
		return
	}
	select {
	case t.netEvents <- ev:
	default:
	}
}

// onRelayEvent reports the state of the proxy relay and tells the session
// when the path under an established tunnel has changed.
func (t *swuDatagramTransport) onRelayEvent(ev transport.Socks5UDPEvent) {
	switch ev.Kind {
	case transport.Socks5UDPAssociated, transport.Socks5UDPReassociated:
		reassociated := ev.Kind == transport.Socks5UDPReassociated
		adjustment := string(ev.Relay.Adjustment)
		if adjustment == "" {
			adjustment = "none"
		}
		t.logger.Info("SWu proxy relay ready",
			zap.Bool("reassociated", reassociated),
			zap.String("relay_address_adjustment", adjustment),
			zap.Bool("credentials_ignored", ev.CredentialsIgnored))
		if ev.CredentialsIgnored {
			t.logger.Warn("SWu proxy has no username/password support; the configured credentials were not used")
		}
		if ev.Relay.Adjustment == transport.Socks5RelayPrivate {
			t.logger.Warn("SWu proxy advertised a private relay address; datagrams only pass if that network is reachable from this host")
		}
		if reassociated {
			// The ePDG now sees this tunnel arrive from a new address and
			// keeps sending downlink to the old one until it receives an
			// authenticated packet. Have the session send one right away
			// instead of waiting for uplink traffic or the next DPD period.
			t.emitNetEvent(externalipsec.NetEvent{
				Type:   externalipsec.EventPathChanged,
				Reason: "proxy relay re-associated",
			})
		}
	case transport.Socks5UDPAssociationLost:
		t.logger.Warn("SWu proxy relay lost; re-associating", swuFailureFields(ev.Err)...)
	case transport.Socks5UDPAttemptFailed:
		t.logger.Warn("SWu proxy association attempt failed",
			append(swuFailureFields(ev.Err), zap.Int("consecutive_failures", ev.Attempt))...)
	case transport.Socks5UDPFailed:
		t.logger.Error("SWu proxy relay unavailable; giving up",
			append(swuFailureFields(ev.Err), zap.Int("consecutive_failures", ev.Attempt))...)
	}
}

// swuFailureFields describes a transport failure for the log. Error texts
// are left out on purpose: they carry proxy and peer addresses, which SWu
// diagnostics never record.
func swuFailureFields(err error) []zap.Field {
	if err == nil {
		return nil
	}
	var netErr net.Error
	timeout := errors.As(err, &netErr) && netErr.Timeout()

	var se *transport.Socks5Error
	if errors.As(err, &se) {
		fields := []zap.Field{
			zap.String("stage", string(se.Stage)),
			zap.String("reason", string(se.Reason)),
		}
		if se.Op != "" {
			fields = append(fields, zap.String("step", se.Op))
		}
		if se.Code != 0 {
			fields = append(fields, zap.Uint8("code", se.Code))
		}
		if timeout {
			fields = append(fields, zap.Bool("timeout", true))
		}
		if se.PeerClosed() {
			fields = append(fields, zap.Bool("closed_by_proxy", true))
		}
		return fields
	}

	reason := "io"
	switch {
	case errors.Is(err, transport.ErrSocks5RelayUnavailable):
		reason = "relay_unavailable"
	case errors.Is(err, net.ErrClosed):
		reason = "closed"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		reason = "closed_by_proxy"
	case timeout:
		reason = "timeout"
	}
	return []zap.Field{zap.String("reason", reason)}
}

// noteDropped counts a datagram discarded because the session is not
// draining its queue, and logs the first and then every thousandth.
func (t *swuDatagramTransport) noteDropped(counter *atomic.Uint64, kind string) {
	if n := counter.Add(1); n == 1 || n%1000 == 0 {
		t.logger.Warn("SWu receive queue full; datagram dropped",
			zap.String("kind", kind),
			zap.Uint64("dropped_total", n))
	}
}

func (t *swuDatagramTransport) readLoop() {
	defer close(t.done)
	buf := make([]byte, 65535)
	for {
		n, _, err := t.tp.RecvFrom(buf)
		if err != nil {
			if !t.isStopped() {
				// The transport ended by itself. Without this the tunnel would
				// stay up in name while receiving nothing; waking the session's
				// liveness check lets it notice and rebuild.
				t.logger.Error("SWu datagram transport stopped receiving", swuFailureFields(err)...)
				t.emitNetEvent(externalipsec.NetEvent{
					Type:   externalipsec.EventNetworkDown,
					Reason: "datagram transport closed",
				})
			}
			return
		}
		if n <= 0 {
			continue
		}
		data := append([]byte(nil), buf[:n]...)
		if len(data) == 1 && data[0] == 0xff {
			continue
		}
		if ikeData, ok := parseSWuIKEPayload(data); ok {
			select {
			case t.ikeCh <- ikeData:
			default:
				t.noteDropped(&t.droppedIKE, "ike")
			}
			continue
		}
		if len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == 0 {
			data = data[4:]
		}
		if len(data) == 0 {
			continue
		}
		select {
		case t.espCh <- data:
		default:
			t.noteDropped(&t.droppedESP, "esp")
		}
	}
}

func parseSWuIKEPayload(data []byte) ([]byte, bool) {
	if len(data) < 4 {
		return nil, false
	}
	if binary.BigEndian.Uint32(data[:4]) == 0 {
		if len(data) < 4+ikev2.IKE_HEADER_LEN {
			return nil, false
		}
		ikeData := data[4:]
		if looksLikeSWuIKE(ikeData) {
			return ikeData, true
		}
		return nil, false
	}
	if len(data) < ikev2.IKE_HEADER_LEN {
		return nil, false
	}
	if looksLikeSWuIKE(data) {
		return data, true
	}
	return nil, false
}

func looksLikeSWuIKE(data []byte) bool {
	if len(data) < ikev2.IKE_HEADER_LEN {
		return false
	}
	if data[17] != 0x20 {
		return false
	}
	switch ikev2.ExchangeType(data[18]) {
	case ikev2.IKE_SA_INIT, ikev2.IKE_AUTH, ikev2.CREATE_CHILD_SA, ikev2.INFORMATIONAL:
		return true
	default:
		return false
	}
}

// buildSWuTransportFactory returns the factory for sessions that go through
// the proxy, or nil when the route is direct.
func buildSWuTransportFactory(proxy *ProxyConfig, logger *zap.Logger) func(string, string) (externalswu.Transport, error) {
	routePolicy := buildRoutePolicy(proxy)
	if routePolicy.Kind != transport.ProxySocks5UDPAssociate {
		return nil
	}
	return func(_, remote string) (externalswu.Transport, error) {
		remoteAddr, err := net.ResolveUDPAddr("udp", remote)
		if err != nil {
			return nil, fmt.Errorf("swu proxy transport resolve remote %q: %w", remote, err)
		}
		tp, err := transport.NewSocks5UDPTransport(routePolicy.Addr, routePolicy.Username, routePolicy.Password)
		if err != nil {
			return nil, err
		}
		return newSWuDatagramTransport(tp, remoteAddr, logger), nil
	}
}

func buildObservedSWuTransportFactory(
	proxy *ProxyConfig,
	candidate epdgCandidate,
	logger *zap.Logger,
	baseFactory func(string, string) (externalswu.Transport, error),
) func(string, string) (externalswu.Transport, error) {
	if baseFactory == nil {
		relayLogger := logger
		if relayLogger == nil {
			relayLogger = zap.NewNop()
		}
		baseFactory = buildSWuTransportFactory(proxy, relayLogger.With(
			zap.String("address_family", candidate.Family),
			zap.Int("candidate_index", candidate.Index),
			zap.Int("candidate_total", candidate.Total),
		))
	}
	if baseFactory == nil {
		baseFactory = func(local, remote string) (externalswu.Transport, error) {
			return externalipsec.NewSocketManager(local, remote, "")
		}
	}
	return func(local, remote string) (externalswu.Transport, error) {
		remote = canonicalSWURemote(remote, candidate)
		inner, err := baseFactory(local, remote)
		if err != nil {
			return nil, err
		}
		return newObservedSWUTransport(inner, candidate, logger), nil
	}
}

func canonicalSWURemote(remote string, candidate epdgCandidate) string {
	if candidate.IP == nil {
		return remote
	}
	_, port, err := net.SplitHostPort(remote)
	if err != nil {
		if separator := strings.LastIndex(remote, ":"); separator >= 0 && separator+1 < len(remote) {
			port = remote[separator+1:]
		}
	}
	if strings.TrimSpace(port) == "" {
		return remote
	}
	return net.JoinHostPort(candidate.IP.String(), port)
}
