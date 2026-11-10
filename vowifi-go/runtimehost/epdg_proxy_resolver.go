package runtimehost

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/1239t/vowifi-go/runtimehost/transport"
)

// epdgDNSRescueEnv controls the rescue of ePDG name resolution through the
// proxy. Unset, the default public resolvers are used; "off" disables the
// rescue; any other value is a comma separated list of resolver addresses
// (IP or IP:port) to ask through the proxy instead.
const epdgDNSRescueEnv = "VOHIVE_EPDG_DNS_RESCUE"

const (
	// epdgRescueHeadStart is how long the local resolver is left alone
	// before the proxy is asked as well.
	epdgRescueHeadStart = 2 * time.Second
	// epdgRescueProxyTimeout bounds the TCP connect and every SOCKS5
	// exchange of the rescue.
	epdgRescueProxyTimeout = 3 * time.Second
	// epdgRescueServerTimeout is how long one resolver gets to answer.
	epdgRescueServerTimeout = 2 * time.Second
	// epdgRescueMaxServers bounds the resolvers asked, and with them the
	// time a rescue can take.
	epdgRescueMaxServers = 4
)

var defaultEPDGRescueServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// localEPDGResolver is the resolver of the host; tests replace it.
var localEPDGResolver epdgResolver = net.DefaultResolver

var (
	errEPDGRescueTimeout   = errors.New("epdg dns rescue: no resolver answered through the proxy")
	errEPDGRescueNoAddress = errors.New("epdg dns rescue: the resolvers know no address for the name")
)

// epdgResolverFor returns the resolver for the ePDG host name of a start
// request: the local resolver, backed by the proxy when the session goes
// through one.
func epdgResolverFor(req StartRequest) epdgResolver {
	if req.epdgResolver != nil {
		return req.epdgResolver
	}
	// The route is derived exactly as for the tunnel, so the rescue is
	// available whenever the session itself goes through the proxy.
	route := buildRoutePolicy(req.Proxy)
	if route.Kind != transport.ProxySocks5UDPAssociate {
		return localEPDGResolver
	}
	servers, enabled := epdgRescueServers(os.Getenv(epdgDNSRescueEnv))
	if !enabled {
		return localEPDGResolver
	}
	if len(servers) == 0 {
		logger.Warn("ePDG 域名经代理解析已停用：环境变量未包含可用的解析器地址",
			logger.String("trace_id", strings.TrimSpace(req.TraceID)),
			logger.String("env", epdgDNSRescueEnv))
		return localEPDGResolver
	}
	return &proxyRescueResolver{
		local:         localEPDGResolver,
		proxyID:       strings.TrimSpace(req.Proxy.ID),
		route:         route,
		servers:       servers,
		headStart:     epdgRescueHeadStart,
		proxyTimeout:  epdgRescueProxyTimeout,
		serverTimeout: epdgRescueServerTimeout,
		traceID:       strings.TrimSpace(req.TraceID),
	}
}

// epdgRescueServers interprets the value of epdgDNSRescueEnv. enabled is
// false only when the rescue was switched off on purpose.
func epdgRescueServers(raw string) (servers []*net.UDPAddr, enabled bool) {
	raw = strings.TrimSpace(raw)
	switch strings.ToLower(raw) {
	case "off", "0", "false", "no", "disabled":
		return nil, false
	case "":
		return parseEPDGRescueServers(defaultEPDGRescueServers), true
	}
	return parseEPDGRescueServers(strings.Split(raw, ",")), true
}

// parseEPDGRescueServers keeps the entries that are an IP address with an
// optional port, without duplicates and up to epdgRescueMaxServers. Host
// names are not accepted: resolving them is the problem being solved.
func parseEPDGRescueServers(items []string) []*net.UDPAddr {
	var servers []*net.UDPAddr
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		host, port := item, 53
		if net.ParseIP(strings.Trim(item, "[]")) != nil {
			host = strings.Trim(item, "[]")
		} else {
			h, p, err := net.SplitHostPort(item)
			if err != nil {
				continue
			}
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				continue
			}
			host, port = h, n
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		addr := &net.UDPAddr{IP: ip, Port: port}
		if _, dup := seen[addr.String()]; dup {
			continue
		}
		seen[addr.String()] = struct{}{}
		servers = append(servers, addr)
		if len(servers) == epdgRescueMaxServers {
			break
		}
	}
	return servers
}

// proxyRescueResolver resolves the ePDG host name the way a session always
// has, with the local resolver, and falls back to public resolvers reached
// through the proxy's UDP relay when the local resolver fails. A proxy is
// typically configured because the local network is not the SIM's home
// network, and that is also where local DNS is most likely to be unable to
// resolve an operator's ePDG name.
//
// The local answer always wins. The relay is consulted only once the local
// resolver has failed or has been silent for headStart, and its answer is
// used only if the local resolver ends without one. A host whose DNS works
// therefore behaves exactly as before and sends nothing extra through the
// proxy; the candidate order and the tunnel budget, which start after
// resolution, are not involved.
type proxyRescueResolver struct {
	local   epdgResolver
	proxyID string
	route   transport.RoutePolicy
	servers []*net.UDPAddr

	headStart     time.Duration
	proxyTimeout  time.Duration
	serverTimeout time.Duration

	traceID string
}

type epdgLookup struct {
	addrs []net.IPAddr
	err   error
}

func (l epdgLookup) ok() bool { return l.err == nil && len(l.addrs) > 0 }

func (r *proxyRescueResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if net.ParseIP(host) != nil {
		return r.local.LookupIPAddr(ctx, host)
	}

	localCh := make(chan epdgLookup, 1)
	go func() {
		addrs, err := r.local.LookupIPAddr(ctx, host)
		localCh <- epdgLookup{addrs: addrs, err: err}
	}()

	headStart := time.NewTimer(r.headStart)
	defer headStart.Stop()

	var local epdgLookup
	localDone := false
	select {
	case local = <-localCh:
		if local.ok() {
			return local.addrs, nil
		}
		localDone = true
	case <-headStart.C:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	rescueCtx, cancelRescue := context.WithCancel(ctx)
	defer cancelRescue()
	rescueCh := make(chan epdgLookup, 1)
	go func() {
		addrs, err := r.lookupViaProxy(rescueCtx, host)
		rescueCh <- epdgLookup{addrs: addrs, err: err}
	}()

	if !localDone {
		select {
		case local = <-localCh:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if local.ok() {
			return local.addrs, nil
		}
	}

	var rescue epdgLookup
	select {
	case rescue = <-rescueCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if rescue.ok() {
		ipv4, ipv6 := countAddressFamilies(rescue.addrs)
		logger.Info("ePDG 域名本机解析失败，已采用经前置代理解析的结果",
			logger.String("trace_id", r.traceID),
			logger.String("proxy_id", r.proxyID),
			logger.Int("ipv4", ipv4),
			logger.Int("ipv6", ipv6))
		return rescue.addrs, nil
	}
	logger.Warn("ePDG 域名本机解析失败，经前置代理解析也未成功",
		logger.String("trace_id", r.traceID),
		logger.String("proxy_id", r.proxyID),
		logger.String("reason", epdgRescueFailureReason(rescue.err)))
	if local.err != nil {
		return nil, local.err
	}
	return nil, errEPDGRescueNoAddress
}

// lookupViaProxy asks the configured resolvers, one after the other, for
// the A and AAAA records of host through a UDP association of its own.
func (r *proxyRescueResolver) lookupViaProxy(ctx context.Context, host string) ([]net.IPAddr, error) {
	tp, err := transport.NewSocks5UDPTransportWithOptions(transport.Socks5UDPOptions{
		ProxyAddr:   r.route.Addr,
		Username:    r.route.Username,
		Password:    r.route.Password,
		Timeout:     r.proxyTimeout,
		MaxAttempts: 1,
	})
	if err != nil {
		return nil, err
	}
	// Closing the transport is what ends a blocked receive and an
	// association in progress, so it also carries the cancellation.
	stop := context.AfterFunc(ctx, func() { _ = tp.Close() })
	defer stop()
	defer tp.Close()

	replies := make(chan dnsDatagram, 16)
	reading := false
	var lastErr error
	for _, server := range r.servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		queries, err := newEPDGQueries()
		if err != nil {
			return nil, err
		}
		for i := range queries {
			packet, err := encodeDNSQuery(queries[i].id, host, queries[i].qtype)
			if err != nil {
				return nil, err
			}
			if _, err := tp.SendTo(packet, server); err != nil {
				// The relay is not there; another resolver cannot change that.
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, ctxErr
				}
				return nil, err
			}
		}
		if !reading {
			reading = true
			go readDNSDatagrams(tp, replies)
		}
		addrs, err := collectEPDGReplies(ctx, replies, server, host, queries, r.serverTimeout)
		if len(addrs) > 0 {
			return addrs, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		lastErr = err
	}
	return nil, lastErr
}

type dnsDatagram struct {
	from    *net.UDPAddr
	payload []byte
}

// readDNSDatagrams hands on what arrives through the relay until the
// transport is closed. It never blocks on a reader that has stopped
// listening.
func readDNSDatagrams(tp transport.DatagramTransport, out chan<- dnsDatagram) {
	buf := make([]byte, 4096)
	for {
		n, from, err := tp.RecvFrom(buf)
		if err != nil {
			return
		}
		select {
		case out <- dnsDatagram{from: from, payload: append([]byte(nil), buf[:n]...)}:
		default:
		}
	}
}

type epdgQuery struct {
	id    uint16
	qtype uint16
	done  bool
	ips   []net.IP
	err   error
}

// newEPDGQueries prepares the A and the AAAA query with unpredictable
// transaction ids. A comes first: its addresses lead the result.
func newEPDGQueries() ([]epdgQuery, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("epdg dns rescue: transaction id: %w", err)
	}
	first := binary.BigEndian.Uint16(raw[0:])
	second := binary.BigEndian.Uint16(raw[2:])
	if second == first {
		second++
	}
	return []epdgQuery{{id: first, qtype: dnsTypeA}, {id: second, qtype: dnsTypeAAAA}}, nil
}

// collectEPDGReplies waits until server has answered every query or timeout
// has passed and returns the addresses found, IPv4 first.
func collectEPDGReplies(
	ctx context.Context,
	replies <-chan dnsDatagram,
	server *net.UDPAddr,
	host string,
	queries []epdgQuery,
	timeout time.Duration,
) ([]net.IPAddr, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	pending := len(queries)
wait:
	for pending > 0 {
		select {
		case datagram := <-replies:
			if !fromDNSServer(datagram.from, server) {
				continue
			}
			for i := range queries {
				query := &queries[i]
				if query.done {
					continue
				}
				ips, err := parseDNSReply(datagram.payload, query.id, host, query.qtype)
				if errors.Is(err, errDNSNotOurs) {
					continue
				}
				query.done, query.ips, query.err = true, ips, err
				pending--
				break
			}
		case <-timer.C:
			break wait
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	var (
		addrs    []net.IPAddr
		firstErr error
		answered bool
	)
	for _, query := range queries {
		if !query.done {
			continue
		}
		answered = true
		if query.err != nil && firstErr == nil {
			firstErr = query.err
		}
		for _, ip := range query.ips {
			addrs = append(addrs, net.IPAddr{IP: ip})
		}
	}
	switch {
	case len(addrs) > 0:
		return addrs, nil
	case firstErr != nil:
		return nil, firstErr
	case !answered:
		return nil, errEPDGRescueTimeout
	}
	return nil, errEPDGRescueNoAddress
}

// fromDNSServer reports whether a relayed datagram can come from server.
// A proxy that does not report the sender (no address, or the unspecified
// one) is given the benefit of the doubt; the transaction id and the
// question still have to match.
func fromDNSServer(from, server *net.UDPAddr) bool {
	if from == nil || len(from.IP) == 0 || from.IP.IsUnspecified() {
		return true
	}
	return from.IP.Equal(server.IP)
}

func countAddressFamilies(addrs []net.IPAddr) (ipv4, ipv6 int) {
	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			ipv4++
		} else {
			ipv6++
		}
	}
	return ipv4, ipv6
}

// epdgRescueFailureReason names why the rescue did not produce addresses.
// Error texts stay out of the log: they carry proxy and resolver addresses.
func epdgRescueFailureReason(err error) string {
	var (
		proxyErr *transport.Socks5Error
		rcodeErr *dnsRCodeError
	)
	switch {
	case err == nil:
		return "no_address"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled"
	case errors.As(err, &rcodeErr):
		return "dns_rcode_" + strconv.Itoa(rcodeErr.code)
	case errors.Is(err, errEPDGRescueTimeout):
		return "dns_timeout"
	case errors.Is(err, errEPDGRescueNoAddress):
		return "no_address"
	case errors.Is(err, errDNSMalformed):
		return "dns_malformed"
	case errors.As(err, &proxyErr):
		return "proxy_" + string(proxyErr.Stage)
	case errors.Is(err, transport.ErrSocks5RelayUnavailable), errors.Is(err, net.ErrClosed):
		return "proxy_unavailable"
	}
	return "other"
}
