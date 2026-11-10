//go:build linux

package runtimehost

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/transport"
	"github.com/1239t/vowifi-go/runtimehost/transport/socks5sim"
)

var errSyntheticLocalDNS = errors.New("synthetic local resolver failure")

// scriptedEPDGResolver stands in for the resolver of the host: it answers
// after delay, or gives up when the lookup is cancelled first.
type scriptedEPDGResolver struct {
	delay     time.Duration
	addresses []net.IPAddr
	err       error
	calls     atomic.Int32
}

func (r *scriptedEPDGResolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	r.calls.Add(1)
	if r.delay > 0 {
		timer := time.NewTimer(r.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	return append([]net.IPAddr(nil), r.addresses...), nil
}

// testDNSZone is what a simulated public resolver knows about the name.
type testDNSZone struct {
	a, aaaa []net.IP
	rcode   int
	// forgeA answers the A query under a different transaction id.
	forgeA bool
}

// startTestDNSServer runs a resolver behind the simulated proxy. It is a
// UDP peer on loopback, reachable only through the relay like a public
// resolver is in the field.
func startTestDNSServer(t *testing.T, zone testDNSZone) *socks5sim.UDPPeer {
	t.Helper()
	peer, err := socks5sim.StartUDPPeer()
	if err != nil {
		t.Fatalf("start DNS peer: %v", err)
	}
	t.Cleanup(peer.Close)
	peer.SetResponder(func(query []byte) []byte {
		if len(query) < dnsHeaderLen {
			return nil
		}
		_, questionEnd, err := readDNSName(query, dnsHeaderLen)
		if err != nil || questionEnd+4 > len(query) {
			return nil
		}
		reply := dnsTestReply{rcode: zone.rcode}
		switch binary.BigEndian.Uint16(query[questionEnd:]) {
		case dnsTypeA:
			reply.ips = zone.a
			if zone.forgeA {
				reply.idOffset = 1
			}
		case dnsTypeAAAA:
			reply.ips = zone.aaaa
		}
		return buildDNSTestReply(query, reply)
	})
	return peer
}

func startRescueProxy(t *testing.T) *socks5sim.Server {
	t.Helper()
	proxy, err := socks5sim.Start(socks5sim.Config{})
	if err != nil {
		t.Fatalf("start simulated proxy: %v", err)
	}
	t.Cleanup(proxy.Close)
	return proxy
}

// newTestRescueResolver builds the resolver with test-sized timeouts.
func newTestRescueResolver(local epdgResolver, proxyAddr string, servers ...*net.UDPAddr) *proxyRescueResolver {
	return &proxyRescueResolver{
		local:         local,
		proxyID:       "proxy-under-test",
		route:         transport.RoutePolicy{Kind: transport.ProxySocks5UDPAssociate, Addr: proxyAddr},
		servers:       servers,
		headStart:     100 * time.Millisecond,
		proxyTimeout:  2 * time.Second,
		serverTimeout: 400 * time.Millisecond,
	}
}

func lookupContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func addrStrings(addrs []net.IPAddr) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.IP.String())
	}
	return out
}

func ipAddrs(addrs ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(addr)})
	}
	return out
}

func unusedLoopbackTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// A host whose own DNS works must behave as it did before the rescue
// existed: same answer, nothing sent through the proxy.
func TestEPDGRescueLeavesAWorkingLocalResolverAlone(t *testing.T) {
	proxy := startRescueProxy(t)
	dns := startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.53")})
	local := &scriptedEPDGResolver{addresses: ipAddrs("198.51.100.10", "2001:db8:1::10")}

	got, err := newTestRescueResolver(local, proxy.Addr(), dns.Addr()).LookupIPAddr(lookupContext(t), testEPDGHost)
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if want := []string{"198.51.100.10", "2001:db8:1::10"}; !reflect.DeepEqual(addrStrings(got), want) {
		t.Fatalf("addresses = %v, want the local answer %v", addrStrings(got), want)
	}
	if n := proxy.Stats().Connections; n != 0 {
		t.Fatalf("the proxy saw %d connections, want none", n)
	}
	if n := dns.Received(); n != 0 {
		t.Fatalf("the public resolver received %d queries, want none", n)
	}
}

func TestEPDGRescueResolvesThroughTheProxyWhenTheLocalResolverFails(t *testing.T) {
	proxy := startRescueProxy(t)
	dns := startTestDNSServer(t, testDNSZone{
		a:    testIPs("192.0.2.10", "192.0.2.11"),
		aaaa: testIPs("2001:db8::10"),
	})
	local := &scriptedEPDGResolver{err: errSyntheticLocalDNS}

	got, err := newTestRescueResolver(local, proxy.Addr(), dns.Addr()).LookupIPAddr(lookupContext(t), testEPDGHost)
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if want := []string{"192.0.2.10", "192.0.2.11", "2001:db8::10"}; !reflect.DeepEqual(addrStrings(got), want) {
		t.Fatalf("addresses = %v, want %v (IPv4 first)", addrStrings(got), want)
	}
	if n := proxy.Stats().Associations; n != 1 {
		t.Fatalf("the proxy granted %d associations, want 1", n)
	}
	if n := dns.Received(); n != 2 {
		t.Fatalf("the public resolver received %d queries, want 2 (A and AAAA)", n)
	}
}

func TestEPDGRescueAuthenticatesToTheProxy(t *testing.T) {
	proxy, err := socks5sim.Start(socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: "sim-user", Password: "sim-pass"})
	if err != nil {
		t.Fatalf("start simulated proxy: %v", err)
	}
	t.Cleanup(proxy.Close)
	dns := startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.10")})

	resolver := newTestRescueResolver(&scriptedEPDGResolver{err: errSyntheticLocalDNS}, proxy.Addr(), dns.Addr())
	resolver.route.Username, resolver.route.Password = "sim-user", "sim-pass"
	got, err := resolver.LookupIPAddr(lookupContext(t), testEPDGHost)
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if want := []string{"192.0.2.10"}; !reflect.DeepEqual(addrStrings(got), want) {
		t.Fatalf("addresses = %v, want %v", addrStrings(got), want)
	}
	if stats := proxy.Stats(); stats.AuthOK != 1 || stats.AuthFailed != 0 {
		t.Fatalf("proxy logins ok=%d failed=%d, want 1 and 0", stats.AuthOK, stats.AuthFailed)
	}
}

// The local answer wins even when it arrives after the rescue has started.
func TestEPDGRescuePrefersALocalAnswerThatArrivesLate(t *testing.T) {
	proxy := startRescueProxy(t)
	dns := startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.53")})
	local := &scriptedEPDGResolver{delay: time.Second, addresses: ipAddrs("198.51.100.10")}

	got, err := newTestRescueResolver(local, proxy.Addr(), dns.Addr()).LookupIPAddr(lookupContext(t), testEPDGHost)
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if want := []string{"198.51.100.10"}; !reflect.DeepEqual(addrStrings(got), want) {
		t.Fatalf("addresses = %v, want the local answer %v", addrStrings(got), want)
	}
	if n := proxy.Stats().Connections; n == 0 {
		t.Fatal("the rescue was not started while the local resolver was silent")
	}
}

func TestEPDGRescueCoversALocalResolverThatFailsLate(t *testing.T) {
	proxy := startRescueProxy(t)
	dns := startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.10")})
	local := &scriptedEPDGResolver{delay: 400 * time.Millisecond, err: errSyntheticLocalDNS}

	got, err := newTestRescueResolver(local, proxy.Addr(), dns.Addr()).LookupIPAddr(lookupContext(t), testEPDGHost)
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if want := []string{"192.0.2.10"}; !reflect.DeepEqual(addrStrings(got), want) {
		t.Fatalf("addresses = %v, want %v", addrStrings(got), want)
	}
}

func TestEPDGRescueAsksTheNextResolverWhenOneIsSilent(t *testing.T) {
	proxy := startRescueProxy(t)
	silent := startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.66")})
	silent.SetSilent(true)
	answering := startTestDNSServer(t, testDNSZone{aaaa: testIPs("2001:db8::20")})
	local := &scriptedEPDGResolver{err: errSyntheticLocalDNS}

	resolver := newTestRescueResolver(local, proxy.Addr(), silent.Addr(), answering.Addr())
	got, err := resolver.LookupIPAddr(lookupContext(t), testEPDGHost)
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if want := []string{"2001:db8::20"}; !reflect.DeepEqual(addrStrings(got), want) {
		t.Fatalf("addresses = %v, want %v from the second resolver", addrStrings(got), want)
	}
	if n := silent.Received(); n != 2 {
		t.Fatalf("the silent resolver received %d queries, want 2", n)
	}
	if n := proxy.Stats().Associations; n != 1 {
		t.Fatalf("the proxy granted %d associations, want one for both resolvers", n)
	}
}

// A reply under another transaction id is not an answer, however plausible
// its content.
func TestEPDGRescueIgnoresAReplyUnderAnotherTransactionID(t *testing.T) {
	proxy := startRescueProxy(t)
	dns := startTestDNSServer(t, testDNSZone{
		a:      testIPs("192.0.2.66"),
		aaaa:   testIPs("2001:db8::10"),
		forgeA: true,
	})
	local := &scriptedEPDGResolver{err: errSyntheticLocalDNS}

	got, err := newTestRescueResolver(local, proxy.Addr(), dns.Addr()).LookupIPAddr(lookupContext(t), testEPDGHost)
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if want := []string{"2001:db8::10"}; !reflect.DeepEqual(addrStrings(got), want) {
		t.Fatalf("addresses = %v, want only %v", addrStrings(got), want)
	}
}

// When the proxy cannot help either, the caller gets the failure of the
// local resolver, exactly as without the rescue.
func TestEPDGRescueKeepsTheLocalFailureWhenTheProxyCannotHelp(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) (proxyAddr string, servers []*net.UDPAddr)
	}{
		{
			name: "proxy unreachable",
			setup: func(t *testing.T) (string, []*net.UDPAddr) {
				return unusedLoopbackTCPAddr(t), []*net.UDPAddr{startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.10")}).Addr()}
			},
		},
		{
			name: "proxy refuses UDP",
			setup: func(t *testing.T) (string, []*net.UDPAddr) {
				proxy := startRescueProxy(t)
				proxy.SetFaults(func(f *socks5sim.Faults) { f.AssociateReply = 0x07 })
				return proxy.Addr(), []*net.UDPAddr{startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.10")}).Addr()}
			},
		},
		{
			name: "proxy drops the connection",
			setup: func(t *testing.T) (string, []*net.UDPAddr) {
				proxy := startRescueProxy(t)
				proxy.SetFaults(func(f *socks5sim.Faults) { f.CloseOnGreeting = true })
				return proxy.Addr(), []*net.UDPAddr{startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.10")}).Addr()}
			},
		},
		{
			name: "resolvers silent",
			setup: func(t *testing.T) (string, []*net.UDPAddr) {
				first := startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.10")})
				first.SetSilent(true)
				second := startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.10")})
				second.SetSilent(true)
				return startRescueProxy(t).Addr(), []*net.UDPAddr{first.Addr(), second.Addr()}
			},
		},
		{
			name: "datagrams lost in the relay",
			setup: func(t *testing.T) (string, []*net.UDPAddr) {
				proxy := startRescueProxy(t)
				proxy.SetFaults(func(f *socks5sim.Faults) { f.DropInbound = 100 })
				return proxy.Addr(), []*net.UDPAddr{startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.10")}).Addr()}
			},
		},
		{
			name: "name unknown to the resolvers",
			setup: func(t *testing.T) (string, []*net.UDPAddr) {
				return startRescueProxy(t).Addr(), []*net.UDPAddr{startTestDNSServer(t, testDNSZone{rcode: 3}).Addr()}
			},
		},
		{
			name: "resolver failure",
			setup: func(t *testing.T) (string, []*net.UDPAddr) {
				return startRescueProxy(t).Addr(), []*net.UDPAddr{startTestDNSServer(t, testDNSZone{rcode: 2}).Addr()}
			},
		},
		{
			name: "name without addresses",
			setup: func(t *testing.T) (string, []*net.UDPAddr) {
				return startRescueProxy(t).Addr(), []*net.UDPAddr{startTestDNSServer(t, testDNSZone{}).Addr()}
			},
		},
		{
			name: "only addresses no ePDG can have",
			setup: func(t *testing.T) (string, []*net.UDPAddr) {
				zone := testDNSZone{a: testIPs("127.0.0.1", "0.0.0.0"), aaaa: testIPs("::1")}
				return startRescueProxy(t).Addr(), []*net.UDPAddr{startTestDNSServer(t, zone).Addr()}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxyAddr, servers := tc.setup(t)
			local := &scriptedEPDGResolver{err: errSyntheticLocalDNS}

			got, err := newTestRescueResolver(local, proxyAddr, servers...).LookupIPAddr(lookupContext(t), testEPDGHost)
			if !errors.Is(err, errSyntheticLocalDNS) {
				t.Fatalf("LookupIPAddr() = %v, %v; want the local resolver's failure", addrStrings(got), err)
			}
		})
	}
}

func TestEPDGRescueStopsWhenTheStartIsCancelled(t *testing.T) {
	proxy := startRescueProxy(t)
	dns := startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.10")})
	dns.SetSilent(true)
	local := &scriptedEPDGResolver{delay: time.Minute, addresses: ipAddrs("198.51.100.10")}

	resolver := newTestRescueResolver(local, proxy.Addr(), dns.Addr())
	resolver.serverTimeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	defer cancel()

	started := time.Now()
	_, err := resolver.LookupIPAddr(ctx, testEPDGHost)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("LookupIPAddr() error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("LookupIPAddr() returned %v after the cancellation", elapsed)
	}
}

func TestEPDGRescueDoesNotResolveAddressLiterals(t *testing.T) {
	proxy := startRescueProxy(t)
	dns := startTestDNSServer(t, testDNSZone{a: testIPs("192.0.2.53")})
	local := &scriptedEPDGResolver{err: errSyntheticLocalDNS}

	_, err := newTestRescueResolver(local, proxy.Addr(), dns.Addr()).LookupIPAddr(lookupContext(t), "192.0.2.77")
	if !errors.Is(err, errSyntheticLocalDNS) {
		t.Fatalf("LookupIPAddr() error = %v, want the local resolver's result", err)
	}
	if n := proxy.Stats().Connections; n != 0 {
		t.Fatalf("the proxy saw %d connections for an address literal, want none", n)
	}
}

func TestEPDGRescueServers(t *testing.T) {
	cases := []struct {
		raw     string
		want    []string
		enabled bool
	}{
		{raw: "", want: []string{"1.1.1.1:53", "8.8.8.8:53"}, enabled: true},
		{raw: "   ", want: []string{"1.1.1.1:53", "8.8.8.8:53"}, enabled: true},
		{raw: "off", enabled: false},
		{raw: " OFF ", enabled: false},
		{raw: "0", enabled: false},
		{raw: "false", enabled: false},
		{raw: "9.9.9.9", want: []string{"9.9.9.9:53"}, enabled: true},
		{
			raw:     "9.9.9.9:5353, [2001:db8::53]:53, 2001:db8::54, [2001:db8::55], 9.9.9.9:5353",
			want:    []string{"9.9.9.9:5353", "[2001:db8::53]:53", "[2001:db8::54]:53", "[2001:db8::55]:53"},
			enabled: true,
		},
		{raw: "dns.example.org, 9.9.9.9:0, 9.9.9.9:70000, 0.0.0.0, :53, 149.112.112.112", want: []string{"149.112.112.112:53"}, enabled: true},
		{raw: "192.0.2.1,192.0.2.2,192.0.2.3,192.0.2.4,192.0.2.5", want: []string{"192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53", "192.0.2.4:53"}, enabled: true},
		{raw: "not-an-address", enabled: true},
	}
	for _, tc := range cases {
		servers, enabled := epdgRescueServers(tc.raw)
		got := make([]string, 0, len(servers))
		for _, server := range servers {
			got = append(got, server.String())
		}
		if enabled != tc.enabled || !reflect.DeepEqual(got, append([]string{}, tc.want...)) {
			t.Errorf("epdgRescueServers(%q) = %v, %v; want %v, %v", tc.raw, got, enabled, tc.want, tc.enabled)
		}
	}
}

func useLocalEPDGResolver(t *testing.T, resolver epdgResolver) {
	t.Helper()
	previous := localEPDGResolver
	localEPDGResolver = resolver
	t.Cleanup(func() { localEPDGResolver = previous })
}

func TestEPDGResolverForRequest(t *testing.T) {
	local := &scriptedEPDGResolver{}
	useLocalEPDGResolver(t, local)
	proxy := &ProxyConfig{ID: "p1", Addr: "127.0.0.1:1080", Enabled: true}

	t.Run("a resolver injected by a test is used as is", func(t *testing.T) {
		injected := &scriptedEPDGResolver{}
		if got := epdgResolverFor(StartRequest{epdgResolver: injected, Proxy: proxy}); got != epdgResolver(injected) {
			t.Fatalf("epdgResolverFor() = %T, want the injected resolver", got)
		}
	})

	direct := map[string]*ProxyConfig{
		"no proxy":                 nil,
		"proxy disabled":           {ID: "p1", Addr: "127.0.0.1:1080"},
		"proxy without an address": {ID: "p1", Addr: "  ", Enabled: true},
		"proxy host without port":  {ID: "p1", Host: "127.0.0.1", Enabled: true},
	}
	for name, cfg := range direct {
		t.Run(name, func(t *testing.T) {
			t.Setenv(epdgDNSRescueEnv, "")
			if got := epdgResolverFor(StartRequest{Proxy: cfg}); got != epdgResolver(local) {
				t.Fatalf("epdgResolverFor() = %T, want the local resolver", got)
			}
		})
	}

	for _, value := range []string{"off", "not-an-address"} {
		t.Run("rescue unavailable with "+value, func(t *testing.T) {
			t.Setenv(epdgDNSRescueEnv, value)
			if got := epdgResolverFor(StartRequest{Proxy: proxy}); got != epdgResolver(local) {
				t.Fatalf("epdgResolverFor() = %T, want the local resolver", got)
			}
		})
	}

	t.Run("a session through a proxy gets the rescue", func(t *testing.T) {
		t.Setenv(epdgDNSRescueEnv, "")
		rescue, ok := epdgResolverFor(StartRequest{Proxy: proxy, TraceID: " trace-1 "}).(*proxyRescueResolver)
		if !ok {
			t.Fatal("epdgResolverFor() did not return the rescue resolver")
		}
		if rescue.local != epdgResolver(local) || rescue.proxyID != "p1" || rescue.traceID != "trace-1" {
			t.Fatalf("rescue resolver = %+v, want the local resolver, the request's proxy id and trace id", rescue)
		}
		if rescue.route != buildRoutePolicy(proxy) {
			t.Fatalf("rescue route differs from the route of the tunnel")
		}
		if len(rescue.servers) != len(defaultEPDGRescueServers) {
			t.Fatalf("rescue servers = %v, want the defaults", rescue.servers)
		}
		if rescue.headStart != epdgRescueHeadStart || rescue.proxyTimeout != epdgRescueProxyTimeout || rescue.serverTimeout != epdgRescueServerTimeout {
			t.Fatalf("rescue timing = %v/%v/%v, want the defaults", rescue.headStart, rescue.proxyTimeout, rescue.serverTimeout)
		}
	})

	// The tunnel accepts a proxy described by host and port as well; the
	// rescue must not be lost for that form.
	t.Run("a proxy given as host and port gets the rescue too", func(t *testing.T) {
		t.Setenv(epdgDNSRescueEnv, "")
		split := &ProxyConfig{ID: "p2", Host: "127.0.0.1", Port: 1080, Username: "u", Password: "p", Enabled: true}
		rescue, ok := epdgResolverFor(StartRequest{Proxy: split}).(*proxyRescueResolver)
		if !ok {
			t.Fatal("epdgResolverFor() did not return the rescue resolver")
		}
		want := transport.RoutePolicy{Kind: transport.ProxySocks5UDPAssociate, Addr: "127.0.0.1:1080", Username: "u", Password: "p"}
		if rescue.route != want || rescue.proxyID != "p2" {
			t.Fatalf("rescue route address = %q (proxy %q), want the address joined from host and port and the proxy's credentials", rescue.route.Addr, rescue.proxyID)
		}
	})
}

// End to end for the start path: the host cannot resolve the ePDG name, the
// session is configured with a proxy, and the tunnel is attempted against
// the addresses a resolver behind the proxy knows.
func TestEstablishSWuResolvesTheEPDGThroughTheProxyWhenLocalDNSFails(t *testing.T) {
	proxy := startRescueProxy(t)
	dns := startTestDNSServer(t, testDNSZone{
		a:    testIPs("192.0.2.10"),
		aaaa: testIPs("2001:db8::10"),
	})
	t.Setenv(epdgDNSRescueEnv, dns.Addr().String())
	useLocalEPDGResolver(t, failingEPDGResolver{})

	instance := &Instance{lifecycleGeneration: 1}
	var tried []string
	req := StartRequest{
		Proxy: &ProxyConfig{ID: "p1", Addr: proxy.Addr(), Enabled: true},
		swuStarter: func(_ context.Context, _ StartRequest, candidate epdgCandidate, _ string) (*swuSessionLease, error) {
			tried = append(tried, candidate.IP.String())
			if candidate.Family == "ipv4" {
				return nil, context.DeadlineExceeded
			}
			return completedSyntheticSWULease(candidate, swuSnapshot{Established: true}), nil
		},
	}

	lease, err := instance.establishSWu(lookupContext(t), req, testEPDGHost, "500", 1)
	if err != nil {
		t.Fatalf("establishSWu() error = %v", err)
	}
	if want := []string{"192.0.2.10", "2001:db8::10"}; !reflect.DeepEqual(tried, want) {
		t.Fatalf("candidates tried = %v, want %v", tried, want)
	}
	if winner := lease.Candidate(); winner.IP.String() != "2001:db8::10" {
		t.Fatalf("winning candidate = %v, want 2001:db8::10", winner.IP)
	}
}

func TestEstablishSWuKeepsTheDNSFailureWhenTheRescueIsSwitchedOff(t *testing.T) {
	proxy := startRescueProxy(t)
	t.Setenv(epdgDNSRescueEnv, "off")
	useLocalEPDGResolver(t, failingEPDGResolver{})

	instance := &Instance{lifecycleGeneration: 1}
	req := StartRequest{
		Proxy: &ProxyConfig{ID: "p1", Addr: proxy.Addr(), Enabled: true},
		swuStarter: func(context.Context, StartRequest, epdgCandidate, string) (*swuSessionLease, error) {
			t.Error("a tunnel was attempted without an address")
			return nil, context.Canceled
		},
	}

	_, err := instance.establishSWu(lookupContext(t), req, testEPDGHost, "500", 1)
	if got := classifyTunnelFailure(err); got != "tunnel_dns_failed" {
		t.Fatalf("classifyTunnelFailure() = %q, want tunnel_dns_failed (err=%v)", got, err)
	}
	if n := proxy.Stats().Connections; n != 0 {
		t.Fatalf("the proxy saw %d connections with the rescue switched off, want none", n)
	}
}

// The failure of a rescue that could not help is classified like any other
// failure to resolve the ePDG.
func TestEstablishSWuKeepsTheDNSFailureWhenTheRescueFails(t *testing.T) {
	proxy := startRescueProxy(t)
	dns := startTestDNSServer(t, testDNSZone{rcode: 3})
	t.Setenv(epdgDNSRescueEnv, dns.Addr().String())
	useLocalEPDGResolver(t, failingEPDGResolver{})

	instance := &Instance{lifecycleGeneration: 1}
	req := StartRequest{Proxy: &ProxyConfig{ID: "p1", Addr: proxy.Addr(), Enabled: true}}

	_, err := instance.establishSWu(lookupContext(t), req, testEPDGHost, "500", 1)
	if got := classifyTunnelFailure(err); got != "tunnel_dns_failed" {
		t.Fatalf("classifyTunnelFailure() = %q, want tunnel_dns_failed (err=%v)", got, err)
	}
	if n := dns.Received(); n != 2 {
		t.Fatalf("the public resolver received %d queries, want 2", n)
	}
}

func TestEPDGRescueFailureReason(t *testing.T) {
	cases := map[string]error{
		"no_address":    nil,
		"cancelled":     context.Canceled,
		"dns_rcode_3":   &dnsRCodeError{code: 3},
		"dns_timeout":   errEPDGRescueTimeout,
		"dns_malformed": errDNSMalformed,
		"other":         errors.New("something with 192.0.2.1:1080 in it"),
	}
	for want, err := range cases {
		if got := epdgRescueFailureReason(err); got != want {
			t.Errorf("epdgRescueFailureReason(%v) = %q, want %q", err, got, want)
		}
	}
	if got := epdgRescueFailureReason(errEPDGRescueNoAddress); got != "no_address" {
		t.Errorf("epdgRescueFailureReason(no address) = %q, want no_address", got)
	}
}
