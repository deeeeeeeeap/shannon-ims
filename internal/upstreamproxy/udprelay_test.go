package upstreamproxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/transport"
	"github.com/1239t/vowifi-go/runtimehost/transport/socks5sim"
)

// fastRelayRetry keeps the tests short; the production policy is the
// transport's default.
var fastRelayRetry = relayRetry{
	maxAttempts: 3,
	backoffBase: 5 * time.Millisecond,
	backoffMax:  20 * time.Millisecond,
	minStable:   time.Millisecond,
}

type relayLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *relayLog) logf(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *relayLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func (l *relayLog) contains(part string) bool {
	for _, line := range l.all() {
		if strings.Contains(line, part) {
			return true
		}
	}
	return false
}

// relayFixture is a relay in front of a simulated proxy with two simulated
// remote ports behind it, the way a relay fronts an ePDG's IKE and NAT-T ports.
type relayFixture struct {
	proxy *socks5sim.Server
	peers [2]*socks5sim.UDPPeer
	relay *UDPRelay
	log   *relayLog
}

func startRelayFixture(t *testing.T) *relayFixture {
	t.Helper()
	f := &relayFixture{log: &relayLog{}}
	f.proxy = startSimProxy(t, socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: simUser, Password: simPassword})
	for i := range f.peers {
		tag := []byte{'A' + byte(i), ':'}
		f.peers[i] = startSimPeer(t)
		f.peers[i].SetResponder(func(payload []byte) []byte {
			return append(append([]byte(nil), tag...), payload...)
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relay, err := StartUDPRelay(ctx, UDPRelayConfig{
		ProxyAddr:   f.proxy.Addr(),
		Username:    simUser,
		Password:    simPassword,
		TargetHost:  "127.0.0.1",
		LocalIP:     "127.0.0.1",
		Ports:       []int{0, 0},
		TargetPorts: []int{f.peers[0].Addr().Port, f.peers[1].Addr().Port},
		Logf:        f.log.logf,
		retry:       fastRelayRetry,
	})
	if err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(func() { _ = relay.Close() })
	f.relay = relay
	return f
}

// relayClient stands in for the local IKE daemon talking to one relay port.
type relayClient struct {
	t    *testing.T
	conn *net.UDPConn
	to   *net.UDPAddr
}

func newRelayClient(t *testing.T, to *net.UDPAddr) *relayClient {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &relayClient{t: t, conn: conn, to: to}
}

func (c *relayClient) send(payload string) {
	c.t.Helper()
	if _, err := c.conn.WriteToUDP([]byte(payload), c.to); err != nil {
		c.t.Fatalf("client send: %v", err)
	}
}

// receive returns the next datagram, or "" when none arrives in time.
func (c *relayClient) receive(wait time.Duration) string {
	c.t.Helper()
	buf := make([]byte, 2048)
	_ = c.conn.SetReadDeadline(time.Now().Add(wait))
	n, from, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return ""
	}
	if !from.IP.Equal(c.to.IP) || from.Port != c.to.Port {
		c.t.Fatalf("answer came from %v, want the relay port %v the request was sent to", from, c.to)
	}
	return string(buf[:n])
}

// exchange sends payload until want comes back, as a retransmitting
// protocol would across a gap.
func (c *relayClient) exchange(payload, want string) {
	c.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.send(payload)
		for {
			got := c.receive(100 * time.Millisecond)
			if got == want {
				return
			}
			if got == "" {
				break
			}
		}
	}
	c.t.Fatalf("no %q in answer to %q", want, payload)
}

func TestUDPRelayForwardsBothPortsBothWays(t *testing.T) {
	f := startRelayFixture(t)
	addrs := f.relay.LocalAddrs()
	if len(addrs) != 2 {
		t.Fatalf("relay listens on %d addresses, want 2", len(addrs))
	}
	ike := newRelayClient(t, addrs[0])
	natt := newRelayClient(t, addrs[1])

	ike.send("ike-init")
	if got := ike.receive(3 * time.Second); got != "A:ike-init" {
		t.Fatalf("first port answered %q, want the first remote port's answer", got)
	}
	natt.send("esp-data")
	if got := natt.receive(3 * time.Second); got != "B:esp-data" {
		t.Fatalf("second port answered %q, want the second remote port's answer", got)
	}

	// Unsolicited traffic from the remote end reaches the last local peer.
	if err := f.peers[1].Send([]byte("keepalive")); err != nil {
		t.Fatalf("peer send: %v", err)
	}
	if got := natt.receive(3 * time.Second); got != "keepalive" {
		t.Fatalf("second port delivered %q, want the remote end's datagram", got)
	}

	// The counters are updated just after each datagram is passed on.
	eventually(t, "the counters to show 2 forwarded and 3 returned", func() bool {
		stats := f.relay.Stats()
		return stats.Forwarded == 2 && stats.Returned == 3
	})
	if stats := f.relay.Stats(); stats.Dropped != 0 || stats.Associations != 1 {
		t.Fatalf("stats = %+v, want nothing dropped and 1 association", stats)
	}
	if st := f.proxy.Stats(); st.AuthOK != 1 {
		t.Fatalf("proxy saw %d successful logins, want the relay to authenticate once", st.AuthOK)
	}
	if !f.log.contains("proxy association ready") {
		t.Fatalf("association state was not reported: %v", f.log.all())
	}
}

func TestUDPRelayCarriesLargeAndBinaryDatagrams(t *testing.T) {
	f := startRelayFixture(t)
	f.peers[0].SetResponder(nil) // plain echo
	client := newRelayClient(t, f.relay.LocalAddrs()[0])

	for _, size := range []int{1, 28, 1200, 1472, 4000} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i*7 + size)
		}
		if _, err := client.conn.WriteToUDP(payload, client.to); err != nil {
			t.Fatalf("send %d bytes: %v", size, err)
		}
		buf := make([]byte, 8192)
		_ = client.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := client.conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no echo of the %d-byte datagram: %v", size, err)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("%d-byte datagram came back changed (%d bytes)", size, n)
		}
	}
}

// The relay used to keep running, and silently forward nowhere, once the
// proxy had dropped the control connection.
func TestUDPRelayReassociatesAfterProxyDropsControlConnection(t *testing.T) {
	f := startRelayFixture(t)
	client := newRelayClient(t, f.relay.LocalAddrs()[0])
	client.exchange("before", "A:before")

	time.Sleep(10 * time.Millisecond) // let the association count as established
	if dropped := f.proxy.DropControlConnections(); dropped != 1 {
		t.Fatalf("dropped %d control connections, want 1", dropped)
	}
	client.exchange("after", "A:after")

	if got := f.relay.Stats().Associations; got != 2 {
		t.Fatalf("associations = %d, want a second one after the drop", got)
	}
	select {
	case <-f.relay.Done():
		t.Fatalf("relay stopped although the proxy took it back: %v", f.relay.Err())
	default:
	}
	for _, line := range []string{"proxy association lost; re-associating", "proxy association re-established"} {
		if !f.log.contains(line) {
			t.Fatalf("missing log line %q in %v", line, f.log.all())
		}
	}
	if sources := f.peers[0].Sources(); len(sources) != 2 {
		t.Fatalf("remote end saw sources %v, want the old and the new relay path", sources)
	}
}

func TestUDPRelayStopsWhenProxyIsGoneForGood(t *testing.T) {
	f := startRelayFixture(t)
	client := newRelayClient(t, f.relay.LocalAddrs()[0])
	client.exchange("before", "A:before")

	f.proxy.Close()

	select {
	case <-f.relay.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("relay kept running without a proxy")
	}
	if err := f.relay.Err(); err == nil || !strings.Contains(err.Error(), "giving up") {
		t.Fatalf("Err() = %v, want the reason the relay stopped", err)
	}
	eventually(t, "the stop to be reported", func() bool { return f.log.contains("relay stopping") })

	// The local ports are released, so nothing believes a relay is there.
	for _, addr := range f.relay.LocalAddrs() {
		conn, err := net.ListenUDP("udp4", addr)
		if err != nil {
			t.Fatalf("port %d is still held after the relay stopped: %v", addr.Port, err)
		}
		_ = conn.Close()
	}
	if err := f.relay.Close(); err != nil {
		t.Fatalf("Close after a failure: %v", err)
	}
}

func TestUDPRelayCloseIsCleanAndIdempotent(t *testing.T) {
	f := startRelayFixture(t)
	client := newRelayClient(t, f.relay.LocalAddrs()[0])
	client.exchange("ping", "A:ping")

	for i := 0; i < 2; i++ {
		if err := f.relay.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i+1, err)
		}
	}
	select {
	case <-f.relay.Done():
	default:
		t.Fatal("Done is not closed after Close")
	}
	if err := f.relay.Err(); err != nil {
		t.Fatalf("Err() = %v after a plain Close, want nil", err)
	}
	eventually(t, "the proxy to see the association end", func() bool {
		return f.proxy.Stats().ActiveAssociations == 0
	})
}

func TestUDPRelayDropsWhatItCannotRoute(t *testing.T) {
	f := startRelayFixture(t)
	client := newRelayClient(t, f.relay.LocalAddrs()[0])
	client.exchange("ping", "A:ping")
	base := f.relay.Stats()

	// A relay datagram from a port nothing was ever sent to.
	stray, err := transport.EncodeSocks5UDPDatagram(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, []byte("stray"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// The second remote port answers, but no local peer has used that port.
	unclaimed, err := transport.EncodeSocks5UDPDatagram(f.peers[1].Addr(), []byte("unclaimed"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, raw := range [][]byte{stray, unclaimed, {0xde, 0xad}} {
		if reached := f.proxy.InjectToClients(raw); reached != 1 {
			t.Fatalf("injected datagram reached %d clients, want 1", reached)
		}
	}
	eventually(t, "the two unroutable datagrams to be counted", func() bool {
		return f.relay.Stats().Dropped == base.Dropped+2
	})
	if got := client.receive(150 * time.Millisecond); got != "" {
		t.Fatalf("local peer received %q, want nothing", got)
	}

	// And the relay still works.
	client.exchange("again", "A:again")
}

func TestStartUDPRelayReportsWhyTheProxyIsUnusable(t *testing.T) {
	closedPort := func(t *testing.T) string {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		return ln.Addr().String()
	}

	cases := []struct {
		name     string
		proxy    func(t *testing.T) string
		password string
		want     string
	}{
		{
			name: "wrong password",
			proxy: func(t *testing.T) string {
				return startSimProxy(t, socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: simUser, Password: simPassword}).Addr()
			},
			password: "not-the-password",
			want:     "socks5 handshake",
		},
		{
			name: "udp associate refused",
			proxy: func(t *testing.T) string {
				srv := startSimProxy(t, socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: simUser, Password: simPassword})
				srv.SetFaults(func(f *socks5sim.Faults) { f.AssociateReply = 0x02 })
				return srv.Addr()
			},
			password: simPassword,
			want:     "socks5 udp associate",
		},
		{
			name:     "nothing listening",
			proxy:    closedPort,
			password: simPassword,
			want:     "dial proxy",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			relay, err := StartUDPRelay(ctx, UDPRelayConfig{
				ProxyAddr:   tc.proxy(t),
				Username:    simUser,
				Password:    tc.password,
				TargetHost:  "127.0.0.1",
				LocalIP:     "127.0.0.1",
				Ports:       []int{0},
				TargetPorts: []int{4500},
				retry:       fastRelayRetry,
			})
			if err == nil {
				_ = relay.Close()
				t.Fatal("relay started on an unusable proxy")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to name the failing step %q", err, tc.want)
			}
			if strings.Contains(err.Error(), tc.password) {
				t.Fatalf("error contains the password: %q", err)
			}
		})
	}
}

func TestStartUDPRelayHonoursStartDeadline(t *testing.T) {
	srv := startSimProxy(t, socks5sim.Config{Auth: socks5sim.AuthNone})
	srv.SetFaults(func(f *socks5sim.Faults) { f.StallGreeting = true })

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	relay, err := StartUDPRelay(ctx, UDPRelayConfig{
		ProxyAddr:   srv.Addr(),
		TargetHost:  "127.0.0.1",
		LocalIP:     "127.0.0.1",
		Ports:       []int{0},
		TargetPorts: []int{4500},
	})
	if err == nil {
		_ = relay.Close()
		t.Fatal("relay started although the proxy never answered")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("start returned after %v, want it bounded by the caller's deadline", elapsed)
	}
}

func TestStartUDPRelayValidatesConfig(t *testing.T) {
	valid := UDPRelayConfig{
		ProxyAddr:   "127.0.0.1:1080",
		TargetHost:  "127.0.0.1",
		LocalIP:     "127.0.0.1",
		Ports:       []int{0, 0},
		TargetPorts: []int{500, 4500},
	}
	cases := []struct {
		name   string
		mutate func(*UDPRelayConfig)
		want   string
	}{
		{"no proxy", func(c *UDPRelayConfig) { c.ProxyAddr = " " }, "ProxyAddr is required"},
		{"no target", func(c *UDPRelayConfig) { c.TargetHost = "" }, "TargetHost is required"},
		{"no local address", func(c *UDPRelayConfig) { c.LocalIP = "" }, "LocalIP is required"},
		{"local address is a name", func(c *UDPRelayConfig) { c.LocalIP = "localhost" }, "is not an IP address"},
		{"no ports", func(c *UDPRelayConfig) { c.Ports = nil }, "Ports is required"},
		{"port lists differ in length", func(c *UDPRelayConfig) { c.TargetPorts = []int{500} }, "same length"},
		{"target port listed twice", func(c *UDPRelayConfig) { c.TargetPorts = []int{500, 500} }, "listed twice"},
		{"target port out of range", func(c *UDPRelayConfig) { c.TargetPorts = []int{500, 70000} }, "out of range"},
		{"listen port out of range", func(c *UDPRelayConfig) { c.Ports = []int{0, -1} }, "out of range"},
		{"default target ports need real listen ports", func(c *UDPRelayConfig) { c.TargetPorts = nil }, "out of range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			relay, err := StartUDPRelay(context.Background(), cfg)
			if err == nil {
				_ = relay.Close()
				t.Fatal("invalid configuration was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}
