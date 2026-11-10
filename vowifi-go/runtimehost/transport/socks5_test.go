package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/transport/socks5sim"
)

const (
	testUser     = "sim-user"
	testPassword = "sim-pass"
)

func startSim(t *testing.T, cfg socks5sim.Config) *socks5sim.Server {
	t.Helper()
	srv, err := socks5sim.Start(cfg)
	if err != nil {
		t.Fatalf("start simulated proxy: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func startPeer(t *testing.T) *socks5sim.UDPPeer {
	t.Helper()
	peer, err := socks5sim.StartUDPPeer()
	if err != nil {
		t.Fatalf("start simulated peer: %v", err)
	}
	t.Cleanup(peer.Close)
	return peer
}

func asSocks5Error(t *testing.T, err error) *Socks5Error {
	t.Helper()
	var se *Socks5Error
	if !errors.As(err, &se) {
		t.Fatalf("error %v (%T) is not a *Socks5Error", err, err)
	}
	return se
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestSocks5UDPDatagramRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		dst     *net.UDPAddr
		payload []byte
	}{
		{"ipv4", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}, []byte("ike-payload")},
		{"ipv6", &net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 500}, []byte{0xde, 0xad, 0xbe, 0xef}},
		{"empty payload", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 1}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := EncodeSocks5UDPDatagram(tc.dst, tc.payload)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
				t.Fatalf("reserved and fragment bytes must be zero, got % x", packet[:3])
			}
			src, payload, err := DecodeSocks5UDPDatagram(packet)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !src.IP.Equal(tc.dst.IP) || src.Port != tc.dst.Port {
				t.Fatalf("address = %v, want %v", src, tc.dst)
			}
			if !bytes.Equal(payload, tc.payload) {
				t.Fatalf("payload = % x, want % x", payload, tc.payload)
			}
		})
	}
}

// A datagram cut anywhere inside its header must be rejected, never indexed
// past its end: the previous implementation panicked on an IPv6-typed
// datagram of 10 to 21 bytes, so one stray UDP packet could take the process
// down.
func TestDecodeSocks5UDPDatagramTruncatedIsRejected(t *testing.T) {
	full := map[string][]byte{}
	v4, _ := EncodeSocks5UDPDatagram(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4500}, []byte("x"))
	v6, _ := EncodeSocks5UDPDatagram(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4500}, []byte("x"))
	full["ipv4"] = v4
	full["ipv6"] = v6
	full["domain"] = append([]byte{0, 0, 0, 0x03, 4, 'e', 'p', 'd', 'g', 0x11, 0x94}, 'x')

	for name, packet := range full {
		headerLen := len(packet) - 1
		for n := 0; n < headerLen; n++ {
			if _, _, err := DecodeSocks5UDPDatagram(packet[:n]); err == nil {
				t.Errorf("%s: %d of %d header bytes decoded without error", name, n, headerLen)
			}
		}
		if _, payload, err := DecodeSocks5UDPDatagram(packet[:headerLen]); err != nil || len(payload) != 0 {
			t.Errorf("%s: header-only datagram: payload=%q err=%v, want empty payload", name, payload, err)
		}
	}
}

func TestDecodeSocks5UDPDatagramRejectsFragmentsAndUnknownTypes(t *testing.T) {
	valid, _ := EncodeSocks5UDPDatagram(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4500}, []byte("x"))

	fragment := append([]byte(nil), valid...)
	fragment[2] = 0x01
	if _, _, err := DecodeSocks5UDPDatagram(fragment); !errors.Is(err, ErrSocks5Fragment) {
		t.Fatalf("fragment: err = %v, want ErrSocks5Fragment", err)
	}

	unknown := append([]byte(nil), valid...)
	unknown[3] = 0x7f
	if _, _, err := DecodeSocks5UDPDatagram(unknown); err == nil {
		t.Fatal("unknown address type decoded without error")
	}
}

func TestDecodeSocks5UDPDatagramDomainSource(t *testing.T) {
	packet := append([]byte{0, 0, 0, 0x03, 4, 'e', 'p', 'd', 'g', 0x11, 0x94}, "data"...)
	src, payload, err := DecodeSocks5UDPDatagram(packet)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if src.Domain != "epdg" || src.Port != 4500 || src.IP != nil {
		t.Fatalf("source = %+v, want domain epdg port 4500", src)
	}
	if string(payload) != "data" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestEncodeSocks5UDPDatagramRejectsMissingDestination(t *testing.T) {
	if _, err := EncodeSocks5UDPDatagram(nil, []byte("x")); err == nil {
		t.Error("nil destination encoded without error")
	}
	if _, err := EncodeSocks5UDPDatagram(&net.UDPAddr{Port: 4500}, []byte("x")); err == nil {
		t.Error("destination without an IP encoded without error")
	}
}

func TestDialSocks5WithoutAuthentication(t *testing.T) {
	srv := startSim(t, socks5sim.Config{Auth: socks5sim.AuthNone})
	conn, err := DialSocks5(context.Background(), srv.Addr(), Socks5Options{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if conn.AuthMethod() != Socks5AuthNone || conn.CredentialsIgnored() {
		t.Fatalf("method=%#x ignored=%v, want no authentication", conn.AuthMethod(), conn.CredentialsIgnored())
	}
	if got := srv.Greetings(); !reflect.DeepEqual(got, [][]byte{{Socks5AuthNone}}) {
		t.Fatalf("offered methods = %v, want only no-auth", got)
	}
}

// With credentials configured only username/password is offered, so a proxy
// that supports both methods can never pick the unauthenticated one.
func TestDialSocks5OffersOnlyCredentialsFirst(t *testing.T) {
	for _, mode := range []socks5sim.AuthMode{socks5sim.AuthUserPass, socks5sim.AuthEither} {
		srv := startSim(t, socks5sim.Config{Auth: mode, Username: testUser, Password: testPassword})
		conn, err := DialSocks5(context.Background(), srv.Addr(), Socks5Options{Username: testUser, Password: testPassword})
		if err != nil {
			t.Fatalf("mode %d: dial: %v", mode, err)
		}
		conn.Close()
		if conn.AuthMethod() != Socks5AuthUserPassword || conn.CredentialsIgnored() {
			t.Fatalf("mode %d: method=%#x ignored=%v, want username/password", mode, conn.AuthMethod(), conn.CredentialsIgnored())
		}
		if got := srv.Greetings(); !reflect.DeepEqual(got, [][]byte{{Socks5AuthUserPassword}}) {
			t.Fatalf("mode %d: offered methods = %v, want only username/password", mode, got)
		}
		if st := srv.Stats(); st.AuthOK != 1 || st.Connections != 1 {
			t.Fatalf("mode %d: stats = %+v, want one authenticated connection", mode, st)
		}
	}
}

// Credentials configured for a proxy that has no username/password support:
// after the explicit refusal the session is retried once without
// authentication instead of failing, and the caller is told.
func TestDialSocks5FallsBackWhenProxyHasNoPasswordSupport(t *testing.T) {
	srv := startSim(t, socks5sim.Config{Auth: socks5sim.AuthNone})
	conn, err := DialSocks5(context.Background(), srv.Addr(), Socks5Options{Username: testUser, Password: testPassword})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if conn.AuthMethod() != Socks5AuthNone || !conn.CredentialsIgnored() {
		t.Fatalf("method=%#x ignored=%v, want unauthenticated session flagged as credentials ignored", conn.AuthMethod(), conn.CredentialsIgnored())
	}
	want := [][]byte{{Socks5AuthUserPassword}, {Socks5AuthNone}}
	if got := srv.Greetings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("offered methods = %v, want %v", got, want)
	}
}

func TestDialSocks5WrongPasswordIsNotRetried(t *testing.T) {
	srv := startSim(t, socks5sim.Config{Auth: socks5sim.AuthEither, Username: testUser, Password: testPassword})
	_, err := DialSocks5(context.Background(), srv.Addr(), Socks5Options{Username: testUser, Password: "wrong"})
	se := asSocks5Error(t, err)
	if se.Stage != Socks5StageHandshake || se.Reason != Socks5ReasonAuthRejected {
		t.Fatalf("error = %v (stage %s, reason %s), want rejected credentials", err, se.Stage, se.Reason)
	}
	if st := srv.Stats(); st.Connections != 1 || st.AuthFailed != 1 {
		t.Fatalf("stats = %+v, want exactly one rejected attempt and no unauthenticated retry", st)
	}
	if strings.Contains(err.Error(), "wrong") || strings.Contains(err.Error(), testUser) {
		t.Fatalf("error text leaks credentials: %v", err)
	}
}

func TestDialSocks5ProxyRequiresCredentials(t *testing.T) {
	srv := startSim(t, socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: testUser, Password: testPassword})
	_, err := DialSocks5(context.Background(), srv.Addr(), Socks5Options{})
	se := asSocks5Error(t, err)
	if se.Reason != Socks5ReasonNoAcceptableMethod {
		t.Fatalf("error = %v (reason %s), want no acceptable method", err, se.Reason)
	}
	if st := srv.Stats(); st.Connections != 1 {
		t.Fatalf("connections = %d, want 1", st.Connections)
	}
}

func TestDialSocks5RejectsOversizedCredentials(t *testing.T) {
	srv := startSim(t, socks5sim.Config{Auth: socks5sim.AuthEither})
	_, err := DialSocks5(context.Background(), srv.Addr(), Socks5Options{Username: strings.Repeat("u", 256), Password: "p"})
	se := asSocks5Error(t, err)
	if se.Reason != Socks5ReasonInvalidCredentials {
		t.Fatalf("error = %v (reason %s), want invalid credentials", err, se.Reason)
	}
	if st := srv.Stats(); st.Connections != 0 {
		t.Fatalf("connections = %d, want none: unencodable credentials must not reach the proxy", st.Connections)
	}
}

func TestDialSocks5DetectsNonSocksServer(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	srv.SetFaults(func(f *socks5sim.Faults) { f.WrongVersion = true })
	_, err := DialSocks5(context.Background(), srv.Addr(), Socks5Options{})
	se := asSocks5Error(t, err)
	if se.Reason != Socks5ReasonNotSocks5 || se.Code != 0x04 {
		t.Fatalf("error = %v (reason %s, code %#x), want not-SOCKS5 with the version byte", err, se.Reason, se.Code)
	}
}

func TestDialSocks5ReportsPeerClose(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	srv.SetFaults(func(f *socks5sim.Faults) { f.CloseOnGreeting = true })
	_, err := DialSocks5(context.Background(), srv.Addr(), Socks5Options{})
	se := asSocks5Error(t, err)
	if se.Stage != Socks5StageHandshake || !se.PeerClosed() {
		t.Fatalf("error = %v (stage %s, reason %s), want handshake closed by peer", err, se.Stage, se.Reason)
	}
}

func TestDialSocks5ReportsUnreachableProxy(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, err = DialSocks5(context.Background(), addr, Socks5Options{Timeout: time.Second})
	se := asSocks5Error(t, err)
	if se.Stage != Socks5StageConnect || se.Reason != Socks5ReasonIO {
		t.Fatalf("error = %v (stage %s), want TCP connect failure", err, se.Stage)
	}
}

// The previous handshake had no deadline: a proxy that accepted the
// connection and then went quiet blocked the caller forever.
func TestDialSocks5StalledProxyTimesOut(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	srv.SetFaults(func(f *socks5sim.Faults) { f.StallGreeting = true })

	start := time.Now()
	_, err := DialSocks5(context.Background(), srv.Addr(), Socks5Options{Timeout: 150 * time.Millisecond})
	elapsed := time.Since(start)

	se := asSocks5Error(t, err)
	var netErr net.Error
	if se.Stage != Socks5StageHandshake || !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("error = %v (stage %s), want a handshake timeout", err, se.Stage)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("gave up after %v, want about the 150ms timeout", elapsed)
	}
}

func TestDialSocks5CancelUnblocksStalledHandshake(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	srv.SetFaults(func(f *socks5sim.Faults) { f.StallGreeting = true })

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	_, err := DialSocks5(ctx, srv.Addr(), Socks5Options{Timeout: time.Minute})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("returned after %v, want promptly after cancellation", elapsed)
	}
}

// Replies that arrive one byte per segment must still be parsed: the previous
// code used single Read calls and treated a short read as a protocol error.
func TestSocks5HandlesRepliesSplitAcrossSegments(t *testing.T) {
	srv := startSim(t, socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: testUser, Password: testPassword})
	srv.SetFaults(func(f *socks5sim.Faults) { f.ByteAtATime = true })

	conn, err := DialSocks5(context.Background(), srv.Addr(), Socks5Options{Username: testUser, Password: testPassword})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	relay, err := conn.UDPAssociate(context.Background())
	if err != nil {
		t.Fatalf("UDP ASSOCIATE: %v", err)
	}
	if relay.Addr == nil || relay.Addr.Port == 0 || !relay.Addr.IP.IsLoopback() {
		t.Fatalf("relay = %+v, want a loopback endpoint", relay)
	}
}

func startTCPEcho(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if banner != "" {
					if _, err := io.WriteString(conn, banner); err != nil {
						return
					}
				}
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestSocks5TCPDialerTunnelsData(t *testing.T) {
	for _, target := range []string{"ip", "domain"} {
		t.Run(target, func(t *testing.T) {
			srv := startSim(t, socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: testUser, Password: testPassword})
			echo := startTCPEcho(t, "")
			if target == "domain" {
				_, port, _ := net.SplitHostPort(echo)
				echo = net.JoinHostPort("localhost", port)
			}

			dial := Socks5TCPDialer(srv.Addr(), testUser, testPassword)
			conn, err := dial(context.Background(), "tcp", echo)
			if err != nil {
				t.Fatalf("dial through proxy: %v", err)
			}
			defer conn.Close()

			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(conn, "ping"); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, 4)
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
				t.Fatalf("echo = %q, err = %v", got, err)
			}
			if st := srv.Stats(); st.Connects != 1 {
				t.Fatalf("CONNECT tunnels = %d, want 1", st.Connects)
			}
		})
	}
}

// Bytes the target sends first can share a segment with the proxy's reply.
// The reply must be consumed exactly; the previous code read up to 262 bytes
// in one call and silently swallowed the start of the tunnelled stream.
func TestSocks5TCPDialerDoesNotSwallowEarlyData(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	srv.SetFaults(func(f *socks5sim.Faults) { f.ConnectTrailer = []byte("220 ready\r\n") })
	echo := startTCPEcho(t, "")

	conn, err := Socks5TCPDialer(srv.Addr(), "", "")(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len("220 ready\r\n"))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "220 ready\r\n" {
		t.Fatalf("first tunnelled bytes = %q, err = %v", got, err)
	}
}

func TestSocks5TCPDialerReportsRefusal(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	srv.SetFaults(func(f *socks5sim.Faults) { f.ConnectReply = 0x05 })

	_, err := Socks5TCPDialer(srv.Addr(), "", "")(context.Background(), "tcp", "127.0.0.1:9")
	se := asSocks5Error(t, err)
	if se.Stage != Socks5StageRequest || se.Reason != Socks5ReasonRequestRejected || se.Code != 0x05 {
		t.Fatalf("error = %v (stage %s, reason %s, code %#x), want CONNECT refused with code 5", err, se.Stage, se.Reason, se.Code)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("error text %q does not explain the reply code", err)
	}
}

func TestSocks5TCPDialerRejectsBadRequests(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	dial := Socks5TCPDialer(srv.Addr(), "", "")

	if _, err := dial(context.Background(), "udp", "127.0.0.1:9"); err == nil {
		t.Error("non-TCP network accepted")
	}
	if st := srv.Stats(); st.Connections != 0 {
		t.Errorf("connections = %d, want none for an unsupported network", st.Connections)
	}

	_, err := dial(context.Background(), "tcp", "no-port")
	if se := asSocks5Error(t, err); se.Reason != Socks5ReasonInvalidTarget {
		t.Errorf("error = %v (reason %s), want invalid target", err, se.Reason)
	}
}

func TestNormalizeSocks5Relay(t *testing.T) {
	publicProxy := net.ParseIP("198.51.100.9")
	resolvesTo := func(ip string) func(string) net.IP {
		return func(string) net.IP { return net.ParseIP(ip) }
	}
	unresolvable := func(string) net.IP { return nil }

	cases := []struct {
		name       string
		advertised Socks5Addr
		proxyIP    net.IP
		resolve    func(string) net.IP
		wantIP     string
		wantAdjust Socks5RelayAdjustment
		wantErr    bool
	}{
		{name: "routable address is used as advertised",
			advertised: Socks5Addr{IP: net.ParseIP("203.0.113.7"), Port: 4000}, proxyIP: publicProxy,
			wantIP: "203.0.113.7"},
		{name: "0.0.0.0 means the proxy's own address",
			advertised: Socks5Addr{IP: net.IPv4zero, Port: 4000}, proxyIP: publicProxy,
			wantIP: "198.51.100.9", wantAdjust: Socks5RelayUnspecified},
		{name: ":: means the proxy's own address",
			advertised: Socks5Addr{IP: net.IPv6unspecified, Port: 4000}, proxyIP: net.ParseIP("2001:db8::1"),
			wantIP: "2001:db8::1", wantAdjust: Socks5RelayUnspecified},
		{name: "loopback from a remote proxy is the proxy itself",
			advertised: Socks5Addr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}, proxyIP: publicProxy,
			wantIP: "198.51.100.9", wantAdjust: Socks5RelayLoopback},
		{name: "loopback from a local proxy is kept",
			advertised: Socks5Addr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}, proxyIP: net.IPv4(127, 0, 0, 1),
			wantIP: "127.0.0.1"},
		{name: "private address from a public proxy is kept but flagged",
			advertised: Socks5Addr{IP: net.IPv4(10, 0, 0, 5), Port: 4000}, proxyIP: publicProxy,
			wantIP: "10.0.0.5", wantAdjust: Socks5RelayPrivate},
		{name: "private address from a private proxy is normal",
			advertised: Socks5Addr{IP: net.IPv4(10, 0, 0, 5), Port: 4000}, proxyIP: net.IPv4(10, 0, 0, 1),
			wantIP: "10.0.0.5"},
		{name: "domain name is resolved",
			advertised: Socks5Addr{Domain: "relay.example", Port: 4000}, proxyIP: publicProxy, resolve: resolvesTo("203.0.113.20"),
			wantIP: "203.0.113.20", wantAdjust: Socks5RelayDomain},
		{name: "unresolvable domain falls back to the proxy",
			advertised: Socks5Addr{Domain: "relay.example", Port: 4000}, proxyIP: publicProxy, resolve: unresolvable,
			wantIP: "198.51.100.9", wantAdjust: Socks5RelayDomainUnresolved},
		{name: "unresolvable domain without a known proxy address",
			advertised: Socks5Addr{Domain: "relay.example", Port: 4000}, resolve: unresolvable, wantErr: true},
		{name: "unspecified address without a known proxy address",
			advertised: Socks5Addr{IP: net.IPv4zero, Port: 4000}, wantErr: true},
		{name: "port zero",
			advertised: Socks5Addr{IP: net.ParseIP("203.0.113.7")}, proxyIP: publicProxy, wantErr: true},
		{name: "empty host",
			advertised: Socks5Addr{Port: 4000}, proxyIP: publicProxy, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolve := tc.resolve
			if resolve == nil {
				resolve = func(host string) net.IP {
					t.Errorf("unexpected lookup of %q", host)
					return nil
				}
			}
			relay, err := normalizeSocks5Relay(tc.advertised, tc.proxyIP, "", resolve)
			if tc.wantErr {
				se := asSocks5Error(t, err)
				if se.Reason != Socks5ReasonMalformedReply {
					t.Fatalf("reason = %s, want malformed reply", se.Reason)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if !relay.Addr.IP.Equal(net.ParseIP(tc.wantIP)) || relay.Addr.Port != 4000 {
				t.Fatalf("relay address = %v, want %s:4000", relay.Addr, tc.wantIP)
			}
			if relay.Adjustment != tc.wantAdjust {
				t.Fatalf("adjustment = %q, want %q", relay.Adjustment, tc.wantAdjust)
			}
			if relay.Advertised.Port != tc.advertised.Port || relay.Advertised.Domain != tc.advertised.Domain {
				t.Fatalf("advertised address not preserved: %+v", relay.Advertised)
			}
		})
	}
}

func TestUDPAssociateReportsProxyFailures(t *testing.T) {
	cases := []struct {
		name   string
		fault  func(*socks5sim.Faults)
		reason Socks5Reason
		code   byte
	}{
		{"command not supported", func(f *socks5sim.Faults) { f.AssociateReply = 0x07 }, Socks5ReasonRequestRejected, 0x07},
		{"not allowed by ruleset", func(f *socks5sim.Faults) { f.AssociateReply = 0x02 }, Socks5ReasonRequestRejected, 0x02},
		{"relay port zero", func(f *socks5sim.Faults) { f.Advertise = socks5sim.AdvertisePortZero }, Socks5ReasonMalformedReply, 0},
		{"closed instead of answering", func(f *socks5sim.Faults) { f.CloseOnRequest = true }, Socks5ReasonIO, 0},
		{"no answer", func(f *socks5sim.Faults) { f.StallRequest = true }, Socks5ReasonIO, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startSim(t, socks5sim.Config{})
			srv.SetFaults(tc.fault)
			conn, err := DialSocks5(context.Background(), srv.Addr(), Socks5Options{Timeout: 200 * time.Millisecond})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			_, err = conn.UDPAssociate(context.Background())
			se := asSocks5Error(t, err)
			if se.Stage != Socks5StageRequest || se.Reason != tc.reason || se.Code != tc.code {
				t.Fatalf("error = %v (stage %s, reason %s, code %#x), want reason %s code %#x",
					err, se.Stage, se.Reason, se.Code, tc.reason, tc.code)
			}
		})
	}
}
