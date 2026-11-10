//go:build linux

package runtimehost

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	externalipsec "github.com/1239t/swu-go/pkg/ipsec"
	externalswu "github.com/1239t/swu-go/pkg/swu"
	"github.com/1239t/vowifi-go/runtimehost/transport"
	"github.com/1239t/vowifi-go/runtimehost/transport/socks5sim"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// fakeDatagramTransport is a datagram transport under the test's control.
type fakeDatagramTransport struct {
	mu        sync.Mutex
	sent      [][]byte
	sentTo    []net.UDPAddr
	inbox     chan []byte
	failure   chan error
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeDatagramTransport() *fakeDatagramTransport {
	return &fakeDatagramTransport{
		inbox:   make(chan []byte, 16),
		failure: make(chan error, 1),
		closed:  make(chan struct{}),
	}
}

func (f *fakeDatagramTransport) SendTo(payload []byte, addr *net.UDPAddr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, append([]byte(nil), payload...))
	f.sentTo = append(f.sentTo, *addr)
	return len(payload), nil
}

func (f *fakeDatagramTransport) RecvFrom(buffer []byte) (int, *net.UDPAddr, error) {
	select {
	case data := <-f.inbox:
		return copy(buffer, data), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}, nil
	case err := <-f.failure:
		return 0, nil, err
	case <-f.closed:
		return 0, nil, net.ErrClosed
	}
}

func (f *fakeDatagramTransport) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeDatagramTransport) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}

func (f *fakeDatagramTransport) lastSent(t *testing.T) ([]byte, net.UDPAddr) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		t.Fatal("nothing was sent")
	}
	return f.sent[len(f.sent)-1], f.sentTo[len(f.sentTo)-1]
}

// testIKEPacket builds the smallest datagram the transport classifies as IKE.
func testIKEPacket(tag byte) []byte {
	packet := make([]byte, 28+4)
	for i := 0; i < 8; i++ {
		packet[i] = 0xa0 + tag
	}
	packet[17] = 0x20 // IKEv2
	packet[18] = 34   // IKE_SA_INIT
	packet[27] = byte(len(packet))
	packet[28] = tag
	return packet
}

func testESPPacket(tag byte) []byte {
	return []byte{0xc0, 0xff, 0xee, tag, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef}
}

func receiveWithin(t *testing.T, what string, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case data, ok := <-ch:
		if !ok {
			t.Fatalf("%s channel closed", what)
		}
		return data
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	return nil
}

func netEventWithin(t *testing.T, ch <-chan externalipsec.NetEvent) externalipsec.NetEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("network event channel closed")
		}
		return ev
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for a network event")
	}
	return externalipsec.NetEvent{}
}

// Session setup that fails before the transport is started still stops it.
// Stop used to wait for a read loop that had never been launched.
func TestSWuDatagramTransportStopWithoutStart(t *testing.T) {
	tp := newSWuDatagramTransport(newFakeDatagramTransport(), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500}, nil)

	stopped := make(chan struct{})
	go func() {
		tp.Stop()
		tp.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked on a transport that was never started")
	}
	if _, ok := <-tp.IKEPackets(); ok {
		t.Fatal("IKE channel still open after Stop")
	}
	tp.Start() // must not launch a read loop on closed channels
}

func TestSWuDatagramTransportNonESPMarker(t *testing.T) {
	fake := newFakeDatagramTransport()
	tp := newSWuDatagramTransport(fake, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500}, nil)
	tp.Start()
	defer tp.Stop()

	ike := testIKEPacket(1)
	if err := tp.SendIKE(ike); err != nil {
		t.Fatalf("send IKE on 500: %v", err)
	}
	if sent, to := fake.lastSent(t); !bytes.Equal(sent, ike) || to.Port != 500 {
		t.Fatalf("on port 500 sent % x to port %d, want the bare IKE packet", sent, to.Port)
	}

	tp.SetRemotePort(4500)
	if got := tp.RemotePort(); got != 4500 {
		t.Fatalf("remote port = %d after switching to 4500", got)
	}
	if err := tp.SendIKE(ike); err != nil {
		t.Fatalf("send IKE on 4500: %v", err)
	}
	if sent, to := fake.lastSent(t); !bytes.Equal(sent, append([]byte{0, 0, 0, 0}, ike...)) || to.Port != 4500 {
		t.Fatalf("on port 4500 sent % x to port %d, want the non-ESP marker before the IKE packet", sent, to.Port)
	}

	esp := testESPPacket(1)
	if err := tp.SendESP(esp); err != nil {
		t.Fatalf("send ESP: %v", err)
	}
	if sent, _ := fake.lastSent(t); !bytes.Equal(sent, esp) {
		t.Fatalf("ESP sent as % x, want it unchanged", sent)
	}

	fake.inbox <- []byte{0xff} // NAT keepalive: dropped
	fake.inbox <- append([]byte{0, 0, 0, 0}, ike...)
	fake.inbox <- esp
	if got := receiveWithin(t, "IKE", tp.IKEPackets()); !bytes.Equal(got, ike) {
		t.Fatalf("received IKE % x, want the marker stripped", got)
	}
	if got := receiveWithin(t, "ESP", tp.ESPPackets()); !bytes.Equal(got, esp) {
		t.Fatalf("received ESP % x, want %x", got, esp)
	}

	tp.SetRemotePort(0)
	if got := tp.RemotePort(); got != 4500 {
		t.Fatalf("remote port = %d after an invalid switch, want it unchanged", got)
	}
}

// The session switches the remote port from its own goroutine while sends
// are in flight on others; run with -race.
func TestSWuDatagramTransportRemotePortSwitchIsSynchronized(t *testing.T) {
	fake := newFakeDatagramTransport()
	tp := newSWuDatagramTransport(fake, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500}, nil)
	tp.Start()
	defer tp.Stop()

	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = tp.SendIKE(testIKEPacket(1))
				_ = tp.SendESP(testESPPacket(1))
				_ = tp.RemotePort()
				_ = tp.RemoteIP()
				_ = tp.RemoteAddrString()
			}
		}()
	}
	for i := 0; i < 200; i++ {
		tp.SetRemotePort(500 + 4000*(i%2))
	}
	wg.Wait()

	fake.mu.Lock()
	defer fake.mu.Unlock()
	for i, to := range fake.sentTo {
		marked := len(fake.sent[i]) >= 4 && bytes.Equal(fake.sent[i][:4], []byte{0, 0, 0, 0})
		isIKE := len(fake.sent[i]) >= 28
		if isIKE && marked != (to.Port == 4500) {
			t.Fatalf("send %d: marker=%v to port %d; marker and port must be taken from the same address", i, marked, to.Port)
		}
	}
}

// A transport that ends by itself used to end the read loop without a word,
// leaving a tunnel that looked up and received nothing.
func TestSWuDatagramTransportReportsTransportFailure(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	fake := newFakeDatagramTransport()
	tp := newSWuDatagramTransport(fake, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}, zap.New(core))
	tp.Start()
	defer tp.Stop()

	fake.failure <- fmt.Errorf("socks5 udp: giving up after 5 failed association attempts: %w",
		&transport.Socks5Error{Stage: transport.Socks5StageConnect, Reason: transport.Socks5ReasonIO,
			Err: errors.New("dial tcp 198.51.100.9:1080: connect: connection refused")})

	if ev := netEventWithin(t, tp.NetEventsChan()); ev.Type != externalipsec.EventNetworkDown {
		t.Fatalf("network event = %+v, want network down", ev)
	}
	entries := logs.FilterMessage("SWu datagram transport stopped receiving").All()
	if len(entries) != 1 {
		t.Fatalf("failure logged %d times, want once", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["stage"] != "tcp_connect" || fields["reason"] != "io" {
		t.Fatalf("log fields = %v, want the failing stage and reason", fields)
	}
	for key, value := range fields {
		if strings.Contains(fmt.Sprint(value), "198.51.100.9") {
			t.Fatalf("log field %q leaks the proxy address: %v", key, value)
		}
	}
}

func TestSWuDatagramTransportStopIsNotReportedAsFailure(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	tp := newSWuDatagramTransport(newFakeDatagramTransport(), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}, zap.New(core))
	tp.Start()
	tp.Stop()

	if n := logs.FilterMessage("SWu datagram transport stopped receiving").Len(); n != 0 {
		t.Fatalf("an orderly stop was logged as a failure %d times", n)
	}
	if ev, ok := <-tp.NetEventsChan(); ok {
		t.Fatalf("an orderly stop emitted %+v", ev)
	}
}

func TestBuildSWuTransportFactoryDirectRoute(t *testing.T) {
	for name, proxy := range map[string]*ProxyConfig{
		"no proxy":       nil,
		"disabled proxy": {Addr: "127.0.0.1:1080", Enabled: false},
		"blank address":  {Enabled: true},
	} {
		if factory := buildSWuTransportFactory(proxy, zap.NewNop()); factory != nil {
			t.Errorf("%s: a proxy transport factory was built for a direct route", name)
		}
	}
}

func startProxiedSWuTransport(t *testing.T, proxy *ProxyConfig, peer *socks5sim.UDPPeer, logger *zap.Logger) externalswu.Transport {
	t.Helper()
	factory := buildObservedSWuTransportFactory(proxy, epdgCandidate{Family: "ipv4", Index: 1, Total: 1}, logger, nil)
	tp, err := factory("0.0.0.0:0", peer.Addr().String())
	if err != nil {
		t.Fatalf("transport factory: %v", err)
	}
	tp.Start()
	t.Cleanup(tp.Stop)
	return tp
}

// sendIKEUntilEchoed retransmits like the IKE layer does until the simulated
// ePDG's echo comes back.
func sendIKEUntilEchoed(t *testing.T, tp externalswu.Transport, packet []byte) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_ = tp.SendIKE(packet)
		select {
		case got, ok := <-tp.IKEPackets():
			if !ok {
				t.Fatal("IKE channel closed")
			}
			if bytes.Equal(got, packet) {
				return
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("IKE packet % x was never echoed", packet[:8])
}

// End to end without hardware: IKE and ESP travel from the session-facing
// transport through an authenticating SOCKS5 proxy to a simulated ePDG and
// back.
func TestSWuTransportThroughSimulatedProxy(t *testing.T) {
	srv, err := socks5sim.Start(socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: "sim-user", Password: "sim-pass"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	peer, err := socks5sim.StartUDPPeer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Close)

	core, logs := observer.New(zap.DebugLevel)
	tp := startProxiedSWuTransport(t,
		&ProxyConfig{Addr: srv.Addr(), Username: "sim-user", Password: "sim-pass", Enabled: true},
		peer, zap.New(core))

	ike := testIKEPacket(1)
	sendIKEUntilEchoed(t, tp, ike)

	esp := testESPPacket(1)
	if err := tp.SendESP(esp); err != nil {
		t.Fatalf("send ESP: %v", err)
	}
	if got := receiveWithin(t, "ESP", tp.ESPPackets()); !bytes.Equal(got, esp) {
		t.Fatalf("ESP echo = % x, want % x", got, esp)
	}

	if st := srv.Stats(); st.AuthOK != 1 || st.Associations != 1 {
		t.Fatalf("proxy stats = %+v, want one authenticated association", st)
	}
	ready := logs.FilterMessage("SWu proxy relay ready").All()
	if len(ready) != 1 || ready[0].ContextMap()["reassociated"] != false || ready[0].ContextMap()["candidate_index"] != int64(1) {
		t.Fatalf("relay-ready log entries = %+v, want one for the first association tagged with the candidate", ready)
	}
}

// The proxy drops the association under an established tunnel. The transport
// re-associates and the session is told the path changed, which makes it send
// an authenticated IKE request so the ePDG follows the new source address.
func TestSWuTransportSignalsPathChangeAfterProxyReassociation(t *testing.T) {
	srv, err := socks5sim.Start(socks5sim.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	peer, err := socks5sim.StartUDPPeer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Close)

	core, logs := observer.New(zap.DebugLevel)
	tp := startProxiedSWuTransport(t, &ProxyConfig{Addr: srv.Addr(), Enabled: true}, peer, zap.New(core))

	sendIKEUntilEchoed(t, tp, testIKEPacket(1))
	if srv.DropControlConnections() != 1 {
		t.Fatal("the proxy had no association to drop")
	}

	ev := netEventWithin(t, tp.NetEventsChan())
	if ev.Type != externalipsec.EventPathChanged {
		t.Fatalf("network event = %+v, want path changed", ev)
	}
	sendIKEUntilEchoed(t, tp, testIKEPacket(2))

	if sources := peer.Sources(); len(sources) != 2 {
		t.Fatalf("simulated ePDG saw sources %v, want the tunnel to arrive from a second address", sources)
	}
	if n := logs.FilterMessage("SWu proxy relay lost; re-associating").Len(); n != 1 {
		t.Fatalf("relay loss logged %d times, want once", n)
	}
	ready := logs.FilterMessage("SWu proxy relay ready").All()
	if len(ready) != 2 || ready[1].ContextMap()["reassociated"] != true {
		t.Fatalf("relay-ready log entries = %+v, want a second one marked reassociated", ready)
	}

	_, proxyPort, _ := net.SplitHostPort(srv.Addr())
	peerPort := fmt.Sprint(peer.Addr().Port)
	for _, entry := range logs.All() {
		if !strings.HasPrefix(entry.Message, "SWu proxy") && !strings.HasPrefix(entry.Message, "SWu datagram") {
			continue
		}
		for key, value := range entry.ContextMap() {
			text := fmt.Sprint(value)
			if strings.Contains(text, "127.0.0.1") || text == proxyPort || text == peerPort {
				t.Fatalf("log %q field %q records an address: %v", entry.Message, key, value)
			}
		}
	}
}

func TestSWuFailureFields(t *testing.T) {
	fieldMap := func(err error) map[string]interface{} {
		core, logs := observer.New(zap.DebugLevel)
		zap.New(core).Info("x", swuFailureFields(err)...)
		return logs.All()[0].ContextMap()
	}

	if got := swuFailureFields(nil); got != nil {
		t.Fatalf("fields for a nil error = %v", got)
	}
	rejected := fieldMap(&transport.Socks5Error{
		Stage: transport.Socks5StageRequest, Reason: transport.Socks5ReasonRequestRejected, Op: "UDP ASSOCIATE", Code: 0x07,
	})
	if rejected["stage"] != "request" || rejected["reason"] != "request_rejected" || rejected["step"] != "UDP ASSOCIATE" || rejected["code"] != uint8(7) {
		t.Fatalf("rejected request fields = %v", rejected)
	}
	if got := fieldMap(fmt.Errorf("socks5 udp: %w", net.ErrClosed)); got["reason"] != "closed" {
		t.Fatalf("closed transport fields = %v", got)
	}
	if got := fieldMap(transport.ErrSocks5RelayUnavailable); got["reason"] != "relay_unavailable" {
		t.Fatalf("relay unavailable fields = %v", got)
	}
	if got := fieldMap(errors.New("write udp 10.0.0.2:40000->198.51.100.9:4500: network is unreachable")); len(got) != 1 || got["reason"] != "io" {
		t.Fatalf("generic failure fields = %v, want only a class", got)
	}
}
