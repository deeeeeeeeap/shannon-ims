package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/transport/socks5sim"
)

// eventLog collects association events from a transport.
type eventLog struct {
	mu     sync.Mutex
	events []Socks5UDPEvent
}

func (l *eventLog) record(ev Socks5UDPEvent) {
	l.mu.Lock()
	l.events = append(l.events, ev)
	l.mu.Unlock()
}

func (l *eventLog) count(kind Socks5UDPEventKind) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, ev := range l.events {
		if ev.Kind == kind {
			n++
		}
	}
	return n
}

func (l *eventLog) first(kind Socks5UDPEventKind) (Socks5UDPEvent, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ev := range l.events {
		if ev.Kind == kind {
			return ev, true
		}
	}
	return Socks5UDPEvent{}, false
}

// fastOptions keeps retry timing short enough for tests while leaving every
// mechanism in place.
func fastOptions(proxyAddr string) Socks5UDPOptions {
	return Socks5UDPOptions{
		ProxyAddr:   proxyAddr,
		Timeout:     2 * time.Second,
		MaxAttempts: 4,
		BackoffBase: 5 * time.Millisecond,
		BackoffMax:  20 * time.Millisecond,
		MinStable:   time.Millisecond,
	}
}

func newTestTransport(t *testing.T, opts Socks5UDPOptions) (*socks5UDPTransport, *eventLog) {
	t.Helper()
	log := &eventLog{}
	opts.OnEvent = log.record
	tp, err := NewSocks5UDPTransportWithOptions(opts)
	if err != nil {
		t.Fatalf("new transport: %v", err)
	}
	t.Cleanup(func() { tp.Close() })
	return tp.(*socks5UDPTransport), log
}

type received struct {
	payload []byte
	from    *net.UDPAddr
	err     error
}

// startReceiver drains the transport into a channel until it fails.
func startReceiver(tp DatagramTransport) <-chan received {
	ch := make(chan received, 4096)
	go func() {
		defer close(ch)
		buf := make([]byte, 65535)
		for {
			n, from, err := tp.RecvFrom(buf)
			if err != nil {
				ch <- received{err: err}
				return
			}
			ch <- received{payload: append([]byte(nil), buf[:n]...), from: from}
		}
	}()
	return ch
}

// expectPayload waits for want, skipping late echoes of earlier
// retransmissions.
func expectPayload(t *testing.T, ch <-chan received, want []byte) received {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got, ok := <-ch:
			if !ok {
				t.Fatalf("receiver ended while waiting for %q", want)
			}
			if got.err != nil {
				t.Fatalf("receive failed while waiting for %q: %v", want, got.err)
			}
			if bytes.Equal(got.payload, want) {
				return got
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

func expectTerminal(t *testing.T, ch <-chan received) error {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got, ok := <-ch:
			if !ok {
				t.Fatal("receiver ended without reporting an error")
			}
			if got.err != nil {
				return got.err
			}
		case <-deadline:
			t.Fatal("timed out waiting for the transport to fail")
		}
	}
}

// sendUntilDelivered retries like a retransmitting protocol would: a send may
// fail while the relay is being re-established.
func sendUntilDelivered(t *testing.T, tp DatagramTransport, dst *net.UDPAddr, ch <-chan received, payload []byte) received {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = tp.SendTo(payload, dst)
		select {
		case got, ok := <-ch:
			if !ok || got.err != nil {
				t.Fatalf("receiver failed while waiting for %q: %v", payload, got.err)
			}
			if bytes.Equal(got.payload, payload) {
				return got
			}
		case <-time.After(40 * time.Millisecond):
		}
	}
	t.Fatalf("%q was never delivered", payload)
	return received{}
}

func TestSocks5UDPTransportRoundTrip(t *testing.T) {
	srv := startSim(t, socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: testUser, Password: testPassword})
	peer := startPeer(t)
	opts := fastOptions(srv.Addr())
	opts.Username, opts.Password = testUser, testPassword
	tp, log := newTestTransport(t, opts)

	if tp.LocalAddr() != nil || tp.RelayAddr() != nil {
		t.Fatal("transport reports addresses before any association exists")
	}

	payload := []byte("ike-sa-init")
	n, err := tp.SendTo(payload, peer.Addr())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("SendTo reported %d bytes, want the payload length %d", n, len(payload))
	}

	buf := make([]byte, 2048)
	n, from, err := tp.RecvFrom(buf)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("received %q, want %q", buf[:n], payload)
	}
	if !from.IP.Equal(peer.Addr().IP) || from.Port != peer.Addr().Port {
		t.Fatalf("source = %v, want the peer %v", from, peer.Addr())
	}

	ev, ok := log.first(Socks5UDPAssociated)
	if !ok {
		t.Fatal("no association event was reported")
	}
	relay := tp.RelayAddr()
	if relay == nil || ev.Relay.Addr == nil || relay.Port != ev.Relay.Addr.Port || ev.CredentialsIgnored {
		t.Fatalf("event relay %+v does not match RelayAddr %v", ev, relay)
	}
	if tp.LocalAddr() == nil {
		t.Fatal("no local address after association")
	}
	if st := tp.Stats(); st.Associations != 1 || st.FailedAttempts != 0 || st.MalformedDropped != 0 {
		t.Fatalf("stats = %+v, want one clean association", st)
	}
	waitFor(t, "the proxy to count one authenticated round trip", func() bool {
		st := srv.Stats()
		return st.AuthOK == 1 && st.DatagramsOut == 1 && st.DatagramsIn == 1
	})
}

func TestSocks5UDPTransportValidatesInput(t *testing.T) {
	if _, err := NewSocks5UDPTransport("", "", ""); err == nil {
		t.Error("transport created without a proxy address")
	}

	srv := startSim(t, socks5sim.Config{})
	tp, _ := newTestTransport(t, fastOptions(srv.Addr()))
	if _, err := tp.SendTo([]byte("x"), nil); err == nil {
		t.Error("send to a nil address succeeded")
	}
	if st := srv.Stats(); st.Connections != 0 {
		t.Errorf("connections = %d, want none for an invalid send", st.Connections)
	}
}

// A proxy bound to the wildcard address advertises 0.0.0.0 as its relay. The
// previous code sent datagrams to that address as is, i.e. to the local host,
// so the tunnel never came up although the proxy self-check had passed.
func TestSocks5UDPTransportUsesProxyAddressForWildcardRelay(t *testing.T) {
	for name, advertise := range map[string]socks5sim.RelayAdvertise{
		"unspecified": socks5sim.AdvertiseUnspecified,
		"domain":      socks5sim.AdvertiseDomain,
	} {
		t.Run(name, func(t *testing.T) {
			srv := startSim(t, socks5sim.Config{})
			srv.SetFaults(func(f *socks5sim.Faults) { f.Advertise = advertise })
			peer := startPeer(t)
			tp, log := newTestTransport(t, fastOptions(srv.Addr()))
			ch := startReceiver(tp)

			if _, err := tp.SendTo([]byte("hello"), peer.Addr()); err != nil {
				t.Fatalf("send: %v", err)
			}
			expectPayload(t, ch, []byte("hello"))

			ev, _ := log.first(Socks5UDPAssociated)
			if ev.Relay.Addr == nil || !ev.Relay.Addr.IP.IsLoopback() {
				t.Fatalf("relay address = %v, want the proxy's own address", ev.Relay.Addr)
			}
			if ev.Relay.Adjustment == Socks5RelayAsAdvertised {
				t.Fatal("the address correction was not reported")
			}
		})
	}
}

// Anything can arrive on a UDP port. Invalid relay datagrams are dropped and
// counted; the previous code returned them as errors, which ended the tunnel's
// read loop, and panicked on the IPv6-typed short datagram below.
func TestSocks5UDPTransportDropsMalformedDatagrams(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	peer := startPeer(t)
	tp, _ := newTestTransport(t, fastOptions(srv.Addr()))
	ch := startReceiver(tp)

	if _, err := tp.SendTo([]byte("first"), peer.Addr()); err != nil {
		t.Fatalf("send: %v", err)
	}
	expectPayload(t, ch, []byte("first"))

	garbage := [][]byte{
		{0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4, 5, 6, 7, 8},
		{0x00, 0x00, 0x01, 0x01, 192, 0, 2, 1, 0x11, 0x94, 'x'},
		{0x00, 0x00, 0x00, 0x7f, 192, 0, 2, 1, 0x11, 0x94, 'x'},
		{},
	}
	for i, raw := range garbage {
		if srv.InjectToClients(raw) != 1 {
			t.Fatalf("datagram %d was not injected", i)
		}
	}
	waitFor(t, "malformed datagrams to be counted", func() bool {
		return tp.Stats().MalformedDropped == uint64(len(garbage))
	})

	if _, err := tp.SendTo([]byte("second"), peer.Addr()); err != nil {
		t.Fatalf("send after garbage: %v", err)
	}
	expectPayload(t, ch, []byte("second"))
	if st := tp.Stats(); st.Associations != 1 {
		t.Fatalf("associations = %d, want the original one to survive", st.Associations)
	}
}

// Losing the control connection ends the relay. The transport must make a new
// association and carry on; the remote peer then sees a new source address,
// exactly like a NAT rebinding.
func TestSocks5UDPTransportReassociatesAfterControlLoss(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	peer := startPeer(t)
	tp, log := newTestTransport(t, fastOptions(srv.Addr()))
	ch := startReceiver(tp)

	sendUntilDelivered(t, tp, peer.Addr(), ch, []byte("before"))
	firstRelay := tp.RelayAddr()
	time.Sleep(10 * time.Millisecond) // let the association count as stable

	if srv.DropControlConnections() != 1 {
		t.Fatal("the proxy had no association to drop")
	}
	waitFor(t, "the loss to be noticed", func() bool { return log.count(Socks5UDPAssociationLost) == 1 })

	sendUntilDelivered(t, tp, peer.Addr(), ch, []byte("after"))

	if log.count(Socks5UDPReassociated) != 1 || log.count(Socks5UDPAssociated) != 1 {
		t.Fatalf("events: associated=%d reassociated=%d, want 1 and 1",
			log.count(Socks5UDPAssociated), log.count(Socks5UDPReassociated))
	}
	if st := tp.Stats(); st.Associations != 2 || st.FailedAttempts != 0 {
		t.Fatalf("stats = %+v, want two associations and no failed attempt", st)
	}
	waitFor(t, "the proxy to hold only the replacement association", func() bool {
		return srv.Stats().ActiveAssociations == 1
	})
	if st := srv.Stats(); st.Connections != 2 {
		t.Fatalf("proxy stats = %+v, want exactly one replacement connection", st)
	}
	if secondRelay := tp.RelayAddr(); secondRelay == nil || secondRelay.Port == firstRelay.Port {
		t.Fatalf("relay did not change: %v -> %v", firstRelay, secondRelay)
	}
	if sources := peer.Sources(); len(sources) != 2 {
		t.Fatalf("peer saw sources %v, want two: one per association", sources)
	}
}

// countingDialer counts TCP connection attempts to the proxy.
func countingDialer(counter *atomic.Int64) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		counter.Add(1)
		return d.DialContext(ctx, network, addr)
	}
}

// With the proxy gone for good, attempts are spaced, bounded, and then the
// transport fails permanently. The previous code dialled the proxy again on
// every single send and receive, leaking a socket and a goroutine each time.
func TestSocks5UDPTransportGivesUpWithoutConnectionStorm(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	peer := startPeer(t)
	var dials atomic.Int64
	opts := fastOptions(srv.Addr())
	opts.Dial = countingDialer(&dials)
	tp, log := newTestTransport(t, opts)
	ch := startReceiver(tp)

	sendUntilDelivered(t, tp, peer.Addr(), ch, []byte("up"))
	time.Sleep(10 * time.Millisecond) // let the association count as stable
	srv.Close()

	for i := 0; i < 500; i++ {
		_, _ = tp.SendTo([]byte("lost"), peer.Addr())
	}
	err := expectTerminal(t, ch)
	if !strings.Contains(err.Error(), "giving up") {
		t.Fatalf("terminal error = %v, want the give-up reason", err)
	}

	if got := dials.Load(); got != int64(1+opts.MaxAttempts) {
		t.Fatalf("proxy was dialled %d times, want 1 success + %d bounded retries", got, opts.MaxAttempts)
	}
	// Events are delivered after the state change they describe.
	waitFor(t, "the give-up event", func() bool { return log.count(Socks5UDPFailed) == 1 })
	if got := log.count(Socks5UDPAttemptFailed); got != opts.MaxAttempts {
		t.Fatalf("attempt_failed events = %d, want %d", got, opts.MaxAttempts)
	}

	if _, sendErr := tp.SendTo([]byte("x"), peer.Addr()); sendErr == nil || !strings.Contains(sendErr.Error(), "giving up") {
		t.Fatalf("send after giving up: %v, want the terminal error", sendErr)
	}
	time.Sleep(60 * time.Millisecond)
	if got := dials.Load(); got != int64(1+opts.MaxAttempts) {
		t.Fatalf("proxy dialled again after giving up (%d dials)", got)
	}
}

// A proxy that grants an association and drops it right away must not be
// retried forever at full speed.
func TestSocks5UDPTransportGivesUpOnFlappingProxy(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	srv.SetFaults(func(f *socks5sim.Faults) { f.AssociationLifetime = 5 * time.Millisecond })
	opts := fastOptions(srv.Addr())
	opts.MaxAttempts = 3
	opts.MinStable = 10 * time.Second
	tp, log := newTestTransport(t, opts)

	err := expectTerminal(t, startReceiver(tp))
	if !strings.Contains(err.Error(), "giving up") {
		t.Fatalf("terminal error = %v, want the give-up reason", err)
	}
	if st := srv.Stats(); st.Associations != uint64(opts.MaxAttempts) {
		t.Fatalf("proxy granted %d associations, want %d before the transport gave up", st.Associations, opts.MaxAttempts)
	}
	waitFor(t, "the give-up event", func() bool { return log.count(Socks5UDPFailed) == 1 })
}

// A stable period resets the failure count: occasional drops, however many
// over the life of a long session, never add up to giving up.
func TestSocks5UDPTransportStableAssociationResetsFailures(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	peer := startPeer(t)
	opts := fastOptions(srv.Addr())
	opts.MaxAttempts = 2
	tp, log := newTestTransport(t, opts)
	ch := startReceiver(tp)

	for round := 0; round < 6; round++ {
		sendUntilDelivered(t, tp, peer.Addr(), ch, []byte(fmt.Sprintf("round-%d", round)))
		time.Sleep(5 * time.Millisecond)
		srv.DropControlConnections()
		want := round + 1
		waitFor(t, "the loss to be noticed", func() bool { return log.count(Socks5UDPAssociationLost) == want })
	}
	sendUntilDelivered(t, tp, peer.Addr(), ch, []byte("still alive"))
	if log.count(Socks5UDPFailed) != 0 {
		t.Fatal("transport gave up although every association had been stable")
	}
}

func TestSocks5UDPTransportCloseIsTerminal(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	peer := startPeer(t)
	tp, _ := newTestTransport(t, fastOptions(srv.Addr()))
	ch := startReceiver(tp)
	sendUntilDelivered(t, tp, peer.Addr(), ch, []byte("up"))

	if err := tp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := expectTerminal(t, ch); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("blocked receive returned %v, want net.ErrClosed", err)
	}
	if _, err := tp.SendTo([]byte("x"), peer.Addr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("send after close: %v, want net.ErrClosed", err)
	}
	if _, _, err := tp.RecvFrom(make([]byte, 16)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("receive after close: %v, want net.ErrClosed", err)
	}
	if err := tp.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}

	// The previous code re-dialled the proxy from a closed transport.
	time.Sleep(60 * time.Millisecond)
	if st := srv.Stats(); st.Connections != 1 {
		t.Fatalf("connections = %d, want 1: a closed transport must not reconnect", st.Connections)
	}
	waitFor(t, "the proxy to release the association", func() bool { return srv.Stats().ActiveAssociations == 0 })
	if tp.LocalAddr() != nil || tp.RelayAddr() != nil {
		t.Fatal("closed transport still reports addresses")
	}
}

// The previous code held its lock across an unbounded handshake, so Close
// blocked for as long as the proxy stayed silent.
func TestSocks5UDPTransportCloseInterruptsStalledHandshake(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	srv.SetFaults(func(f *socks5sim.Faults) { f.StallGreeting = true })
	opts := fastOptions(srv.Addr())
	opts.Timeout = time.Minute
	tp, _ := newTestTransport(t, opts)
	ch := startReceiver(tp)

	waitFor(t, "the handshake to start", func() bool { return srv.Stats().Connections == 1 })

	start := time.Now()
	if err := tp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close took %v while the handshake was stalled", elapsed)
	}
	if err := expectTerminal(t, ch); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("receive returned %v, want net.ErrClosed", err)
	}
}

// Sends never wait out a back-off period: the caller's own retransmission
// timer covers the gap, and blocking here would stall its send path.
func TestSocks5UDPTransportSendFailsFastWhileRelayIsDown(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadProxy := ln.Addr().String()
	ln.Close()

	var dials atomic.Int64
	opts := fastOptions(deadProxy)
	opts.BackoffBase = 2 * time.Second
	opts.BackoffMax = 2 * time.Second
	opts.Dial = countingDialer(&dials)
	tp, _ := newTestTransport(t, opts)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}

	_, err = tp.SendTo([]byte("x"), dst)
	if se := asSocks5Error(t, err); se.Stage != Socks5StageConnect {
		t.Fatalf("first send: %v, want the TCP connect failure", err)
	}

	start := time.Now()
	for i := 0; i < 50; i++ {
		if _, err := tp.SendTo([]byte("x"), dst); !errors.Is(err, ErrSocks5RelayUnavailable) {
			t.Fatalf("send during back-off: %v, want ErrSocks5RelayUnavailable", err)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("50 sends during back-off took %v, want them to fail immediately", elapsed)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("proxy dialled %d times during back-off, want 1", got)
	}
}

func TestSocks5UDPTransportReportsIgnoredCredentials(t *testing.T) {
	srv := startSim(t, socks5sim.Config{Auth: socks5sim.AuthNone})
	peer := startPeer(t)
	opts := fastOptions(srv.Addr())
	opts.Username, opts.Password = testUser, testPassword
	tp, log := newTestTransport(t, opts)
	ch := startReceiver(tp)

	sendUntilDelivered(t, tp, peer.Addr(), ch, []byte("hello"))
	ev, ok := log.first(Socks5UDPAssociated)
	if !ok || !ev.CredentialsIgnored {
		t.Fatalf("association event = %+v, want credentials reported as ignored", ev)
	}
}

// Loss, reordering, duplication and delay on the proxy path are passed on to
// the tunnel protocol, which is built to handle them; none may break the
// transport itself.
func TestSocks5UDPTransportSurvivesImpairedPath(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	peer := startPeer(t)
	tp, _ := newTestTransport(t, fastOptions(srv.Addr()))
	ch := startReceiver(tp)
	sendUntilDelivered(t, tp, peer.Addr(), ch, []byte("warm-up"))

	t.Run("loss in both directions", func(t *testing.T) {
		srv.SetFaults(func(f *socks5sim.Faults) { f.DropOutbound, f.DropInbound = 2, 2 })
		sendUntilDelivered(t, tp, peer.Addr(), ch, []byte("retransmitted"))
		if st := srv.Stats(); st.DroppedOut != 2 || st.DroppedIn != 2 {
			t.Fatalf("proxy dropped out=%d in=%d, want 2 and 2", st.DroppedOut, st.DroppedIn)
		}
	})

	t.Run("reordering", func(t *testing.T) {
		srv.SetFaults(func(f *socks5sim.Faults) { f.ReorderInbound = 4 })
		defer srv.SetFaults(func(f *socks5sim.Faults) { f.ReorderInbound = 0 })
		for i := 0; i < 4; i++ {
			if _, err := tp.SendTo([]byte{'r', byte('0' + i)}, peer.Addr()); err != nil {
				t.Fatalf("send %d: %v", i, err)
			}
			time.Sleep(2 * time.Millisecond)
		}
		var order []string
		for len(order) < 4 {
			select {
			case got := <-ch:
				if got.err != nil {
					t.Fatalf("receive: %v", got.err)
				}
				if len(got.payload) == 2 && got.payload[0] == 'r' {
					order = append(order, string(got.payload))
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("only %v arrived", order)
			}
		}
		arrived := strings.Join(order, ",")
		sorted := append([]string(nil), order...)
		sort.Strings(sorted)
		if strings.Join(sorted, ",") != "r0,r1,r2,r3" {
			t.Fatalf("arrived %s, want each of r0..r3 exactly once", arrived)
		}
		if arrived == "r0,r1,r2,r3" {
			t.Fatalf("arrival order = %s, the injected reordering was not applied", arrived)
		}
	})

	t.Run("duplication", func(t *testing.T) {
		srv.SetFaults(func(f *socks5sim.Faults) { f.DuplicateInbound = true })
		defer srv.SetFaults(func(f *socks5sim.Faults) { f.DuplicateInbound = false })
		if _, err := tp.SendTo([]byte("twice"), peer.Addr()); err != nil {
			t.Fatalf("send: %v", err)
		}
		expectPayload(t, ch, []byte("twice"))
		expectPayload(t, ch, []byte("twice"))
	})

	t.Run("delay", func(t *testing.T) {
		srv.SetFaults(func(f *socks5sim.Faults) { f.DelayInbound = 120 * time.Millisecond })
		defer srv.SetFaults(func(f *socks5sim.Faults) { f.DelayInbound = 0 })
		start := time.Now()
		if _, err := tp.SendTo([]byte("late"), peer.Addr()); err != nil {
			t.Fatalf("send: %v", err)
		}
		expectPayload(t, ch, []byte("late"))
		if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
			t.Fatalf("reply arrived after %v, the injected delay was not applied", elapsed)
		}
	})

	if st := tp.Stats(); st.Associations != 1 || st.MalformedDropped != 0 {
		t.Fatalf("stats = %+v, want the single association to survive every impairment", st)
	}
}

// Several flows share one transport, as IKE and ESP do, each waiting for its
// own replies while the others keep sending.
func TestSocks5UDPTransportHighLoad(t *testing.T) {
	const (
		flows    = 6
		perFlow  = 400
		maxBytes = 1400
	)
	srv := startSim(t, socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: testUser, Password: testPassword})
	peer := startPeer(t)
	opts := fastOptions(srv.Addr())
	opts.Username, opts.Password = testUser, testPassword
	tp, _ := newTestTransport(t, opts)

	inbox := make([]chan []byte, flows)
	for i := range inbox {
		inbox[i] = make(chan []byte, 64)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := tp.RecvFrom(buf)
			if err != nil {
				return
			}
			if n < 5 || int(buf[0]) >= flows {
				continue
			}
			inbox[buf[0]] <- append([]byte(nil), buf[:n]...)
		}
	}()

	makePayload := func(flow, seq int) []byte {
		size := 5 + (flow*131+seq*17)%(maxBytes-5)
		p := make([]byte, size)
		p[0] = byte(flow)
		binary.BigEndian.PutUint32(p[1:5], uint32(seq))
		for i := 5; i < size; i++ {
			p[i] = byte(flow + seq + i)
		}
		return p
	}

	var wg sync.WaitGroup
	errs := make(chan error, flows)
	for flow := 0; flow < flows; flow++ {
		wg.Add(1)
		go func(flow int) {
			defer wg.Done()
			for seq := 0; seq < perFlow; seq++ {
				want := makePayload(flow, seq)
				delivered := false
				for attempt := 0; attempt < 20 && !delivered; attempt++ {
					if _, err := tp.SendTo(want, peer.Addr()); err != nil {
						errs <- fmt.Errorf("flow %d seq %d: send: %w", flow, seq, err)
						return
					}
					timeout := time.After(250 * time.Millisecond)
				waiting:
					for {
						select {
						case got := <-inbox[flow]:
							if bytes.Equal(got, want) {
								delivered = true
								break waiting
							}
							if binary.BigEndian.Uint32(got[1:5]) >= uint32(seq) {
								errs <- fmt.Errorf("flow %d seq %d: corrupted or misrouted datagram", flow, seq)
								return
							}
						case <-timeout:
							break waiting
						}
					}
				}
				if !delivered {
					errs <- fmt.Errorf("flow %d seq %d: no reply after 20 attempts", flow, seq)
					return
				}
			}
		}(flow)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if st := tp.Stats(); st.Associations != 1 || st.MalformedDropped != 0 {
		t.Fatalf("stats = %+v, want one association and no malformed datagram under load", st)
	}
	waitFor(t, "the proxy to count every relayed datagram", func() bool {
		return srv.Stats().DatagramsOut >= flows*perFlow
	})
	if st := srv.Stats(); st.Connections != 1 {
		t.Fatalf("proxy stats = %+v, want the whole load on one control connection", st)
	}
}

// Every entry point is used at once while the proxy drops associations; run
// with -race this is the check that the transport's state is properly guarded.
func TestSocks5UDPTransportConcurrentUse(t *testing.T) {
	srv := startSim(t, socks5sim.Config{})
	peer := startPeer(t)
	tp, _ := newTestTransport(t, fastOptions(srv.Addr()))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var echoed atomic.Int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			if _, _, err := tp.RecvFrom(buf); err != nil {
				return
			}
			echoed.Add(1)
		}
	}()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = tp.SendTo([]byte("payload"), peer.Addr())
				_ = tp.LocalAddr()
				_ = tp.RelayAddr()
				_ = tp.Stats()
				time.Sleep(200 * time.Microsecond)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			time.Sleep(20 * time.Millisecond)
			srv.DropControlConnections()
			tp.SetEventHandler(func(Socks5UDPEvent) {})
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	tp.Close()
	wg.Wait()

	if echoed.Load() == 0 {
		t.Fatal("no datagram made the round trip")
	}
}

func TestNewTransportFromRoutePolicy(t *testing.T) {
	peer := startPeer(t)

	direct, err := NewTransportFromRoutePolicy(DefaultRoutePolicy())
	if err != nil {
		t.Fatalf("direct transport: %v", err)
	}
	defer direct.Close()
	if _, ok := direct.(Socks5UDPObservable); ok {
		t.Fatal("direct policy produced a proxy transport")
	}
	if _, err := direct.SendTo([]byte("direct"), peer.Addr()); err != nil {
		t.Fatalf("direct send: %v", err)
	}
	buf := make([]byte, 64)
	n, from, err := direct.RecvFrom(buf)
	if err != nil || string(buf[:n]) != "direct" || from.Port != peer.Addr().Port {
		t.Fatalf("direct receive: %q from %v, err %v", buf[:n], from, err)
	}

	srv := startSim(t, socks5sim.Config{})
	proxied, err := NewTransportFromRoutePolicy(RoutePolicy{Kind: ProxySocks5UDPAssociate, Addr: srv.Addr()})
	if err != nil {
		t.Fatalf("proxied transport: %v", err)
	}
	defer proxied.Close()
	if _, ok := proxied.(Socks5UDPObservable); !ok {
		t.Fatal("proxy policy did not produce an observable proxy transport")
	}
	if _, err := proxied.SendTo([]byte("proxied"), peer.Addr()); err != nil {
		t.Fatalf("proxied send: %v", err)
	}
	n, _, err = proxied.RecvFrom(buf)
	if err != nil || string(buf[:n]) != "proxied" {
		t.Fatalf("proxied receive: %q, err %v", buf[:n], err)
	}
	waitFor(t, "the proxy to count the relayed datagram", func() bool { return srv.Stats().DatagramsOut == 1 })
}
