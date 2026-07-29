package ipsec3gpp

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProtectedChannelOwnerAdoptsAndClosesExactlyOnce(t *testing.T) {
	owner := NewProtectedChannelOwner()
	lease, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve channel: %v", err)
	}
	policyInput := syntheticProtectedChannelPolicyInput()
	if err := lease.Install(policyInput); err != nil {
		t.Fatalf("install channel: %v", err)
	}
	carrier := &protectedChannelCloseCountingConn{}
	if err := lease.OpenUDP(carrier); err != nil {
		t.Fatalf("open UDP channel: %v", err)
	}

	handle, err := owner.Adopt(lease)
	if err != nil {
		t.Fatalf("adopt channel: %v", err)
	}
	if handle == nil {
		t.Fatal("adopt returned a nil handle")
	}
	if _, err := owner.Adopt(lease); err == nil {
		t.Fatal("the same lease was adopted twice")
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("close consumed lease: %v", err)
	}
	if got := carrier.closeCount.Load(); got != 0 {
		t.Fatalf("consumed lease closed the adopted carrier %d times", got)
	}

	if err := handle.Close(); err != nil {
		t.Fatalf("close handle: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("close handle again: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close owner: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close owner again: %v", err)
	}
	if got := carrier.closeCount.Load(); got != 1 {
		t.Fatalf("physical carrier closes = %d, want 1", got)
	}
}

func TestProtectedChannelLeaseInstallsExactlyOnce(t *testing.T) {
	owner := NewProtectedChannelOwner()
	lease, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve channel: %v", err)
	}
	first := syntheticProtectedChannelPolicyInput()
	if err := lease.Install(first); err != nil {
		t.Fatalf("install first policy: %v", err)
	}
	second := syntheticProtectedChannelPolicyInput()
	second.RemoteIP = net.ParseIP("2001:db8::30")
	second.Mech.PortS++
	if err := lease.Install(second); err == nil {
		t.Fatal("the same SA generation accepted a second policy/transform install")
	}
	if got := lease.RemoteIP(); !got.Equal(first.RemoteIP) {
		t.Fatal("rejected install changed the generation's remote binding")
	}
	if got := lease.RemoteClientPort(); got != first.Mech.PortS {
		t.Fatalf("rejected install changed remote port-s to %d", got)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("close lease: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close owner: %v", err)
	}
}

func TestProtectedChannelOwnerStopWaitsForInFlightOperation(t *testing.T) {
	owner := NewProtectedChannelOwner()
	lease, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve channel: %v", err)
	}
	if err := lease.Install(syntheticProtectedChannelPolicyInput()); err != nil {
		t.Fatalf("install channel: %v", err)
	}
	carrier := newProtectedChannelBlockingConn()
	if err := lease.OpenUDP(carrier); err != nil {
		t.Fatalf("open UDP channel: %v", err)
	}
	handle, err := owner.Adopt(lease)
	if err != nil {
		t.Fatalf("adopt channel: %v", err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := handle.Write([]byte("synthetic"))
		writeDone <- writeErr
	}()
	<-carrier.writeEntered

	stopDone := make(chan error, 1)
	go func() { stopDone <- owner.Close() }()
	<-carrier.closed
	select {
	case err := <-stopDone:
		t.Fatalf("Stop returned before the in-flight write exited: %v", err)
	default:
	}

	close(carrier.releaseWrite)
	if err := <-writeDone; err == nil {
		t.Fatal("the interrupted in-flight write unexpectedly succeeded")
	}
	if err := <-stopDone; err != nil {
		t.Fatalf("Stop: %v", err)
	}
	before := carrier.writeCount.Load()
	if _, err := handle.Write([]byte("after-stop")); err == nil {
		t.Fatal("a write was accepted after Stop")
	}
	if got := carrier.writeCount.Load(); got != before {
		t.Fatalf("post-Stop write reached the carrier: before=%d after=%d", before, got)
	}
}

func TestProtectedChannelOwnerRejectsLateOlderGeneration(t *testing.T) {
	owner := NewProtectedChannelOwner()
	older, olderCarrier := readyProtectedChannelUDPLease(t, owner)
	newer, newerCarrier := readyProtectedChannelUDPLease(t, owner)

	newerHandle, err := owner.Adopt(newer)
	if err != nil {
		t.Fatalf("adopt newer generation: %v", err)
	}
	if _, err := owner.Adopt(older); err == nil {
		t.Fatal("a late older generation displaced the current channel")
	}
	if got := olderCarrier.closeCount.Load(); got != 1 {
		t.Fatalf("stale candidate closes = %d, want 1", got)
	}
	if got := newerCarrier.closeCount.Load(); got != 0 {
		t.Fatalf("current carrier was closed %d times by a stale adoption", got)
	}
	if _, err := newerHandle.Write([]byte("current")); err != nil {
		t.Fatalf("current generation became unusable: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close owner: %v", err)
	}
	if got := newerCarrier.closeCount.Load(); got != 1 {
		t.Fatalf("current carrier closes = %d, want 1 after Stop", got)
	}
}

func TestProtectedChannelOwnerReplacementRetiresOldGeneration(t *testing.T) {
	owner := NewProtectedChannelOwner()
	older, olderCarrier := readyProtectedChannelUDPLease(t, owner)
	olderHandle, err := owner.Adopt(older)
	if err != nil {
		t.Fatalf("adopt older generation: %v", err)
	}
	newer, newerCarrier := readyProtectedChannelUDPLease(t, owner)
	newerHandle, err := owner.Adopt(newer)
	if err != nil {
		t.Fatalf("adopt newer generation: %v", err)
	}
	if got := olderCarrier.closeCount.Load(); got != 1 {
		t.Fatalf("retired carrier closes = %d, want 1", got)
	}
	if _, err := olderHandle.Write([]byte("stale")); err == nil {
		t.Fatal("retired generation remained writable")
	}
	if _, err := newerHandle.Write([]byte("current")); err != nil {
		t.Fatalf("current generation is not writable: %v", err)
	}
	if olderHandle.ClientPort() != 0 {
		t.Fatal("retired handle still exposes a live client port")
	}
	if newerHandle.ServerPort() != older.ServerPort() {
		t.Fatal("replacement changed the stable server port")
	}
	if newerHandle.ClientPort() == older.ClientPort() {
		t.Fatal("replacement reused the live predecessor client port")
	}
	if got := newerCarrier.closeCount.Load(); got != 0 {
		t.Fatalf("current carrier closes = %d, want 0", got)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close owner: %v", err)
	}
	if got := newerCarrier.closeCount.Load(); got != 1 {
		t.Fatalf("current carrier closes after Stop = %d, want 1", got)
	}
}

func TestProtectedChannelOwnerReplacementWaitsForOldInFlightOperation(t *testing.T) {
	owner := NewProtectedChannelOwner()
	older, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve older generation: %v", err)
	}
	if err := older.Install(syntheticProtectedChannelPolicyInput()); err != nil {
		t.Fatalf("install older generation: %v", err)
	}
	blockingCarrier := newProtectedChannelBlockingConn()
	if err := older.OpenUDP(blockingCarrier); err != nil {
		t.Fatalf("open older generation: %v", err)
	}
	olderHandle, err := owner.Adopt(older)
	if err != nil {
		t.Fatalf("adopt older generation: %v", err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := olderHandle.Write([]byte("in-flight"))
		writeDone <- writeErr
	}()
	<-blockingCarrier.writeEntered

	newer, _ := readyProtectedChannelUDPLease(t, owner)
	adoptDone := make(chan error, 1)
	go func() {
		_, adoptErr := owner.Adopt(newer)
		adoptDone <- adoptErr
	}()
	<-blockingCarrier.closed
	select {
	case err := <-adoptDone:
		t.Fatalf("replacement returned before the retired operation joined: %v", err)
	default:
	}
	close(blockingCarrier.releaseWrite)
	if err := <-writeDone; err == nil {
		t.Fatal("retired in-flight write unexpectedly succeeded")
	}
	if err := <-adoptDone; err != nil {
		t.Fatalf("replacement: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close owner: %v", err)
	}
}

func TestProtectedChannelOwnerConcurrentAdoptionKeepsNewestGeneration(t *testing.T) {
	owner := NewProtectedChannelOwner()
	const candidates = 16
	leases := make([]*ProtectedChannelLease, candidates)
	carriers := make([]*protectedChannelCloseCountingConn, candidates)
	for i := range leases {
		leases[i], carriers[i] = readyProtectedChannelUDPLease(t, owner)
	}
	handles := make([]*ProtectedChannelHandle, candidates)
	errs := make([]error, candidates)
	var wg sync.WaitGroup
	wg.Add(candidates)
	for i := range leases {
		go func(index int) {
			defer wg.Done()
			handles[index], errs[index] = owner.Adopt(leases[index])
		}(i)
	}
	wg.Wait()
	newest := candidates - 1
	if errs[newest] != nil || handles[newest] == nil {
		t.Fatalf("newest generation was not adopted: %v", errs[newest])
	}
	if _, err := handles[newest].Write([]byte("current")); err != nil {
		t.Fatalf("newest generation is not current: %v", err)
	}
	for i := 0; i < newest; i++ {
		if handles[i] != nil {
			if _, err := handles[i].Write([]byte("stale")); err == nil {
				t.Fatalf("generation %d remained current", i+1)
			}
		}
		if got := carriers[i].closeCount.Load(); got != 1 {
			t.Fatalf("displaced carrier %d closes = %d, want 1", i+1, got)
		}
	}
	if got := carriers[newest].closeCount.Load(); got != 0 {
		t.Fatalf("newest carrier closes = %d, want 0", got)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close owner: %v", err)
	}
}

func TestProtectedChannelOwnerNeverReusesALiveClientPort(t *testing.T) {
	owner := NewProtectedChannelOwner()
	leases := make([]*ProtectedChannelLease, 0, protectedChannelClientSpan)
	livePorts := make(map[int]struct{}, protectedChannelClientSpan)
	for i := 0; i < protectedChannelClientSpan; i++ {
		lease, err := owner.Reserve()
		if err != nil {
			t.Fatalf("reserve generation %d: %v", i+1, err)
		}
		port := lease.ClientPort()
		if _, duplicate := livePorts[port]; duplicate {
			t.Fatalf("a live client port was reissued at generation %d", i+1)
		}
		livePorts[port] = struct{}{}
		leases = append(leases, lease)
	}
	if _, err := owner.Reserve(); err == nil {
		t.Fatal("port exhaustion did not fail closed")
	}

	releasedPort := leases[0].ClientPort()
	if err := leases[0].Close(); err != nil {
		t.Fatalf("release first generation: %v", err)
	}
	delete(livePorts, releasedPort)
	replacement, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve after release: %v", err)
	}
	if _, duplicate := livePorts[replacement.ClientPort()]; duplicate {
		t.Fatal("replacement reused a port still held by another generation")
	}

	if err := owner.Close(); err != nil {
		t.Fatalf("close owner: %v", err)
	}
}

func TestProtectedChannelLeaseOwnsTCPStackAndJoinedTeardown(t *testing.T) {
	owner := NewProtectedChannelOwner()
	lease, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve channel: %v", err)
	}
	if err := lease.Install(syntheticProtectedChannelPolicyInput()); err != nil {
		t.Fatalf("install channel: %v", err)
	}
	carrier := &protectedChannelCloseCountingConn{}
	if err := lease.OpenTCP(carrier, 1280); err != nil {
		t.Fatalf("open TCP channel: %v", err)
	}
	if !lease.ServerFlowReady() {
		t.Fatal("OpenTCP returned before the server flow was ready")
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("close TCP lease: %v", err)
	}
	if lease.ServerFlowReady() {
		t.Fatal("closed TCP lease still reports a ready server flow")
	}
	if got := carrier.closeCount.Load(); got != 1 {
		t.Fatalf("TCP carrier closes = %d, want 1", got)
	}
}

func TestProtectedChannelTCPClientFlowContinuesAcrossAdoption(t *testing.T) {
	owner := NewProtectedChannelOwner()
	lease, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve channel: %v", err)
	}
	policyInput := syntheticProtectedChannelPolicyInput()
	if err := lease.Install(policyInput); err != nil {
		t.Fatalf("install channel: %v", err)
	}

	clientCarrier, peerCarrier := newProductionWirePacketPair()
	if err := lease.OpenTCP(clientCarrier, ProtectedTunnelMTU); err != nil {
		t.Fatalf("open TCP channel: %v", err)
	}
	policyInput.UEPortC = lease.ClientPort()
	policyInput.UEPortS = lease.ServerPort()
	policyInput.UESPIc = lease.ClientSPI()
	policyInput.UESPIs = lease.ServerSPI()
	clientPolicy, err := NewPolicy(policyInput)
	if err != nil {
		t.Fatalf("client policy: %v", err)
	}
	peerPolicy := reverseProtoTCPPolicy(clientPolicy)
	peerTransport, err := NewTransport(peerPolicy)
	if err != nil {
		t.Fatalf("peer transport: %v", err)
	}
	peerStack, err := NewProtectedTCPStack(peerCarrier, peerTransport, peerPolicy, ProtectedTunnelMTU)
	if err != nil {
		t.Fatalf("peer stack: %v", err)
	}
	t.Cleanup(func() { _ = peerStack.Close() })
	peerListener := listenProductionWireClientFlow(t, peerStack, peerPolicy)
	t.Cleanup(func() { _ = peerListener.Close() })

	const before = "before"
	const after = "after"
	const reply = "reply"
	peerDone := make(chan error, 1)
	go func() {
		conn, acceptErr := peerListener.Accept()
		if acceptErr != nil {
			peerDone <- acceptErr
			return
		}
		defer conn.Close()
		payload := make([]byte, len(before)+len(after))
		_, readErr := io.ReadFull(conn, payload)
		if readErr == nil && string(payload) != before+after {
			readErr = io.ErrUnexpectedEOF
		}
		if readErr == nil {
			_, readErr = conn.Write([]byte(reply))
		}
		peerDone <- readErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := lease.DialTCPClient(ctx); err != nil {
		t.Fatalf("dial TCP client flow: %v", err)
	}
	if _, err := lease.Write([]byte(before)); err != nil {
		t.Fatalf("write before adoption: %v", err)
	}

	handle, err := owner.Adopt(lease)
	if err != nil {
		t.Fatalf("adopt channel: %v", err)
	}
	if _, err := lease.Write([]byte("stale")); err == nil {
		t.Fatal("adopted lease remained usable")
	}
	if _, err := handle.Write([]byte(after)); err != nil {
		t.Fatalf("write after adoption: %v", err)
	}
	if handle.PacketMode() {
		t.Fatal("TCP handle reports packet mode")
	}
	if err := handle.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set handle deadline: %v", err)
	}
	gotReply := make([]byte, len(reply))
	if _, err := io.ReadFull(handle, gotReply); err != nil {
		t.Fatalf("read after adoption: %v", err)
	}
	if string(gotReply) != reply {
		t.Fatalf("reply = %q, want %q", gotReply, reply)
	}
	if err := <-peerDone; err != nil {
		t.Fatalf("peer read across adoption: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("close handle: %v", err)
	}
}

var _ net.Conn = (*ProtectedChannelHandle)(nil)

func readyProtectedChannelUDPLease(t *testing.T, owner *ProtectedChannelOwner) (*ProtectedChannelLease, *protectedChannelCloseCountingConn) {
	t.Helper()
	lease, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve channel: %v", err)
	}
	if err := lease.Install(syntheticProtectedChannelPolicyInput()); err != nil {
		t.Fatalf("install channel: %v", err)
	}
	carrier := &protectedChannelCloseCountingConn{}
	if err := lease.OpenUDP(carrier); err != nil {
		t.Fatalf("open UDP channel: %v", err)
	}
	return lease, carrier
}

func syntheticProtectedChannelPolicyInput() PolicyInput {
	return PolicyInput{
		LocalIP:  net.ParseIP("2001:db8::10"),
		RemoteIP: net.ParseIP("2001:db8::20"),
		Mech: SecurityMechanism{
			Alg:   "hmac-sha-1-96",
			EAlg:  "aes-cbc",
			SPIc:  101,
			SPIs:  102,
			PortC: 5060,
			PortS: 5060,
		},
		CK: make([]byte, 16),
		IK: make([]byte, 16),
	}
}

type protectedChannelCloseCountingConn struct {
	closeCount atomic.Int32
}

func (*protectedChannelCloseCountingConn) Read([]byte) (int, error)    { return 0, net.ErrClosed }
func (*protectedChannelCloseCountingConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *protectedChannelCloseCountingConn) Close() error              { c.closeCount.Add(1); return nil }
func (*protectedChannelCloseCountingConn) LocalAddr() net.Addr {
	return protectedChannelTestAddr("local")
}
func (*protectedChannelCloseCountingConn) RemoteAddr() net.Addr {
	return protectedChannelTestAddr("remote")
}
func (*protectedChannelCloseCountingConn) SetDeadline(time.Time) error      { return nil }
func (*protectedChannelCloseCountingConn) SetReadDeadline(time.Time) error  { return nil }
func (*protectedChannelCloseCountingConn) SetWriteDeadline(time.Time) error { return nil }

type protectedChannelTestAddr string

func (a protectedChannelTestAddr) Network() string { return "test" }
func (a protectedChannelTestAddr) String() string  { return string(a) }

var _ net.Conn = (*protectedChannelCloseCountingConn)(nil)

type protectedChannelBlockingConn struct {
	writeEntered chan struct{}
	closed       chan struct{}
	releaseWrite chan struct{}
	writeOnce    sync.Once
	closeOnce    sync.Once
	writeCount   atomic.Int32
}

func newProtectedChannelBlockingConn() *protectedChannelBlockingConn {
	return &protectedChannelBlockingConn{
		writeEntered: make(chan struct{}),
		closed:       make(chan struct{}),
		releaseWrite: make(chan struct{}),
	}
}

func (*protectedChannelBlockingConn) Read([]byte) (int, error) { return 0, net.ErrClosed }

func (c *protectedChannelBlockingConn) Write([]byte) (int, error) {
	c.writeCount.Add(1)
	c.writeOnce.Do(func() { close(c.writeEntered) })
	<-c.closed
	<-c.releaseWrite
	return 0, net.ErrClosed
}

func (c *protectedChannelBlockingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*protectedChannelBlockingConn) LocalAddr() net.Addr              { return protectedChannelTestAddr("local") }
func (*protectedChannelBlockingConn) RemoteAddr() net.Addr             { return protectedChannelTestAddr("remote") }
func (*protectedChannelBlockingConn) SetDeadline(time.Time) error      { return nil }
func (*protectedChannelBlockingConn) SetReadDeadline(time.Time) error  { return nil }
func (*protectedChannelBlockingConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*protectedChannelBlockingConn)(nil)
