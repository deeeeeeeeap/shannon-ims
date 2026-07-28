package ipsec3gpp

import (
	"bytes"
	"context"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// productionWirePacketConn is a packet-preserving in-memory carrier. Unlike
// net.Pipe, one Write is exactly one Read, matching the SWu raw-IP contract.
type productionWirePacketConn struct {
	mu        sync.Mutex
	peer      *productionWirePacketConn
	rx        chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	writes    [][]byte
}

func newProductionWirePacketPair() (*productionWirePacketConn, *productionWirePacketConn) {
	a := &productionWirePacketConn{rx: make(chan []byte, 64), closed: make(chan struct{})}
	b := &productionWirePacketConn{rx: make(chan []byte, 64), closed: make(chan struct{})}
	a.peer = b
	b.peer = a
	return a, b
}

func (c *productionWirePacketConn) Read(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case packet := <-c.rx:
		if len(packet) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, packet), nil
	}
}

func (c *productionWirePacketConn) Write(p []byte) (int, error) {
	if c == nil || c.peer == nil {
		return 0, net.ErrClosed
	}
	packet := append([]byte(nil), p...)
	c.mu.Lock()
	c.writes = append(c.writes, packet)
	c.mu.Unlock()
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.peer.closed:
		return 0, net.ErrClosed
	case c.peer.rx <- append([]byte(nil), packet...):
		return len(p), nil
	}
}

func (c *productionWirePacketConn) Close() error {
	if c != nil {
		c.closeOnce.Do(func() { close(c.closed) })
	}
	return nil
}

func (*productionWirePacketConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (*productionWirePacketConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (*productionWirePacketConn) SetDeadline(time.Time) error      { return nil }
func (*productionWirePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*productionWirePacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *productionWirePacketConn) captured() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	for i := range c.writes {
		out[i] = append([]byte(nil), c.writes[i]...)
	}
	return out
}

func listenProductionWireClientFlow(t *testing.T, stack *ProtectedTCPStack, policy Policy) net.Listener {
	t.Helper()
	var wq waiter.Queue
	ep, tcpErr := stack.stack.NewEndpoint(tcp.ProtocolNumber, stack.endpoint.NetworkProtocol(), &wq)
	if tcpErr != nil {
		t.Fatalf("peer endpoint: %v", tcpErr)
	}
	if err := ep.SetSockOptInt(tcpip.MaxSegOption, stack.SafeMSS()); err != nil {
		ep.Close()
		t.Fatalf("peer MSS: %v", err)
	}
	addr := tcpip.FullAddress{
		NIC:  protectedTCPStackNICID,
		Addr: tcpip.AddrFromSlice(net.IP(policy.LocalIP)),
		Port: uint16(policy.FlowC.LocalPort),
	}
	if err := ep.Bind(addr); err != nil {
		ep.Close()
		t.Fatalf("peer bind: %v", err)
	}
	if err := ep.Listen(1); err != nil {
		ep.Close()
		t.Fatalf("peer listen: %v", err)
	}
	return gonet.NewTCPListener(stack.stack, &wq, ep)
}

func TestProtectedTCPPathUsesConservativeMSSCap(t *testing.T) {
	endpoint, _, _, policy := plinkEndpoint(t)
	if got := endpoint.SafeMSS(); got != 1024 {
		t.Fatalf("protected TCP MSS = %d, want conservative cap 1024", got)
	}
	maxCleartext := protectedIPv6HeaderLen + protectedMinTCPHeaderLen + endpoint.SafeMSS()
	protectedLen, err := PredictProtectedESPLen(policy.FlowC, maxCleartext)
	if err != nil {
		t.Fatalf("predict protected length: %v", err)
	}
	if protectedLen > 1152 {
		t.Fatalf("protected packet at capped MSS = %d, want <= 1152", protectedLen)
	}
}

// TestProtectedTCPProductionWireMatchesIndependentOracle exercises the actual
// production ProtectedTCPStack and ProtectedLinkEndpoint together. The peer
// receives the complete byte stream, while the captured ESP packets are decoded
// by the independent standard-library oracle from protected_tcp_prototype_test.
func TestProtectedTCPProductionWireMatchesIndependentOracle(t *testing.T) {
	clientPolicy := oraclePolicy(t)
	peerPolicy := reverseProtoTCPPolicy(clientPolicy)
	clientTransport, err := NewTransport(clientPolicy)
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}
	peerTransport, err := NewTransport(peerPolicy)
	if err != nil {
		t.Fatalf("peer transport: %v", err)
	}
	clientCarrier, peerCarrier := newProductionWirePacketPair()
	clientStack, err := NewProtectedTCPStack(clientCarrier, clientTransport, clientPolicy, ProtectedTunnelMTU)
	if err != nil {
		t.Fatalf("client stack: %v", err)
	}
	defer clientStack.Close()
	peerStack, err := NewProtectedTCPStack(peerCarrier, peerTransport, peerPolicy, ProtectedTunnelMTU)
	if err != nil {
		t.Fatalf("peer stack: %v", err)
	}
	defer peerStack.Close()

	listener := listenProductionWireClientFlow(t, peerStack, peerPolicy)
	defer listener.Close()

	const requestLen = 1347
	request := make([]byte, requestLen)
	for i := range request {
		request[i] = byte('A' + i%26)
	}
	peerDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			peerDone <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, requestLen)
		if _, readErr := io.ReadFull(conn, got); readErr != nil {
			peerDone <- readErr
			return
		}
		if !bytes.Equal(got, request) {
			peerDone <- io.ErrUnexpectedEOF
			return
		}
		_, writeErr := conn.Write([]byte{1})
		peerDone <- writeErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientStack.DialClientFlow(ctx)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("client write: %v", err)
	}
	var marker [1]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		t.Fatalf("client read marker: %v", err)
	}
	if err := <-peerDone; err != nil {
		t.Fatalf("peer exchange: %v", err)
	}

	snapshot := clientStack.Snapshot()
	if snapshot.AckedBytes != requestLen {
		t.Fatalf("acknowledged bytes = %d, want %d", snapshot.AckedBytes, requestLen)
	}
	if snapshot.MaxInnerPacketLen > 1152 {
		t.Fatalf("largest protected packet = %d, exceeds conservative path budget 1152", snapshot.MaxInnerPacketLen)
	}

	encKey, authKey := oracleExpectedKeys(clientPolicy.FlowC)
	type piece struct {
		seq  uint32
		data []byte
	}
	var pieces []piece
	for _, packet := range clientCarrier.captured() {
		segment := protoTCPDecodeESP(t, packet, encKey, authKey)
		if !segment.checksumValid {
			t.Fatal("production TCP data segment has an invalid checksum")
		}
		if len(segment.payload) == 0 {
			continue
		}
		if int(segment.srcPort) != clientPolicy.FlowC.LocalPort || int(segment.dstPort) != clientPolicy.FlowC.RemotePort {
			t.Fatal("production TCP data segment used the wrong protected port pair")
		}
		pieces = append(pieces, piece{seq: segment.seq, data: append([]byte(nil), segment.payload...)})
	}
	if len(pieces) < 2 {
		t.Fatalf("data segments = %d, want at least 2", len(pieces))
	}
	sort.Slice(pieces, func(i, j int) bool { return pieces[i].seq < pieces[j].seq })
	var reconstructed []byte
	for _, p := range pieces {
		reconstructed = append(reconstructed, p.data...)
	}
	if !bytes.Equal(reconstructed, request) {
		t.Fatal("independent production-wire reassembly differs from the written stream")
	}
}
