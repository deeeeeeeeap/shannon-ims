package imscore

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
)

type runtimeCarrier struct {
	mu           sync.Mutex
	closes       int
	reads        int
	writes       [][]byte
	inbound      chan []byte
	closedCh     chan struct{}
	once         sync.Once
	readDeadline time.Time
}

func newRuntimeCarrier() *runtimeCarrier {
	return &runtimeCarrier{
		inbound:  make(chan []byte, 16),
		closedCh: make(chan struct{}),
	}
}

func (c *runtimeCarrier) Read(p []byte) (int, error) {
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		if !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-c.closedCh:
		return 0, net.ErrClosed
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	case packet, ok := <-c.inbound:
		if !ok {
			return 0, net.ErrClosed
		}
		c.mu.Lock()
		c.reads++
		c.mu.Unlock()
		return copy(p, packet), nil
	}
}

func (c *runtimeCarrier) Write(p []byte) (int, error) {
	select {
	case <-c.closedCh:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}

func (c *runtimeCarrier) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closes++
		c.mu.Unlock()
		close(c.closedCh)
	})
	return nil
}

func (*runtimeCarrier) LocalAddr() net.Addr  { return &net.IPAddr{} }
func (*runtimeCarrier) RemoteAddr() net.Addr { return &net.IPAddr{} }
func (c *runtimeCarrier) SetDeadline(deadline time.Time) error {
	return c.SetReadDeadline(deadline)
}
func (c *runtimeCarrier) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return nil
}
func (*runtimeCarrier) SetWriteDeadline(time.Time) error { return nil }
func (c *runtimeCarrier) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}
func (c *runtimeCarrier) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

type countingCarrierDialer struct {
	dials       atomic.Int64
	failWith    error
	mu          sync.Mutex
	conns       []*runtimeCarrier
	hostListens int
}

func (d *countingCarrierDialer) DialContextIP(_ context.Context, _ net.IP, _ net.IP, protocol uint8) (net.Conn, error) {
	d.dials.Add(1)
	if d.failWith != nil {
		return nil, d.failWith
	}
	if protocol != 50 {
		return nil, errors.New("unexpected protocol")
	}
	conn := newRuntimeCarrier()
	d.mu.Lock()
	d.conns = append(d.conns, conn)
	d.mu.Unlock()
	return conn, nil
}

func (*countingCarrierDialer) DialContextTCP(context.Context, net.IP, int, net.IP, int) (net.Conn, error) {
	return nil, errors.New("protected TCP must use the raw IP dialer")
}
func (*countingCarrierDialer) DialContextUDP(context.Context, net.IP, int, net.IP, int) (net.Conn, error) {
	return nil, errors.New("protected TCP must use the raw IP dialer")
}
func (d *countingCarrierDialer) ListenContextTCP(context.Context, net.IP, int) (net.Listener, error) {
	d.mu.Lock()
	d.hostListens++
	d.mu.Unlock()
	return nil, errors.New("protected TCP must not open a host listener")
}
func (d *countingCarrierDialer) ListenContextUDP(context.Context, net.IP, int) (net.PacketConn, error) {
	d.mu.Lock()
	d.hostListens++
	d.mu.Unlock()
	return nil, errors.New("protected TCP must not open a host listener")
}
func (*countingCarrierDialer) Close() error { return nil }
func (d *countingCarrierDialer) hostListenCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hostListens
}
func (d *countingCarrierDialer) carriers() []*runtimeCarrier {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*runtimeCarrier(nil), d.conns...)
}

type protectedChannelPacketConn struct {
	peer *protectedChannelPacketConn
	rx   chan []byte
	done chan struct{}

	closeOnce  sync.Once
	closeCount atomic.Int32
}

func newProtectedChannelPacketPair() (*protectedChannelPacketConn, *protectedChannelPacketConn) {
	a := &protectedChannelPacketConn{rx: make(chan []byte, 64), done: make(chan struct{})}
	b := &protectedChannelPacketConn{rx: make(chan []byte, 64), done: make(chan struct{})}
	a.peer = b
	b.peer = a
	return a, b
}

func (c *protectedChannelPacketConn) Read(payload []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	case packet := <-c.rx:
		if len(packet) > len(payload) {
			return 0, io.ErrShortBuffer
		}
		return copy(payload, packet), nil
	}
}

func (c *protectedChannelPacketConn) Write(payload []byte) (int, error) {
	if c == nil || c.peer == nil {
		return 0, net.ErrClosed
	}
	packet := append([]byte(nil), payload...)
	select {
	case <-c.done:
		return 0, net.ErrClosed
	case <-c.peer.done:
		return 0, net.ErrClosed
	case c.peer.rx <- packet:
		return len(payload), nil
	}
}

func (c *protectedChannelPacketConn) Close() error {
	if c != nil {
		c.closeOnce.Do(func() {
			c.closeCount.Add(1)
			close(c.done)
		})
	}
	return nil
}

func (*protectedChannelPacketConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (*protectedChannelPacketConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (*protectedChannelPacketConn) SetDeadline(time.Time) error      { return nil }
func (*protectedChannelPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*protectedChannelPacketConn) SetWriteDeadline(time.Time) error { return nil }

type protectedChannelTCPFixture struct {
	owner         *ipsec3gpp.ProtectedChannelOwner
	lease         *ipsec3gpp.ProtectedChannelLease
	peer          net.Conn
	clientCarrier *protectedChannelPacketConn
	clientPort    int
	serverPort    int
}

func newProtectedChannelTCPFixture(t *testing.T) protectedChannelTCPFixture {
	t.Helper()
	owner := ipsec3gpp.NewProtectedChannelOwner()
	lease, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve protected channel: %v", err)
	}
	input := ipsec3gpp.PolicyInput{
		LocalIP:  net.ParseIP("2001:db8::10"),
		RemoteIP: net.ParseIP("2001:db8::20"),
		Mech: ipsec3gpp.SecurityMechanism{
			Alg:   "hmac-sha-1-96",
			EAlg:  "aes-cbc",
			SPIc:  501,
			SPIs:  502,
			PortC: 6501,
			PortS: 6502,
		},
		CK: make([]byte, 16),
		IK: make([]byte, 16),
	}
	if err := lease.Install(input); err != nil {
		t.Fatalf("install protected channel: %v", err)
	}
	input.UEPortC = lease.ClientPort()
	input.UEPortS = lease.ServerPort()
	input.UESPIc = lease.ClientSPI()
	input.UESPIs = lease.ServerSPI()
	clientPolicy, err := ipsec3gpp.NewPolicy(input)
	if err != nil {
		t.Fatalf("build peer-visible client policy: %v", err)
	}

	clientCarrier, peerCarrier := newProtectedChannelPacketPair()
	if err := lease.OpenTCP(clientCarrier, ipsec3gpp.ProtectedTunnelMTU); err != nil {
		t.Fatalf("open protected TCP channel: %v", err)
	}
	peerPolicy := protectedChannelPeerPolicy(clientPolicy)
	peerTransform, err := ipsec3gpp.NewTransport(peerPolicy)
	if err != nil {
		t.Fatalf("build peer transform: %v", err)
	}
	peerStack, err := ipsec3gpp.NewProtectedTCPStack(
		peerCarrier, peerTransform, peerPolicy, ipsec3gpp.ProtectedTunnelMTU)
	if err != nil {
		t.Fatalf("build peer stack: %v", err)
	}
	peerListener, err := peerStack.ListenServerFlow()
	if err != nil {
		t.Fatalf("listen for protected client flow: %v", err)
	}
	acceptResult := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, acceptErr := peerListener.Accept()
		acceptResult <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: acceptErr}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := lease.DialTCPClient(ctx); err != nil {
		t.Fatalf("dial protected client flow: %v", err)
	}
	accepted := <-acceptResult
	if accepted.err != nil {
		t.Fatalf("accept protected client flow: %v", accepted.err)
	}

	t.Cleanup(func() {
		_ = accepted.conn.Close()
		_ = peerListener.Close()
		_ = peerStack.Close()
		_ = owner.Close()
	})
	return protectedChannelTCPFixture{
		owner:         owner,
		lease:         lease,
		peer:          accepted.conn,
		clientCarrier: clientCarrier,
		clientPort:    lease.ClientPort(),
		serverPort:    lease.ServerPort(),
	}
}

func protectedChannelPeerPolicy(client ipsec3gpp.Policy) ipsec3gpp.Policy {
	reverseFlow := func(flow ipsec3gpp.Flow) ipsec3gpp.Flow {
		flow.OutboundSPI, flow.InboundSPI = flow.InboundSPI, flow.OutboundSPI
		flow.LocalPort, flow.RemotePort = flow.RemotePort, flow.LocalPort
		return flow
	}
	peerFlowC := reverseFlow(client.FlowS)
	peerFlowS := reverseFlow(client.FlowC)
	return ipsec3gpp.Policy{
		LocalIP:     append([]byte(nil), client.RemoteIP...),
		RemoteIP:    append([]byte(nil), client.LocalIP...),
		LocalPortC:  peerFlowC.LocalPort,
		LocalPortS:  peerFlowS.LocalPort,
		RemotePortC: peerFlowC.RemotePort,
		RemotePortS: peerFlowS.RemotePort,
		FlowC:       peerFlowC,
		FlowS:       peerFlowS,
	}
}

func protectedChannelPolicyForTest(t *testing.T, cfg Config, state *registerState) ipsec3gpp.Policy {
	t.Helper()
	policy, err := protectedChannelPolicyFromStateForTest(cfg, state)
	if err != nil {
		t.Fatalf("rebuild protected channel policy: %v", err)
	}
	return policy
}

func protectedChannelPolicyFromStateForTest(cfg Config, state *registerState) (ipsec3gpp.Policy, error) {
	if state == nil || state.channel == nil || state.selectedOffer == nil {
		return ipsec3gpp.Policy{}, errors.New("protected channel policy inputs are incomplete")
	}
	selected := state.selectedOffer
	policy, err := ipsec3gpp.NewPolicy(ipsec3gpp.PolicyInput{
		LocalIP:  cfg.LocalIP,
		RemoteIP: state.channel.RemoteIP(),
		Mech: ipsec3gpp.SecurityMechanism{
			Alg:   selected.Alg,
			EAlg:  selected.EAlg,
			Prot:  selected.Prot,
			Mode:  selected.Mode,
			SPIc:  selected.SPIC,
			SPIs:  selected.SPIS,
			PortC: selected.PortC,
			PortS: selected.PortS,
		},
		CK:      state.ck,
		IK:      state.ik,
		UEPortC: state.channel.ClientPort(),
		UEPortS: state.channel.ServerPort(),
		UESPIc:  state.channel.ClientSPI(),
		UESPIs:  state.channel.ServerSPI(),
	})
	return policy, err
}
