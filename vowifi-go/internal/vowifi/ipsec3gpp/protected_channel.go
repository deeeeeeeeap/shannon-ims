package ipsec3gpp

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"sync"
	"time"
)

const (
	protectedChannelServerPort = 5063
	protectedChannelClientBase = 5064
	protectedChannelClientSpan = 256
)

var (
	errProtectedChannelOwnerStopped   = errors.New("ipsec3gpp: protected channel owner is stopped")
	errProtectedChannelLeaseUsed      = errors.New("ipsec3gpp: protected channel lease is no longer pending")
	errProtectedChannelNotReady       = errors.New("ipsec3gpp: protected channel is not ready")
	errProtectedChannelStale          = errors.New("ipsec3gpp: protected channel handle is stale")
	errProtectedChannelPortsExhausted = errors.New("ipsec3gpp: protected channel client ports are exhausted")
)

// IsProtectedChannelPortsExhausted lets the IMS retry policy preserve its
// existing fail-closed classification without exposing allocator internals.
func IsProtectedChannelPortsExhausted(err error) bool {
	return errors.Is(err, errProtectedChannelPortsExhausted)
}

type protectedChannelLeaseState uint8

const (
	protectedChannelLeasePending protectedChannelLeaseState = iota
	protectedChannelLeaseAdopted
	protectedChannelLeaseClosed
)

// ProtectedChannelOwner is the sole lifecycle owner for all protected SA
// generations belonging to one IMS service.
type ProtectedChannelOwner struct {
	mu                sync.Mutex
	stopped           bool
	generation        uint64
	portOffset        int
	activePorts       map[int]uint64
	activeGenerations map[uint64]int
	current           *protectedChannel
	pending           map[uint64]*ProtectedChannelLease
}

// ProtectedChannelLease owns one provisional SA generation until it is either
// adopted by its owner or closed by the registration attempt.
type ProtectedChannelLease struct {
	owner *ProtectedChannelOwner

	mu      sync.Mutex
	state   protectedChannelLeaseState
	channel *protectedChannel
}

// ProtectedChannelHandle is a generation-bound reference to the owner's
// current channel. It carries no policy, transform, flow, or cleanup pointers.
type ProtectedChannelHandle struct {
	owner      *ProtectedChannelOwner
	generation uint64
}

type protectedChannel struct {
	generation uint64
	clientPort int
	serverPort int
	spiC       uint32
	spiS       uint32
	owner      *ProtectedChannelOwner

	mu          sync.Mutex
	policy      Policy
	transport   *Transport
	udp         *SecureChannelConn
	tcpStack    *ProtectedTCPStack
	tcpListener net.Listener
	tcpClient   net.Conn
	tcpDialing  bool
	tcpServers  map[*protectedChannelServerConn]struct{}
	closeOnce   sync.Once
	releaseOnce sync.Once

	operationMu sync.Mutex
	closing     bool
	operations  sync.WaitGroup
}

type protectedChannelServerConn struct {
	handle  *ProtectedChannelHandle
	channel *protectedChannel
	conn    net.Conn

	closeOnce sync.Once
}

// NewProtectedChannelOwner creates an empty, running owner.
func NewProtectedChannelOwner() *ProtectedChannelOwner {
	offset := 0
	if n, err := rand.Int(rand.Reader, big.NewInt(protectedChannelClientSpan)); err == nil {
		offset = int(n.Int64())
	}
	return &ProtectedChannelOwner{
		portOffset:        offset,
		activePorts:       make(map[int]uint64),
		activeGenerations: make(map[uint64]int),
		pending:           make(map[uint64]*ProtectedChannelLease),
	}
}

// Reserve creates one provisional generation. The lease is the only owner until
// Adopt succeeds.
func (o *ProtectedChannelOwner) Reserve() (*ProtectedChannelLease, error) {
	if o == nil {
		return nil, errProtectedChannelOwnerStopped
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopped {
		return nil, errProtectedChannelOwnerStopped
	}
	clientPort, ok := o.reserveClientPortLocked()
	if !ok {
		return nil, errProtectedChannelPortsExhausted
	}
	o.generation++
	spiC, spiS := randomProtectedChannelSPIPair()
	channel := &protectedChannel{
		generation: o.generation,
		clientPort: clientPort,
		serverPort: protectedChannelServerPort,
		spiC:       spiC,
		spiS:       spiS,
		owner:      o,
	}
	o.activePorts[clientPort] = channel.generation
	o.activeGenerations[channel.generation] = clientPort
	lease := &ProtectedChannelLease{
		owner:   o,
		state:   protectedChannelLeasePending,
		channel: channel,
	}
	o.pending[channel.generation] = lease
	return lease, nil
}

// Generation identifies this reserved SA generation.
func (l *ProtectedChannelLease) Generation() uint64 {
	if l == nil || l.channel == nil {
		return 0
	}
	return l.channel.generation
}

// ClientPort is the generation-specific protected UE client port.
func (l *ProtectedChannelLease) ClientPort() int {
	if l == nil || l.channel == nil {
		return 0
	}
	return l.channel.clientPort
}

// ServerPort is the stable protected UE server port.
func (l *ProtectedChannelLease) ServerPort() int {
	if l == nil || l.channel == nil {
		return 0
	}
	return l.channel.serverPort
}

// ClientSPI and ServerSPI are the Security-Client SPIs owned by this lease.
func (l *ProtectedChannelLease) ClientSPI() uint32 {
	if l == nil || l.channel == nil {
		return 0
	}
	return l.channel.spiC
}

func (l *ProtectedChannelLease) ServerSPI() uint32 {
	if l == nil || l.channel == nil {
		return 0
	}
	return l.channel.spiS
}

// RemoteIP and protected peer ports expose immutable addressing metadata needed
// to build the SIP request around this opaque channel.
func (l *ProtectedChannelLease) RemoteIP() net.IP {
	if l == nil || l.channel == nil {
		return nil
	}
	l.channel.mu.Lock()
	defer l.channel.mu.Unlock()
	return append(net.IP(nil), l.channel.policy.RemoteIP...)
}

func (l *ProtectedChannelLease) RemoteClientPort() int {
	if l == nil || l.channel == nil {
		return 0
	}
	l.channel.mu.Lock()
	defer l.channel.mu.Unlock()
	return l.channel.policy.FlowC.RemotePort
}

func (l *ProtectedChannelLease) RemoteServerPort() int {
	if l == nil || l.channel == nil {
		return 0
	}
	l.channel.mu.Lock()
	defer l.channel.mu.Unlock()
	return l.channel.policy.FlowS.RemotePort
}

func (l *ProtectedChannelLease) Stats() TransportStats {
	channel, err := l.acquirePending()
	if err != nil {
		return TransportStats{}
	}
	defer channel.endOperation()
	channel.mu.Lock()
	transport := channel.transport
	channel.mu.Unlock()
	if transport == nil {
		return TransportStats{}
	}
	return transport.Stats()
}

func (l *ProtectedChannelLease) Snapshot() ProtectedLinkSnapshot {
	channel, err := l.acquirePending()
	if err != nil {
		return ProtectedLinkSnapshot{}
	}
	defer channel.endOperation()
	channel.mu.Lock()
	stack := channel.tcpStack
	channel.mu.Unlock()
	if stack == nil {
		return ProtectedLinkSnapshot{}
	}
	return stack.Snapshot()
}

func (l *ProtectedChannelLease) SafeMSS() int {
	channel, err := l.acquirePending()
	if err != nil {
		return 0
	}
	defer channel.endOperation()
	channel.mu.Lock()
	stack := channel.tcpStack
	channel.mu.Unlock()
	if stack == nil {
		return 0
	}
	return stack.SafeMSS()
}

func (l *ProtectedChannelLease) ClientFlowRetransmissions() int {
	channel, err := l.acquirePending()
	if err != nil {
		return 0
	}
	defer channel.endOperation()
	channel.mu.Lock()
	stack := channel.tcpStack
	channel.mu.Unlock()
	if stack == nil {
		return 0
	}
	return stack.ClientFlowRetransmissions()
}

// Install creates the policy, transforms, SAs, and replay windows inside the
// provisional channel. The lease's ports and SPIs are authoritative.
func (l *ProtectedChannelLease) Install(in PolicyInput) error {
	if l == nil {
		return errProtectedChannelLeaseUsed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != protectedChannelLeasePending || l.channel == nil {
		return errProtectedChannelLeaseUsed
	}
	l.channel.mu.Lock()
	alreadyInstalled := l.channel.transport != nil
	l.channel.mu.Unlock()
	if alreadyInstalled {
		return errProtectedChannelLeaseUsed
	}
	in.UEPortC = l.channel.clientPort
	in.UEPortS = l.channel.serverPort
	in.UESPIc = l.channel.spiC
	in.UESPIs = l.channel.spiS
	policy, err := NewPolicy(in)
	if err != nil {
		return err
	}
	transport, err := NewTransport(policy)
	if err != nil {
		return err
	}
	l.channel.mu.Lock()
	l.channel.policy = policy
	l.channel.transport = transport
	l.channel.mu.Unlock()
	return nil
}

// OpenUDP transfers one packet carrier into the provisional channel.
func (l *ProtectedChannelLease) OpenUDP(carrier net.Conn) error {
	if l == nil || carrier == nil {
		return errProtectedChannelNotReady
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != protectedChannelLeasePending || l.channel == nil {
		return errProtectedChannelLeaseUsed
	}
	l.channel.mu.Lock()
	defer l.channel.mu.Unlock()
	if l.channel.transport == nil {
		return errProtectedChannelNotReady
	}
	if l.channel.udp != nil || l.channel.tcpStack != nil {
		return errProtectedChannelLeaseUsed
	}
	l.channel.udp = WrapSecureChannelUDP(carrier, l.channel.transport, l.channel.policy)
	return nil
}

// OpenTCP transfers one packet carrier into a private TCP stack and makes the
// terminating server flow ready before returning. The stack, listener, and
// carrier remain owned by this provisional generation until adoption or Close.
func (l *ProtectedChannelLease) OpenTCP(carrier net.Conn, innerMTU int) error {
	if l == nil || carrier == nil {
		return errProtectedChannelNotReady
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != protectedChannelLeasePending || l.channel == nil {
		return errProtectedChannelLeaseUsed
	}

	channel := l.channel
	channel.mu.Lock()
	if channel.transport == nil {
		channel.mu.Unlock()
		return errProtectedChannelNotReady
	}
	if channel.udp != nil || channel.tcpStack != nil {
		channel.mu.Unlock()
		return errProtectedChannelLeaseUsed
	}
	transport := channel.transport
	policy := channel.policy
	channel.mu.Unlock()

	stack, err := NewProtectedTCPStack(carrier, transport, policy, innerMTU)
	if err != nil {
		_ = carrier.Close()
		return err
	}
	listener, err := stack.ListenServerFlow()
	if err != nil {
		_ = stack.Close()
		return err
	}

	channel.mu.Lock()
	channel.tcpStack = stack
	channel.tcpListener = listener
	channel.mu.Unlock()
	return nil
}

// ServerFlowReady reports whether this still-pending generation owns a live
// protected TCP stack with its terminating listener installed.
func (l *ProtectedChannelLease) ServerFlowReady() bool {
	channel, err := l.acquirePending()
	if err != nil {
		return false
	}
	defer channel.endOperation()
	channel.mu.Lock()
	defer channel.mu.Unlock()
	return channel.tcpStack != nil && channel.tcpListener != nil
}

// DialTCPClient opens and retains the UE-originating protected TCP flow inside
// this generation. Callers use the lease itself as the connection while the
// REGISTER attempt is pending; no raw flow pointer is transferred on success.
func (l *ProtectedChannelLease) DialTCPClient(ctx context.Context) error {
	if ctx == nil {
		return errProtectedChannelNotReady
	}
	channel, err := l.acquirePending()
	if err != nil {
		return err
	}
	defer channel.endOperation()

	channel.mu.Lock()
	stack := channel.tcpStack
	if stack == nil || channel.tcpListener == nil {
		channel.mu.Unlock()
		return errProtectedChannelNotReady
	}
	if channel.tcpClient != nil || channel.tcpDialing {
		channel.mu.Unlock()
		return errProtectedChannelLeaseUsed
	}
	channel.tcpDialing = true
	channel.mu.Unlock()

	conn, dialErr := stack.DialClientFlow(ctx)
	channel.mu.Lock()
	channel.tcpDialing = false
	channel.mu.Unlock()
	if dialErr != nil {
		return dialErr
	}

	l.mu.Lock()
	if l.state != protectedChannelLeasePending || l.channel != channel {
		l.mu.Unlock()
		_ = conn.Close()
		return errProtectedChannelLeaseUsed
	}
	channel.mu.Lock()
	if channel.tcpStack != stack || channel.tcpClient != nil {
		channel.mu.Unlock()
		l.mu.Unlock()
		_ = conn.Close()
		return errProtectedChannelLeaseUsed
	}
	channel.tcpClient = conn
	channel.mu.Unlock()
	l.mu.Unlock()
	return nil
}

func (l *ProtectedChannelLease) Read(payload []byte) (int, error) {
	channel, err := l.acquirePending()
	if err != nil {
		return 0, err
	}
	defer channel.endOperation()
	conn := channel.clientConn()
	if conn == nil {
		return 0, errProtectedChannelNotReady
	}
	return conn.Read(payload)
}

func (l *ProtectedChannelLease) Write(payload []byte) (int, error) {
	channel, err := l.acquirePending()
	if err != nil {
		return 0, err
	}
	defer channel.endOperation()
	conn := channel.clientConn()
	if conn == nil {
		return 0, errProtectedChannelNotReady
	}
	return conn.Write(payload)
}

func (l *ProtectedChannelLease) WriteServerFlow(payload []byte) (int, error) {
	channel, err := l.acquirePending()
	if err != nil {
		return 0, err
	}
	defer channel.endOperation()
	udp := channel.udpConn()
	if udp == nil {
		return 0, errProtectedChannelNotReady
	}
	return udp.WriteServerFlow(payload)
}

func (l *ProtectedChannelLease) LocalAddr() net.Addr {
	channel, err := l.acquirePending()
	if err != nil {
		return nil
	}
	defer channel.endOperation()
	if conn := channel.clientConn(); conn != nil {
		return conn.LocalAddr()
	}
	return nil
}

func (l *ProtectedChannelLease) RemoteAddr() net.Addr {
	channel, err := l.acquirePending()
	if err != nil {
		return nil
	}
	defer channel.endOperation()
	if conn := channel.clientConn(); conn != nil {
		return conn.RemoteAddr()
	}
	return nil
}

func (l *ProtectedChannelLease) SetDeadline(deadline time.Time) error {
	return l.withPendingClient(func(conn net.Conn) error { return conn.SetDeadline(deadline) })
}

func (l *ProtectedChannelLease) SetReadDeadline(deadline time.Time) error {
	return l.withPendingClient(func(conn net.Conn) error { return conn.SetReadDeadline(deadline) })
}

func (l *ProtectedChannelLease) SetWriteDeadline(deadline time.Time) error {
	return l.withPendingClient(func(conn net.Conn) error { return conn.SetWriteDeadline(deadline) })
}

func (l *ProtectedChannelLease) PacketMode() bool {
	channel, err := l.acquirePending()
	if err != nil {
		return false
	}
	defer channel.endOperation()
	if udp := channel.udpConn(); udp != nil {
		return udp.PacketMode()
	}
	return false
}

func (l *ProtectedChannelLease) acquirePending() (*protectedChannel, error) {
	if l == nil {
		return nil, errProtectedChannelLeaseUsed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != protectedChannelLeasePending || l.channel == nil {
		return nil, errProtectedChannelLeaseUsed
	}
	if !l.channel.beginOperation() {
		return nil, errProtectedChannelLeaseUsed
	}
	return l.channel, nil
}

func (l *ProtectedChannelLease) withPendingClient(apply func(net.Conn) error) error {
	channel, err := l.acquirePending()
	if err != nil {
		return err
	}
	defer channel.endOperation()
	conn := channel.clientConn()
	if conn == nil {
		return errProtectedChannelNotReady
	}
	return apply(conn)
}

// Adopt atomically consumes a ready lease and makes its generation current.
func (o *ProtectedChannelOwner) Adopt(lease *ProtectedChannelLease) (*ProtectedChannelHandle, error) {
	if o == nil || lease == nil || lease.owner != o {
		return nil, errProtectedChannelLeaseUsed
	}
	o.mu.Lock()
	lease.mu.Lock()
	if o.stopped {
		lease.mu.Unlock()
		o.mu.Unlock()
		return nil, errProtectedChannelOwnerStopped
	}
	if lease.state != protectedChannelLeasePending || lease.channel == nil {
		lease.mu.Unlock()
		o.mu.Unlock()
		return nil, errProtectedChannelLeaseUsed
	}
	channel := lease.channel
	if !channel.ready() {
		lease.mu.Unlock()
		o.mu.Unlock()
		return nil, errProtectedChannelNotReady
	}
	if o.current != nil && channel.generation <= o.current.generation {
		delete(o.pending, channel.generation)
		lease.state = protectedChannelLeaseClosed
		lease.mu.Unlock()
		o.mu.Unlock()
		channel.close()
		return nil, errProtectedChannelStale
	}
	previous := o.current
	o.current = channel
	delete(o.pending, channel.generation)
	lease.state = protectedChannelLeaseAdopted
	lease.mu.Unlock()
	o.mu.Unlock()

	if previous != nil && previous != channel {
		previous.close()
	}
	return &ProtectedChannelHandle{owner: o, generation: channel.generation}, nil
}

// Close releases an unadopted lease. Once adopted, only the owner/handle may
// retire the channel, so a stale deferred cleanup becomes a no-op.
func (l *ProtectedChannelLease) Close() error {
	if l == nil || l.owner == nil {
		return nil
	}
	o := l.owner
	o.mu.Lock()
	l.mu.Lock()
	if l.state != protectedChannelLeasePending {
		l.mu.Unlock()
		o.mu.Unlock()
		return nil
	}
	l.state = protectedChannelLeaseClosed
	channel := l.channel
	if channel != nil {
		delete(o.pending, channel.generation)
	}
	l.mu.Unlock()
	o.mu.Unlock()
	if channel != nil {
		channel.close()
	}
	return nil
}

// Close retires the referenced generation only if it is still current.
func (h *ProtectedChannelHandle) Close() error {
	if h == nil || h.owner == nil {
		return nil
	}
	h.owner.retire(h.generation)
	return nil
}

// Read and Write perform generation-scoped operations. Stop first prevents new
// operations, then closes the owned flow to unblock the current one, and finally
// waits for this operation lease to leave.
func (h *ProtectedChannelHandle) Read(payload []byte) (int, error) {
	channel, err := h.acquireCurrent()
	if err != nil {
		return 0, err
	}
	defer channel.endOperation()
	conn := channel.clientConn()
	if conn == nil {
		return 0, errProtectedChannelNotReady
	}
	return conn.Read(payload)
}

func (h *ProtectedChannelHandle) Write(payload []byte) (int, error) {
	channel, err := h.acquireCurrent()
	if err != nil {
		return 0, err
	}
	defer channel.endOperation()
	conn := channel.clientConn()
	if conn == nil {
		return 0, errProtectedChannelNotReady
	}
	return conn.Write(payload)
}

func (h *ProtectedChannelHandle) WriteServerFlow(payload []byte) (int, error) {
	channel, err := h.acquireCurrent()
	if err != nil {
		return 0, err
	}
	defer channel.endOperation()
	udp := channel.udpConn()
	if udp == nil {
		return 0, errProtectedChannelNotReady
	}
	return udp.WriteServerFlow(payload)
}

func (h *ProtectedChannelHandle) LocalAddr() net.Addr {
	channel, err := h.acquireCurrent()
	if err != nil {
		return nil
	}
	defer channel.endOperation()
	if conn := channel.clientConn(); conn != nil {
		return conn.LocalAddr()
	}
	return nil
}

func (h *ProtectedChannelHandle) RemoteAddr() net.Addr {
	channel, err := h.acquireCurrent()
	if err != nil {
		return nil
	}
	defer channel.endOperation()
	if conn := channel.clientConn(); conn != nil {
		return conn.RemoteAddr()
	}
	return nil
}

func (h *ProtectedChannelHandle) SetDeadline(deadline time.Time) error {
	return h.withCurrentClient(func(conn net.Conn) error { return conn.SetDeadline(deadline) })
}

func (h *ProtectedChannelHandle) SetReadDeadline(deadline time.Time) error {
	return h.withCurrentClient(func(conn net.Conn) error { return conn.SetReadDeadline(deadline) })
}

func (h *ProtectedChannelHandle) SetWriteDeadline(deadline time.Time) error {
	return h.withCurrentClient(func(conn net.Conn) error { return conn.SetWriteDeadline(deadline) })
}

func (h *ProtectedChannelHandle) PacketMode() bool {
	channel, err := h.acquireCurrent()
	if err != nil {
		return false
	}
	defer channel.endOperation()
	return channel.udpConn() != nil
}

func (h *ProtectedChannelHandle) Generation() uint64 {
	if h == nil {
		return 0
	}
	return h.generation
}

func (h *ProtectedChannelHandle) ClientPort() int {
	channel, err := h.acquireCurrent()
	if err != nil {
		return 0
	}
	defer channel.endOperation()
	return channel.clientPort
}

func (h *ProtectedChannelHandle) ServerPort() int {
	channel, err := h.acquireCurrent()
	if err != nil {
		return 0
	}
	defer channel.endOperation()
	return channel.serverPort
}

func (h *ProtectedChannelHandle) RemoteIP() net.IP {
	channel, err := h.acquireCurrent()
	if err != nil {
		return nil
	}
	defer channel.endOperation()
	channel.mu.Lock()
	defer channel.mu.Unlock()
	return append(net.IP(nil), channel.policy.RemoteIP...)
}

func (h *ProtectedChannelHandle) RemoteClientPort() int {
	channel, err := h.acquireCurrent()
	if err != nil {
		return 0
	}
	defer channel.endOperation()
	channel.mu.Lock()
	defer channel.mu.Unlock()
	return channel.policy.FlowC.RemotePort
}

func (h *ProtectedChannelHandle) Stats() TransportStats {
	channel, err := h.acquireCurrent()
	if err != nil {
		return TransportStats{}
	}
	defer channel.endOperation()
	channel.mu.Lock()
	transport := channel.transport
	channel.mu.Unlock()
	if transport == nil {
		return TransportStats{}
	}
	return transport.Stats()
}

func (h *ProtectedChannelHandle) Snapshot() ProtectedLinkSnapshot {
	channel, err := h.acquireCurrent()
	if err != nil {
		return ProtectedLinkSnapshot{}
	}
	defer channel.endOperation()
	channel.mu.Lock()
	stack := channel.tcpStack
	channel.mu.Unlock()
	if stack == nil {
		return ProtectedLinkSnapshot{}
	}
	return stack.Snapshot()
}

func (h *ProtectedChannelHandle) SafeMSS() int {
	channel, err := h.acquireCurrent()
	if err != nil {
		return 0
	}
	defer channel.endOperation()
	channel.mu.Lock()
	stack := channel.tcpStack
	channel.mu.Unlock()
	if stack == nil {
		return 0
	}
	return stack.SafeMSS()
}

func (h *ProtectedChannelHandle) ClientFlowRetransmissions() int {
	channel, err := h.acquireCurrent()
	if err != nil {
		return 0
	}
	defer channel.endOperation()
	channel.mu.Lock()
	stack := channel.tcpStack
	channel.mu.Unlock()
	if stack == nil {
		return 0
	}
	return stack.ClientFlowRetransmissions()
}

func (h *ProtectedChannelHandle) ServerFlowReady() bool {
	channel, err := h.acquireCurrent()
	if err != nil {
		return false
	}
	defer channel.endOperation()
	channel.mu.Lock()
	defer channel.mu.Unlock()
	return channel.tcpStack != nil && channel.tcpListener != nil
}

func (h *ProtectedChannelHandle) AcceptServerFlow() (net.Conn, error) {
	channel, err := h.acquireCurrent()
	if err != nil {
		return nil, err
	}
	defer channel.endOperation()
	channel.mu.Lock()
	listener := channel.tcpListener
	channel.mu.Unlock()
	if listener == nil {
		return nil, errProtectedChannelNotReady
	}
	conn, err := listener.Accept()
	if err != nil {
		return nil, err
	}
	server := &protectedChannelServerConn{
		handle:  &ProtectedChannelHandle{owner: h.owner, generation: h.generation},
		channel: channel,
		conn:    conn,
	}
	channel.operationMu.Lock()
	if channel.closing {
		channel.operationMu.Unlock()
		_ = conn.Close()
		return nil, errProtectedChannelStale
	}
	channel.mu.Lock()
	if channel.tcpServers == nil {
		channel.tcpServers = make(map[*protectedChannelServerConn]struct{})
	}
	channel.tcpServers[server] = struct{}{}
	channel.mu.Unlock()
	channel.operationMu.Unlock()
	return server, nil
}

func (h *ProtectedChannelHandle) withCurrentClient(apply func(net.Conn) error) error {
	channel, err := h.acquireCurrent()
	if err != nil {
		return err
	}
	defer channel.endOperation()
	conn := channel.clientConn()
	if conn == nil {
		return errProtectedChannelNotReady
	}
	return apply(conn)
}

func (c *protectedChannelServerConn) Read(payload []byte) (int, error) {
	return c.withOperation(func(conn net.Conn) (int, error) { return conn.Read(payload) })
}

func (c *protectedChannelServerConn) Write(payload []byte) (int, error) {
	return c.withOperation(func(conn net.Conn) (int, error) { return conn.Write(payload) })
}

func (c *protectedChannelServerConn) Close() error {
	if c == nil {
		return nil
	}
	var closeErr error
	c.closeOnce.Do(func() {
		if c.conn != nil {
			closeErr = c.conn.Close()
		}
		if c.channel != nil {
			c.channel.mu.Lock()
			delete(c.channel.tcpServers, c)
			c.channel.mu.Unlock()
		}
	})
	return closeErr
}

func (c *protectedChannelServerConn) LocalAddr() net.Addr {
	if c == nil || c.conn == nil || c.handle == nil || !c.handle.ServerFlowReady() {
		return nil
	}
	return c.conn.LocalAddr()
}

func (c *protectedChannelServerConn) RemoteAddr() net.Addr {
	if c == nil || c.conn == nil || c.handle == nil || !c.handle.ServerFlowReady() {
		return nil
	}
	return c.conn.RemoteAddr()
}

func (c *protectedChannelServerConn) SetDeadline(deadline time.Time) error {
	return c.withDeadline(func(conn net.Conn) error { return conn.SetDeadline(deadline) })
}

func (c *protectedChannelServerConn) SetReadDeadline(deadline time.Time) error {
	return c.withDeadline(func(conn net.Conn) error { return conn.SetReadDeadline(deadline) })
}

func (c *protectedChannelServerConn) SetWriteDeadline(deadline time.Time) error {
	return c.withDeadline(func(conn net.Conn) error { return conn.SetWriteDeadline(deadline) })
}

func (c *protectedChannelServerConn) withOperation(apply func(net.Conn) (int, error)) (int, error) {
	if c == nil || c.conn == nil || c.handle == nil {
		return 0, net.ErrClosed
	}
	channel, err := c.handle.acquireCurrent()
	if err != nil {
		return 0, err
	}
	defer channel.endOperation()
	return apply(c.conn)
}

func (c *protectedChannelServerConn) withDeadline(apply func(net.Conn) error) error {
	if c == nil || c.conn == nil || c.handle == nil {
		return net.ErrClosed
	}
	channel, err := c.handle.acquireCurrent()
	if err != nil {
		return err
	}
	defer channel.endOperation()
	return apply(c.conn)
}

func (h *ProtectedChannelHandle) acquireCurrent() (*protectedChannel, error) {
	if h == nil || h.owner == nil {
		return nil, errProtectedChannelStale
	}
	o := h.owner
	o.mu.Lock()
	if o.stopped || o.current == nil || o.current.generation != h.generation {
		o.mu.Unlock()
		return nil, errProtectedChannelStale
	}
	channel := o.current
	if !channel.beginOperation() {
		o.mu.Unlock()
		return nil, errProtectedChannelStale
	}
	o.mu.Unlock()
	return channel, nil
}

func (o *ProtectedChannelOwner) retire(generation uint64) {
	if o == nil {
		return
	}
	o.mu.Lock()
	channel := o.current
	if channel == nil || channel.generation != generation {
		o.mu.Unlock()
		return
	}
	o.current = nil
	o.mu.Unlock()
	channel.close()
}

// Close is terminal: it rejects future reservations/adoptions and tears down
// every current or provisional channel exactly once.
func (o *ProtectedChannelOwner) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	if o.stopped {
		o.mu.Unlock()
		return nil
	}
	o.stopped = true
	channels := make([]*protectedChannel, 0, len(o.pending)+1)
	if o.current != nil {
		channels = append(channels, o.current)
		o.current = nil
	}
	for generation, lease := range o.pending {
		lease.mu.Lock()
		if lease.state == protectedChannelLeasePending {
			lease.state = protectedChannelLeaseClosed
			if lease.channel != nil {
				channels = append(channels, lease.channel)
			}
		}
		lease.mu.Unlock()
		delete(o.pending, generation)
	}
	o.mu.Unlock()
	for _, channel := range channels {
		channel.close()
	}
	return nil
}

func (c *protectedChannel) ready() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.transport != nil && (c.udp != nil || (c.tcpStack != nil && c.tcpListener != nil && c.tcpClient != nil))
}

func (c *protectedChannel) udpConn() *SecureChannelConn {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.udp
}

func (c *protectedChannel) clientConn() net.Conn {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.udp != nil {
		return c.udp
	}
	return c.tcpClient
}

func (c *protectedChannel) close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.operationMu.Lock()
		c.closing = true
		c.operationMu.Unlock()
		c.mu.Lock()
		udp := c.udp
		c.udp = nil
		tcpClient := c.tcpClient
		c.tcpClient = nil
		tcpListener := c.tcpListener
		c.tcpListener = nil
		tcpStack := c.tcpStack
		c.tcpStack = nil
		tcpServers := make([]*protectedChannelServerConn, 0, len(c.tcpServers))
		for server := range c.tcpServers {
			tcpServers = append(tcpServers, server)
		}
		c.tcpServers = nil
		c.mu.Unlock()
		if tcpListener != nil {
			_ = tcpListener.Close()
		}
		if tcpClient != nil {
			_ = tcpClient.Close()
		}
		for _, server := range tcpServers {
			_ = server.Close()
		}
		if udp != nil {
			_ = udp.Close()
		}
		if tcpStack != nil {
			_ = tcpStack.Close()
		}
		c.operations.Wait()
		if c.owner != nil {
			c.releaseOnce.Do(func() { c.owner.releaseGeneration(c.generation) })
		}
	})
}

func (o *ProtectedChannelOwner) reserveClientPortLocked() (int, bool) {
	for i := 0; i < protectedChannelClientSpan; i++ {
		candidate := protectedChannelClientBase + (o.portOffset+i)%protectedChannelClientSpan
		if _, active := o.activePorts[candidate]; active {
			continue
		}
		o.portOffset = (o.portOffset + i + 1) % protectedChannelClientSpan
		return candidate, true
	}
	return 0, false
}

func (o *ProtectedChannelOwner) releaseGeneration(generation uint64) {
	if o == nil || generation == 0 {
		return
	}
	o.mu.Lock()
	port, ok := o.activeGenerations[generation]
	if ok {
		delete(o.activeGenerations, generation)
		if owner, active := o.activePorts[port]; active && owner == generation {
			delete(o.activePorts, port)
		}
	}
	o.mu.Unlock()
}

func (c *protectedChannel) beginOperation() bool {
	if c == nil {
		return false
	}
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if c.closing {
		return false
	}
	c.operations.Add(1)
	return true
}

func (c *protectedChannel) endOperation() {
	if c != nil {
		c.operations.Done()
	}
}

func randomProtectedChannelSPIPair() (uint32, uint32) {
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(0x7ffffffe))
		if err != nil {
			return 0x00ffee01, 0x00ffee02
		}
		base := uint32(n.Int64()) + 1
		if base >= 1 && base <= 0x7ffffffe {
			return base, base + 1
		}
	}
}
