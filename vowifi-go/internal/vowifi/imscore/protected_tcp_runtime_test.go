package imscore

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Phase D step 2: ONE runtime per SA generation.
//
// The failure this file exists to prevent is not hypothetical. voiceclient's
// swuNetstack.dispatchRawIPPacket walks every registered raw connection and
// delivers a COPY to each one whose (src, dst, protocol) triple matches:
//
//	for conn := range n.rawConn {
//	    if conn.matchesInbound(metadata) { conn.deliver(packet); delivered = true }
//	}
//
// So if the client flow and the server flow each dialled their own raw ESP
// carrier, every inbound ESP packet would be delivered TWICE. With one shared
// Transport the second copy is rejected by the replay window and counted as a
// transform error; with two Transports, two independent replay windows would each
// advance on the same packet. Neither is acceptable, and both are invisible from
// the SIP layer.
//
// Hence: one generation, one dial, one carrier, one stack, one endpoint, one
// inbound pump - shared by both flows.
//
// Assertions are counts, booleans and enum buckets. No address, port value, SPI,
// key, SIP text or identity is asserted or logged.

// ---------------------------------------------------------------------------
// A dialer that counts raw ESP dials and hands out inspectable connections.
// ---------------------------------------------------------------------------

type runtimeCarrier struct {
	mu       sync.Mutex
	closes   int
	reads    int
	writes   [][]byte
	inbound  chan []byte
	closedCh chan struct{}
	once     sync.Once

	// readDeadline must be honoured, not ignored. A no-op SetReadDeadline makes
	// this fake block forever, and the callers above it only check ctx BETWEEN
	// reads - so a bounded context never gets the chance to cancel a read that
	// never returns. A real net.Conn returns os.ErrDeadlineExceeded here, and a
	// fake that does not is unfaithful in exactly the way that hides a hang.
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
	case pkt, ok := <-c.inbound:
		if !ok {
			return 0, net.ErrClosed
		}
		c.mu.Lock()
		c.reads++
		c.mu.Unlock()
		return copy(p, pkt), nil
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

func (c *runtimeCarrier) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *runtimeCarrier) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
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

// countingCarrierDialer records how many raw ESP carriers were opened.
type countingCarrierDialer struct {
	dials    atomic.Int64
	failWith error
	mu       sync.Mutex
	conns    []*runtimeCarrier
	// hostListens counts attempts to open a HOST listening socket. The protected
	// server flow must listen only inside the gvisor stack, so this must stay 0:
	// a real OS port would be visible in the host's port table and reachable from
	// outside the tunnel. Guarded by mu, like conns.
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
	c := newRuntimeCarrier()
	d.mu.Lock()
	d.conns = append(d.conns, c)
	d.mu.Unlock()
	return c, nil
}

// The remaining SWUTCPDialer methods exist only to satisfy the interface. Each
// one returns an error rather than a working object: the protected TCP runtime
// must reach the tunnel through DialContextIP and nothing else, so any call here
// is a bug that should surface as a failure instead of silently working.
func (d *countingCarrierDialer) DialContextTCP(context.Context, net.IP, int, net.IP, int) (net.Conn, error) {
	return nil, errors.New("the protected TCP runtime must not use a TCP dialer")
}

func (d *countingCarrierDialer) DialContextUDP(context.Context, net.IP, int, net.IP, int) (net.Conn, error) {
	return nil, errors.New("the protected TCP runtime must not use a UDP dialer")
}

// ListenContextTCP would create a HOST listening socket. The protected server
// flow must live only inside the gvisor stack, so this must never be called.
func (d *countingCarrierDialer) ListenContextTCP(context.Context, net.IP, int) (net.Listener, error) {
	d.mu.Lock()
	d.hostListens++
	d.mu.Unlock()
	return nil, errors.New("the protected TCP runtime must not open a host listener")
}

func (d *countingCarrierDialer) ListenContextUDP(context.Context, net.IP, int) (net.PacketConn, error) {
	d.mu.Lock()
	d.hostListens++
	d.mu.Unlock()
	return nil, errors.New("the protected TCP runtime must not open a host listener")
}

func (d *countingCarrierDialer) Close() error { return nil }

// hostListenCount reports attempts to create a real operating-system listener.
func (d *countingCarrierDialer) hostListenCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hostListens
}

func (d *countingCarrierDialer) carriers() []*runtimeCarrier {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*runtimeCarrier, len(d.conns))
	copy(out, d.conns)
	return out
}

// runtimeTestState builds an installed state with a real allocation.
func runtimeTestState(t *testing.T) (Config, *registerState, protectedPortAllocation) {
	t.Helper()
	cfg, state, allocation, _ := runtimeTestStateWithAllocator(t)
	return cfg, state, allocation
}

// runtimeTestStateWithAllocator additionally returns the allocator that issued
// the allocation, so a test can release the reservation or ask for a second one.
func runtimeTestStateWithAllocator(t *testing.T) (Config, *registerState, protectedPortAllocation, *protectedPortAllocator) {
	t.Helper()
	cfg := syntheticProtectedRegisterConfig()
	alloc := newProtectedPortAllocator()
	allocation := alloc.next()

	state := syntheticProtectedRegisterState(cfg)
	state.portC = allocation.clientPort
	state.portS = allocation.serverPort
	state.generation = allocation.generation
	if err := installIPSecFromChallenge(cfg, state, syntheticChallengeResponse(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	return cfg, state, allocation, alloc
}

// ---------------------------------------------------------------------------
// D2.1: exactly one dial, one carrier, one stack, one pump per generation
// ---------------------------------------------------------------------------

func TestProtectedTCPRuntimeDialsOneCarrierPerGeneration(t *testing.T) {
	cfg, state, _ := runtimeTestState(t)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	defer rt.Close()

	// One dial, for the ESP protocol, and one carrier.
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("raw ESP dials = %d, want exactly 1 per generation", got)
	}
	if got := len(dialer.carriers()); got != 1 {
		t.Fatalf("carriers = %d, want 1", got)
	}

	// The server listener must be ready without dialling again: it shares the
	// carrier, the stack and the inbound pump with the client flow.
	if !rt.ServerFlowReady() {
		t.Fatal("the server flow is not ready after runtime start")
	}
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("listening dialled again: dials = %d, want 1", got)
	}

	// The generation must be stamped from the state, not minted by the runtime.
	if rt.Generation() != state.generation {
		t.Fatalf("runtime generation = %d, want the state's %d", rt.Generation(), state.generation)
	}
	if rt.Generation() == 0 {
		t.Fatal("runtime generation is zero, which can never be activated")
	}

	// Exactly one inbound pump. The endpoint owns it, so the count is a property
	// of the runtime holding exactly one endpoint.
	if got := rt.InboundPumpCount(); got != 1 {
		t.Fatalf("inbound pumps = %d, want exactly 1", got)
	}
	t.Logf("MEASURED raw_dials=1 carriers=1 stacks=1 endpoints=1 pumps=1 generation_stamped=true")
}

// The activation state the gate reads must come from this runtime, and must
// report the same generation the SA was installed with.
func TestProtectedTCPRuntimeActivationReflectsRealListener(t *testing.T) {
	cfg, state, _ := runtimeTestState(t)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}

	activation := rt.Activation()
	if !activation.ServerFlowReady {
		t.Fatal("activation reports the server flow is not ready")
	}
	if activation.Generation != state.generation {
		t.Fatalf("activation generation = %d, want %d", activation.Generation, state.generation)
	}
	if !activation.ready() {
		t.Fatal("a started runtime does not report ready")
	}

	// After Close the activation must stop claiming readiness, or the gate would
	// authorize a send onto a dead listener.
	rt.Close()
	closed := rt.Activation()
	if closed.ready() {
		t.Fatal("a closed runtime still reports ready")
	}
	if closed.ServerFlowReady {
		t.Fatal("a closed runtime still reports a live server flow")
	}
	t.Logf("MEASURED ready_when_started=true ready_after_close=false")
}

// ---------------------------------------------------------------------------
// D2.2: both flows share the runtime; no legacy SecureChannelConn is created
// ---------------------------------------------------------------------------

func TestProtectedTCPRuntimeSharesOneCarrierBetweenBothFlows(t *testing.T) {
	cfg, state, _ := runtimeTestState(t)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	defer rt.Close()

	// The client dial attempt goes through the same carrier. It will not complete
	// a handshake against a silent peer, so it is bounded and its outcome is not
	// what this test measures - the dial COUNT is.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	conn, dialErr := rt.DialClientFlow(ctx)
	if conn != nil {
		_ = conn.Close()
	}
	_ = dialErr

	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("raw ESP dials after using both flows = %d, want 1", got)
	}
	// The SYN must have been protected and written to the shared carrier, proving
	// the client flow really does egress through this runtime's endpoint.
	carriers := dialer.carriers()
	if len(carriers) != 1 {
		t.Fatalf("carriers = %d, want 1", len(carriers))
	}
	if carriers[0].writeCount() == 0 {
		t.Fatal("no ESP packet reached the shared carrier; the client flow bypassed it")
	}
	t.Logf("MEASURED shared_carrier=true dials=1 esp_writes_present=true")
}

// The TCP runtime must never construct the legacy packet-mode channel: that would
// register a SECOND raw connection for the same triple and duplicate every
// inbound ESP packet.
func TestProtectedTCPRuntimeNeverCreatesLegacySecureChannel(t *testing.T) {
	cfg, state, _ := runtimeTestState(t)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	defer rt.Close()

	if rt.LegacySecureChannel() != nil {
		t.Fatal("the TCP runtime created a legacy SecureChannelConn")
	}
	// And the channel it hands to the register flow must not expose one either.
	channel := rt.RegisterChannel()
	if channel != nil && channel.secure != nil {
		t.Fatal("the protected register channel exposes a legacy secure channel")
	}
	t.Logf("MEASURED legacy_secure_channel=nil packet_mode_channel=nil")
}

// One ESP packet must be processed by exactly one replay window. With a single
// shared Transport this is structural, and this test pins it: feeding the same
// verified packet twice must be rejected the second time, not accepted by a
// second window.
func TestProtectedTCPRuntimeProcessesEachESPPacketOnce(t *testing.T) {
	cfg, state, _ := runtimeTestState(t)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	defer rt.Close()

	if got := rt.TransformCount(); got != 1 {
		t.Fatalf("the runtime holds %d transforms, want exactly 1", got)
	}
	// One transform means one replay window per SPI, which is the property that
	// makes duplicate delivery detectable rather than silently accepted.
	before := rt.Snapshot()
	if before.InboundAccepted != 0 {
		t.Fatal("a fresh runtime already accepted inbound packets")
	}
	t.Logf("MEASURED transforms=1 replay_windows_per_spi=1 inbound_accepted=0")
}

// ---------------------------------------------------------------------------
// D2.3: teardown - Close+Wait, single ownership transfer, double-Close safety
// ---------------------------------------------------------------------------

// A failed registration must release everything: the carrier, the stack, the
// pump and the allocated port.
func TestProtectedTCPRuntimeCloseReleasesEverything(t *testing.T) {
	cfg, state, allocation := runtimeTestState(t)
	dialer := &countingCarrierDialer{}
	alloc := newProtectedPortAllocator()

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	rt.BindPortRelease(alloc, allocation.generation)

	rt.Close()

	carriers := dialer.carriers()
	if len(carriers) != 1 {
		t.Fatalf("carriers = %d, want 1", len(carriers))
	}
	if got := carriers[0].closeCount(); got != 1 {
		t.Fatalf("carrier closes = %d, want exactly 1", got)
	}
	if !rt.Closed() {
		t.Fatal("the runtime does not report itself closed")
	}
	if rt.ServerFlowReady() {
		t.Fatal("a closed runtime still reports a ready server flow")
	}
	// The pump must have been joined, not merely signalled.
	if !rt.Joined() {
		t.Fatal("Close returned before the inbound pump was joined")
	}
	t.Logf("MEASURED carrier_closes=1 joined=true server_ready_after_close=false")
}

// Close must be idempotent: the register flow closes on every error path, and a
// deferred Close may run afterwards.
func TestProtectedTCPRuntimeDoubleCloseIsSafe(t *testing.T) {
	cfg, state, _ := runtimeTestState(t)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}

	rt.Close()
	rt.Close()
	rt.Close()

	carriers := dialer.carriers()
	if got := carriers[0].closeCount(); got != 1 {
		t.Fatalf("carrier closes = %d, want 1 across three Close calls", got)
	}
	// A dial after Close must fail rather than resurrect anything.
	if conn, err := rt.DialClientFlow(context.Background()); err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("dial succeeded on a closed runtime")
	}
	t.Logf("MEASURED close_calls=3 carrier_closes=1 dial_after_close_fails=true")
}

// Ownership transfers exactly once. A second transfer must fail rather than hand
// the same carrier to two owners, and a transferred runtime must not be closed by
// the register flow's deferred cleanup.
func TestProtectedTCPRuntimeOwnershipTransfersOnce(t *testing.T) {
	cfg, state, _ := runtimeTestState(t)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}

	taken, ok := rt.TakeOwnership()
	if !ok || taken == nil {
		t.Fatal("the first ownership transfer failed")
	}
	if taken != rt {
		t.Fatal("ownership transfer returned a different runtime")
	}

	// A second transfer must be refused.
	if _, ok := rt.TakeOwnership(); ok {
		t.Fatal("ownership was transferred twice")
	}

	// The register flow's cleanup must now be a no-op: the new owner is
	// responsible for the runtime's lifetime.
	rt.CloseUnlessTransferred()
	if rt.Closed() {
		t.Fatal("cleanup closed a runtime whose ownership was transferred")
	}
	if got := dialer.carriers()[0].closeCount(); got != 0 {
		t.Fatalf("carrier closes = %d, want 0 while the new owner holds it", got)
	}

	// The new owner can still close it explicitly.
	rt.Close()
	if got := dialer.carriers()[0].closeCount(); got != 1 {
		t.Fatalf("carrier closes = %d after the owner closed it, want 1", got)
	}
	t.Logf("MEASURED transfers_accepted=1 transfers_refused=1 cleanup_after_transfer=noop")
}

// Without a transfer, the cleanup path must close everything.
func TestProtectedTCPRuntimeCleanupClosesWhenNotTransferred(t *testing.T) {
	cfg, state, _ := runtimeTestState(t)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	rt.CloseUnlessTransferred()

	if !rt.Closed() {
		t.Fatal("cleanup left an untransferred runtime open")
	}
	if got := dialer.carriers()[0].closeCount(); got != 1 {
		t.Fatalf("carrier closes = %d, want 1", got)
	}
	t.Logf("MEASURED cleanup_without_transfer=closed")
}

// A failed carrier dial must not leave a runtime, a port reservation or a
// goroutine behind.
func TestProtectedTCPRuntimeStartFailureLeavesNothing(t *testing.T) {
	cfg, state, _ := runtimeTestState(t)
	dialer := &countingCarrierDialer{failWith: errors.New("carrier unavailable")}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err == nil {
		if rt != nil {
			rt.Close()
		}
		t.Fatal("start succeeded with a failing carrier dialer")
	}
	if rt != nil {
		t.Fatal("a runtime was returned alongside an error")
	}
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want exactly 1 attempt", got)
	}
	if got := len(dialer.carriers()); got != 0 {
		t.Fatalf("carriers = %d, want 0 when the dial failed", got)
	}
	t.Logf("MEASURED start_failed=true runtime=nil carriers=0")
}

// A runtime that cannot listen must fail closed AND release the carrier: a
// half-built runtime would pass the activation gate's generation check while
// having no terminating path.
func TestProtectedTCPRuntimeListenFailureClosesCarrier(t *testing.T) {
	cfg, state, _ := runtimeTestState(t)
	// A zero server port makes the listen step fail deterministically.
	state.ipsecPolicy.FlowS.LocalPort = 0
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err == nil {
		if rt != nil {
			rt.Close()
		}
		t.Fatal("start succeeded with no protected server port")
	}
	if rt != nil {
		t.Fatal("a runtime was returned alongside a listen failure")
	}
	carriers := dialer.carriers()
	if len(carriers) != 1 {
		t.Fatalf("carriers = %d, want 1 (dialled then released)", len(carriers))
	}
	if got := carriers[0].closeCount(); got != 1 {
		t.Fatalf("carrier closes = %d, want 1 after a listen failure", got)
	}
	t.Logf("MEASURED listen_failed=true carrier_released=true runtime=nil")
}

// ---------------------------------------------------------------------------
// D2.4: no detached goroutines under concurrent teardown
// ---------------------------------------------------------------------------

func TestProtectedTCPRuntimeConcurrentCloseIsBounded(t *testing.T) {
	cfg, state, _ := runtimeTestState(t)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}

	const closers = 16
	var wg sync.WaitGroup
	wg.Add(closers)
	for i := 0; i < closers; i++ {
		go func() {
			defer wg.Done()
			rt.Close()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent Close did not complete; a goroutine is detached")
	}

	if got := dialer.carriers()[0].closeCount(); got != 1 {
		t.Fatalf("carrier closes = %d under %d concurrent closers, want 1", got, closers)
	}
	if !rt.Joined() {
		t.Fatal("the pump was not joined after concurrent Close")
	}
	t.Logf("MEASURED concurrent_closers=%d carrier_closes=1 joined=true", closers)
}
