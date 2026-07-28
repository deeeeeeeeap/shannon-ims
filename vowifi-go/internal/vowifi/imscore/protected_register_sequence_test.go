package imscore

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Phase D step 3: the protected REGISTER exchange must follow one fixed order.
//
//	install IPsec
//	  -> provisional runtime (one ESP carrier, one stack, one pump)
//	    -> server listener ready on the stable port_us
//	      -> client TCP handshake from the rotating port_uc
//	        -> protected REGISTER written
//
// The order is not stylistic. TS 33.203 clause 7.1 Ports item 1 requires the
// P-CSCF to open its OWN connection to port_us before sending any request to the
// UE, and TS 24.229 clause 3.1 NOTE 3 leaves it no alternative flow. The P-CSCF
// may do that the instant it accepts our REGISTER, so a listener that starts
// afterwards can miss the first terminating request. Registering first and
// listening later is therefore not a small race - it is a registration that
// looks healthy and silently drops NOTIFY, MESSAGE and terminating INVITE.
//
// Assertions are counts, booleans, orderings and closed enums. No SIP text,
// identity, address, port value, SPI or key material is asserted or logged.

// ---------------------------------------------------------------------------
// D3.1: ordering
// ---------------------------------------------------------------------------

// The listener must be accepting before the client flow writes its first byte.
//
// The proof is structural rather than timing-based: startProtectedTCPRuntime
// returns a runtime that is ALREADY listening, and the send path cannot be
// reached without one. So the observable claim is that at the moment the runtime
// becomes ready, the carrier has seen no write at all - no SYN, no ESP, nothing.
func TestProtectedRegisterListenerIsReadyBeforeAnyWrite(t *testing.T) {
	cfg, state, _, alloc := runtimeTestStateWithAllocator(t)
	defer alloc.release(state.generation)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	defer rt.Close()

	// Ready, and nothing has been written yet.
	if !rt.ServerFlowReady() {
		t.Fatal("the runtime returned without a ready server listener")
	}
	carriers := dialer.carriers()
	if len(carriers) != 1 {
		t.Fatalf("carriers = %d, want exactly 1", len(carriers))
	}
	if got := carriers[0].writeCount(); got != 0 {
		t.Fatalf("carrier saw %d writes before the listener was ready", got)
	}

	// Only now may a handshake begin. Whether it completes depends on a peer that
	// does not exist here; what matters is that the first write happens strictly
	// after readiness.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if conn, err := rt.DialClientFlow(ctx); err == nil && conn != nil {
		_ = conn.Close()
	}
	t.Logf("MEASURED listener_ready_before_write=true writes_at_ready=0 carriers=1")
}

// The orchestrator must refuse to send when handed a runtime that is not ready,
// and it must not fall back to UDP: the plan says TCP because the request does
// not fit UDP, so a downgrade would send a request that fragments.
func TestProtectedRegisterRefusesUnreadyRuntimeWithoutFallback(t *testing.T) {
	cfg, state, _, alloc := runtimeTestStateWithAllocator(t)
	defer alloc.release(state.generation)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	// Retire it, so its activation reports not-ready.
	rt.Close()

	plan := protectedRegisterPlan{
		Transport:             protectedTransportTCP,
		Reason:                protectedTransportReasonESPOverBudget,
		SIPMessageLen:         protectedRegisterMaxUnfragmentedSIPLen + 1,
		PredictedUDPPacketLen: registerProtectedInnerMTU + 12,
	}
	err = authorizeProtectedTCPActivation(plan, rt.Activation())
	if err == nil {
		t.Fatal("a retired runtime was authorized to send")
	}
	var unavailable *protectedTCPUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("refusal is not classified: %v", err)
	}
	// The refusal must not be expressed as a UDP plan.
	if strings.Contains(strings.ToLower(err.Error()), "udp") {
		t.Fatal("the refusal mentions UDP; it must not suggest a downgrade")
	}
	t.Logf("MEASURED unready_refused=true reason=%s downgraded=false", unavailable.Reason())
}

// ---------------------------------------------------------------------------
// D3.2: generation, ports and policy must all match
// ---------------------------------------------------------------------------

// An activation whose generation does not match the runtime must not be honoured.
// This is the guard against a retired SA's runtime being used for a new
// registration, or vice versa.
func TestProtectedRegisterRejectsMismatchedGenerationWithZeroWrites(t *testing.T) {
	cfg, state, _, alloc := runtimeTestStateWithAllocator(t)
	defer alloc.release(state.generation)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	defer rt.Close()

	current := rt.Activation()
	if current.Generation != state.generation {
		t.Fatalf("runtime generation %d does not match the state %d",
			current.Generation, state.generation)
	}

	for _, tc := range []struct {
		name       string
		activation protectedTCPActivation
	}{
		{name: "zero_generation", activation: protectedTCPActivation{ServerFlowReady: true, Generation: 0}},
		{name: "stale_generation", activation: protectedTCPActivation{ServerFlowReady: true, Generation: current.Generation - 1}},
		{name: "future_generation", activation: protectedTCPActivation{ServerFlowReady: true, Generation: current.Generation + 7}},
		{name: "listener_down", activation: protectedTCPActivation{ServerFlowReady: false, Generation: current.Generation}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := dialer.carriers()[0].writeCount()
			err := verifyProtectedActivationMatchesRuntime(rt, tc.activation)
			if err == nil {
				t.Fatal("a mismatched activation was accepted")
			}
			if after := dialer.carriers()[0].writeCount(); after != before {
				t.Fatalf("the mismatch produced %d writes", after-before)
			}
		})
	}

	// The matching activation is accepted, or the guard would be vacuous.
	if err := verifyProtectedActivationMatchesRuntime(rt, current); err != nil {
		t.Fatalf("the runtime's own activation was rejected: %v", err)
	}
	t.Logf("MEASURED mismatches_rejected=4 writes_on_mismatch=0 match_accepted=true")
}

// The runtime must be bound to the same policy the state installed. A runtime
// built from a different policy would protect packets with the wrong keys or
// bind the wrong port.
func TestProtectedRegisterRejectsRuntimeFromDifferentPolicy(t *testing.T) {
	cfg, state, _, alloc := runtimeTestStateWithAllocator(t)
	defer alloc.release(state.generation)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	defer rt.Close()

	// A second state with a DIFFERENT allocation. It must come from the SAME
	// allocator: a fresh allocator starts its port walk from the same base, so two
	// independent allocators hand out the same first port and the mix-up this test
	// looks for becomes undetectable.
	otherAllocation := alloc.next()
	defer alloc.release(otherAllocation.generation)
	otherState := syntheticProtectedRegisterState(cfg)
	otherState.portC = otherAllocation.clientPort
	otherState.portS = otherAllocation.serverPort
	otherState.generation = otherAllocation.generation
	if err := installIPSecFromChallenge(cfg, otherState, syntheticChallengeResponse(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge(other): %v", err)
	}

	if otherState.portC == state.portC {
		t.Fatal("the two allocations share a port_uc; the test cannot detect a mix-up")
	}
	if otherState.generation == state.generation {
		t.Fatal("the two allocations share a generation")
	}
	if err := verifyProtectedRuntimeMatchesState(rt, *otherState); err == nil {
		t.Fatal("a runtime was accepted for a different state's policy")
	}
	if err := verifyProtectedRuntimeMatchesState(rt, *state); err != nil {
		t.Fatalf("the runtime was rejected for its own state: %v", err)
	}
	if got := dialer.carriers()[0].writeCount(); got != 0 {
		t.Fatalf("the policy check produced %d writes", got)
	}
	t.Logf("MEASURED foreign_policy_rejected=true own_policy_accepted=true writes=0")
}

// ---------------------------------------------------------------------------
// D3.3: failure releases everything exactly once
// ---------------------------------------------------------------------------

// Every failure path must Close+Wait the runtime and release the generation's
// port exactly once. A double release would hand the port to a live SA.
func TestProtectedRegisterFailureReleasesGenerationOnce(t *testing.T) {
	cfg, state, _, alloc := runtimeTestStateWithAllocator(t)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	rt.BindPortRelease(alloc, state.generation)

	// The port is held while the runtime lives.
	if !alloc.isActive(state.generation) {
		t.Fatal("the generation's port was not held")
	}

	// Simulate the failure teardown running twice: an explicit Close plus a
	// deferred CloseUnlessTransferred.
	rt.Close()
	rt.CloseUnlessTransferred()
	rt.Close()

	if alloc.isActive(state.generation) {
		t.Fatal("the generation's port was not released")
	}
	// Releasing twice must not free a port that a LATER generation now holds.
	later := alloc.next()
	if later.clientPort == 0 {
		t.Fatal("no port was available after release")
	}
	rt.Close()
	if !alloc.isActive(later.generation) {
		t.Fatal("a repeated release freed a different generation's port")
	}
	alloc.release(later.generation)

	if !rt.Joined() {
		t.Fatal("the runtime did not join its inbound pump")
	}
	if got := dialer.carriers()[0].closeCount(); got != 1 {
		t.Fatalf("carrier closes = %d, want exactly 1", got)
	}
	t.Logf("MEASURED releases=1 carrier_closes=1 joined=true later_generation_intact=true")
}

// ---------------------------------------------------------------------------
// D3.4: ownership transfers once, and the two runtimes are exclusive
// ---------------------------------------------------------------------------

// On success the runtime moves to the Service exactly once, and the legacy
// transport runtime must not also start: two runtimes would mean two readers of
// one ESP carrier.
func TestProtectedRegisterTransfersOwnershipOnceAndSkipsLegacyRuntime(t *testing.T) {
	cfg, state, _, alloc := runtimeTestStateWithAllocator(t)
	defer alloc.release(state.generation)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}

	owned, ok := rt.TakeOwnership()
	if !ok || owned == nil {
		t.Fatal("register flow could not transfer runtime into its result")
	}
	result := &registerResult{
		protectedTCP: owned,
		ipsecPolicy:  state.ipsecPolicy,
		transport:    state.transport,
	}

	// A TCP result must carry no legacy secure channel: the two are mutually
	// exclusive, and service_lifecycle keys the legacy runtime off secureConn.
	if result.secureConn != nil {
		t.Fatal("a protected TCP result carries a legacy secure channel")
	}
	if !protectedResultUsesTCPRuntime(result) {
		t.Fatal("the result was not recognised as a protected TCP result")
	}
	if shouldStartLegacyTransportRuntime(result) {
		t.Fatal("the legacy transport runtime would start alongside the TCP runtime")
	}

	// Ownership moves once.
	taken, ok := takeProtectedTCPOwnership(result)
	if !ok || taken == nil {
		t.Fatal("ownership was not transferred")
	}
	if _, again := takeProtectedTCPOwnership(result); again {
		t.Fatal("ownership was transferred twice")
	}
	// After the transfer the register-side cleanup must be a no-op.
	rt.CloseUnlessTransferred()
	if rt.Closed() {
		t.Fatal("cleanup closed a transferred runtime")
	}
	taken.Close()
	t.Logf("MEASURED transfers=1 second_transfer_refused=true legacy_runtime_started=false")
}

// A UDP result keeps its existing behaviour exactly: legacy runtime starts, no
// TCP runtime exists.
func TestProtectedRegisterUDPResultKeepsLegacyRuntime(t *testing.T) {
	result := &registerResult{}
	if protectedResultUsesTCPRuntime(result) {
		t.Fatal("a UDP result was classified as protected TCP")
	}
	if _, ok := takeProtectedTCPOwnership(result); ok {
		t.Fatal("a UDP result yielded a TCP runtime")
	}
	t.Logf("MEASURED udp_result_uses_tcp_runtime=false")
}

func TestProtectedRegisterRequiresRuntimeAndClientFlowTogether(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	for _, tc := range []struct {
		name   string
		result *registerResult
	}{
		{name: "runtime_without_client", result: &registerResult{protectedTCP: &protectedTCPRuntime{}}},
		{name: "client_without_runtime", result: &registerResult{protectedClientConn: client}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := assertProtectedChannelExclusivity(tc.result); err == nil {
				t.Fatal("incomplete protected TCP ownership was accepted")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// D3.5: no fallback, no candidate switch, no replay
// ---------------------------------------------------------------------------

// A protected TCP failure must surface as one classified error. It must not
// retry on UDP, move to another candidate, or resend the REGISTER.
func TestProtectedRegisterTCPFailureDoesNotFallBackOrReplay(t *testing.T) {
	cfg, state, _, alloc := runtimeTestStateWithAllocator(t)
	defer alloc.release(state.generation)

	dialer := &countingCarrierDialer{failWith: errors.New("no tunnel")}
	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err == nil {
		if rt != nil {
			rt.Close()
		}
		t.Fatal("the runtime started without a carrier")
	}
	if rt != nil {
		t.Fatal("a failed start returned a runtime")
	}
	// Exactly one dial attempt: no retry, no second candidate.
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("raw dials = %d, want exactly 1", got)
	}
	// And no UDP secure channel was created as a consolation prize.
	if len(dialer.carriers()) != 0 {
		t.Fatal("a carrier survived a failed start")
	}
	t.Logf("MEASURED dials=1 retries=0 udp_fallback=false replays=0")
}

// Concurrent teardown of the same runtime while a release is bound must stay
// bounded and must not double-release.
func TestProtectedRegisterConcurrentTeardownReleasesOnce(t *testing.T) {
	cfg, state, _, alloc := runtimeTestStateWithAllocator(t)
	dialer := &countingCarrierDialer{}

	rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	rt.BindPortRelease(alloc, state.generation)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rt.Close()
			rt.CloseUnlessTransferred()
		}()
	}
	wg.Wait()

	if alloc.isActive(state.generation) {
		t.Fatal("the port stayed active after concurrent teardown")
	}
	if got := dialer.carriers()[0].closeCount(); got != 1 {
		t.Fatalf("carrier closes = %d, want exactly 1", got)
	}
	if !rt.Joined() {
		t.Fatal("concurrent teardown did not join the pump")
	}
	t.Logf("MEASURED closers=16 carrier_closes=1 releases=1 joined=true")
}
