package imscore

import (
	"context"
	"sync"
	"testing"
)

// Phase D step 4: re-registration and SA replacement.
//
// TS 33.203 clause 7.4 governs the port behaviour:
//
//	"the protected server ports at the UE (port_us) and the P-CSCF (port_ps)
//	 shall remain unchanged, while the protected client ports at the UE
//	 (port_uc) and the P-CSCF (port_pc) shall change."
//
// and the same clause keeps the OLD SA usable until the new one is confirmed:
// a UE that tore down its old runtime before the new registration succeeded
// would be unreachable for the whole exchange, and unrecoverable if it failed.
//
// So replacement is: build the new runtime alongside the old one, switch only
// after the new one is ready AND the registration succeeded, then cancel+join
// the old one. A late packet arriving on the retired generation must never be
// injected into the new runtime - it was protected with different keys, and its
// replay window belongs to a transform that no longer exists.
//
// Assertions are counts, booleans, orderings and closed enums. No SIP text,
// identity, address, port value, SPI or key material is asserted or logged.

// ---------------------------------------------------------------------------
// D4.1: ports across a replacement
// ---------------------------------------------------------------------------

// port_us must survive, port_uc must move, and both runtimes must exist at once
// during the overlap.
func TestProtectedTCPReRegistrationPreservesPortUSAndRotatesPortUC(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	alloc := newProtectedPortAllocator()

	oldState := replacementState(t, cfg, alloc)
	dialer := &countingCarrierDialer{}
	oldRT, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *oldState)
	if err != nil {
		t.Fatalf("start old runtime: %v", err)
	}
	oldRT.BindPortRelease(alloc, oldState.generation)
	defer oldRT.Close()

	// The new registration allocates while the old one is still live.
	newState := replacementState(t, cfg, alloc)
	newRT, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *newState)
	if err != nil {
		t.Fatalf("start new runtime: %v", err)
	}
	newRT.BindPortRelease(alloc, newState.generation)
	defer newRT.Close()

	// port_us is identical: the P-CSCF connects back to it and must not have to
	// relearn it.
	if oldRT.ProtectedServerPort() != newRT.ProtectedServerPort() {
		t.Fatal("port_us changed across the replacement")
	}
	// port_uc moved: reusing it would collide with the old SA the P-CSCF may
	// still hold for that port pair.
	if oldRT.ProtectedClientPort() == newRT.ProtectedClientPort() {
		t.Fatal("port_uc did not rotate across the replacement")
	}
	// Both generations are live and distinct during the overlap.
	if oldRT.Generation() == newRT.Generation() {
		t.Fatal("the two runtimes share a generation")
	}
	if !alloc.isActive(oldState.generation) || !alloc.isActive(newState.generation) {
		t.Fatal("both generations must hold their ports during the overlap")
	}
	if got := alloc.activeCount(); got != 2 {
		t.Fatalf("active generations = %d, want 2 during the overlap", got)
	}
	// Each generation dialled its own carrier: they are separate SAs.
	if got := len(dialer.carriers()); got != 2 {
		t.Fatalf("carriers = %d, want 2 (one per generation)", got)
	}
	t.Logf("MEASURED port_us_stable=true port_uc_rotated=true overlap_generations=2 carriers=2")
}

// ---------------------------------------------------------------------------
// D4.2: the switch is atomic and only happens on success
// ---------------------------------------------------------------------------

// The holder must expose exactly one current runtime at any time, and must not
// adopt a new one that is not ready.
func TestProtectedTCPSAReplacementSwitchesOnlyWhenNewRuntimeIsReady(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	alloc := newProtectedPortAllocator()
	dialer := &countingCarrierDialer{}

	oldState := replacementState(t, cfg, alloc)
	oldRT, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *oldState)
	if err != nil {
		t.Fatalf("start old: %v", err)
	}
	oldRT.BindPortRelease(alloc, oldState.generation)

	holder := newProtectedRuntimeHolder()
	if replaced := holder.adopt(oldRT); replaced != nil {
		t.Fatal("adopting into an empty holder reported a replaced runtime")
	}
	if holder.current() != oldRT {
		t.Fatal("the holder does not expose the adopted runtime")
	}

	// A not-ready candidate must be refused, and the old runtime must stay.
	newState := replacementState(t, cfg, alloc)
	notReady, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *newState)
	if err != nil {
		t.Fatalf("start new: %v", err)
	}
	notReady.BindPortRelease(alloc, newState.generation)
	notReady.Close() // retire it before adoption

	if err := holder.replace(notReady); err == nil {
		t.Fatal("a retired runtime was adopted")
	}
	if holder.current() != oldRT {
		t.Fatal("a refused replacement displaced the live runtime")
	}
	if oldRT.Closed() {
		t.Fatal("the old runtime was closed by a refused replacement")
	}
	if !alloc.isActive(oldState.generation) {
		t.Fatal("the old generation lost its port on a refused replacement")
	}
	t.Logf("MEASURED refused_replacement=true old_runtime_intact=true old_port_held=true")

	// A ready candidate is adopted, and the old runtime is retired.
	readyState := replacementState(t, cfg, alloc)
	readyRT, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *readyState)
	if err != nil {
		t.Fatalf("start ready: %v", err)
	}
	readyRT.BindPortRelease(alloc, readyState.generation)

	if err := holder.replace(readyRT); err != nil {
		t.Fatalf("a ready runtime was refused: %v", err)
	}
	if holder.current() != readyRT {
		t.Fatal("the holder did not switch to the new runtime")
	}
	// The old runtime must be cancelled AND joined, and its port released.
	if !oldRT.Closed() {
		t.Fatal("the retired runtime was not closed")
	}
	if !oldRT.Joined() {
		t.Fatal("the retired runtime was not joined")
	}
	if alloc.isActive(oldState.generation) {
		t.Fatal("the retired generation still holds its port")
	}
	if !alloc.isActive(readyState.generation) {
		t.Fatal("the current generation lost its port")
	}
	holder.closeCurrent()
	t.Logf("MEASURED switched=true old_closed=true old_joined=true old_port_released=true")
}

// A failed re-registration must leave the old runtime serving. This is the
// difference between a brief re-registration blip and a dead UE.
func TestProtectedTCPFailedReplacementDoesNotLeakMixedPolicies(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	alloc := newProtectedPortAllocator()
	dialer := &countingCarrierDialer{}

	oldState := replacementState(t, cfg, alloc)
	oldRT, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *oldState)
	if err != nil {
		t.Fatalf("start old: %v", err)
	}
	oldRT.BindPortRelease(alloc, oldState.generation)

	holder := newProtectedRuntimeHolder()
	holder.adopt(oldRT)

	// The new attempt gets as far as a live runtime, then the registration fails.
	newState := replacementState(t, cfg, alloc)
	newRT, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *newState)
	if err != nil {
		t.Fatalf("start new: %v", err)
	}
	newRT.BindPortRelease(alloc, newState.generation)

	// abandonReplacement is what the failure path calls: it discards the
	// candidate without touching the incumbent.
	holder.abandonReplacement(newRT)

	if holder.current() != oldRT {
		t.Fatal("a failed replacement displaced the live runtime")
	}
	if oldRT.Closed() {
		t.Fatal("a failed replacement closed the live runtime")
	}
	if !newRT.Closed() || !newRT.Joined() {
		t.Fatal("the abandoned candidate was not closed and joined")
	}
	if alloc.isActive(newState.generation) {
		t.Fatal("the abandoned generation still holds its port")
	}
	if !alloc.isActive(oldState.generation) {
		t.Fatal("the incumbent lost its port")
	}
	// The two runtimes must never have shared a policy or a transform: that is
	// what "mixed policies" would mean.
	if oldRT.ProtectedClientPort() == newRT.ProtectedClientPort() {
		t.Fatal("the abandoned candidate shared the incumbent's port_uc")
	}
	if got := alloc.activeCount(); got != 1 {
		t.Fatalf("active generations = %d, want 1 after abandonment", got)
	}
	holder.closeCurrent()
	t.Logf("MEASURED incumbent_survived=true candidate_closed=true candidate_joined=true active=1")
}

// ---------------------------------------------------------------------------
// D4.3: retired generations are inert
// ---------------------------------------------------------------------------

// A packet or an activation belonging to a retired generation must be refused by
// the current runtime.
func TestProtectedTCPSAReplacementRejectsOldGenerationPackets(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	alloc := newProtectedPortAllocator()
	dialer := &countingCarrierDialer{}

	oldState := replacementState(t, cfg, alloc)
	oldRT, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *oldState)
	if err != nil {
		t.Fatalf("start old: %v", err)
	}
	oldRT.BindPortRelease(alloc, oldState.generation)

	holder := newProtectedRuntimeHolder()
	holder.adopt(oldRT)

	newState := replacementState(t, cfg, alloc)
	newRT, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *newState)
	if err != nil {
		t.Fatalf("start new: %v", err)
	}
	newRT.BindPortRelease(alloc, newState.generation)
	if err := holder.replace(newRT); err != nil {
		t.Fatalf("replace: %v", err)
	}
	defer holder.closeCurrent()

	// The retired generation's activation must not authorize anything.
	retired := protectedTCPActivation{ServerFlowReady: true, Generation: oldState.generation}
	if err := verifyProtectedActivationMatchesRuntime(newRT, retired); err == nil {
		t.Fatal("the retired generation's activation was accepted by the new runtime")
	}
	// Nor must the retired state be paired with the new runtime.
	if err := verifyProtectedRuntimeMatchesState(newRT, *oldState); err == nil {
		t.Fatal("the new runtime accepted the retired state's policy")
	}
	// The old runtime is closed, so its own activation is not ready either: a
	// late packet has nothing live to arrive on.
	if oldRT.Activation().ready() {
		t.Fatal("the retired runtime still reports a ready activation")
	}
	// The retired carrier is closed, which is what makes late packets inert: the
	// inbound pump has already returned.
	carriers := dialer.carriers()
	if len(carriers) != 2 {
		t.Fatalf("carriers = %d, want 2", len(carriers))
	}
	if got := carriers[0].closeCount(); got != 1 {
		t.Fatalf("retired carrier closes = %d, want 1", got)
	}
	if !oldRT.Joined() {
		t.Fatal("the retired runtime did not join its pump")
	}
	// The current runtime's own pairing still works, or the guard would be vacuous.
	if err := verifyProtectedRuntimeMatchesState(newRT, *newState); err != nil {
		t.Fatalf("the current runtime rejected its own state: %v", err)
	}
	t.Logf("MEASURED retired_activation_refused=true retired_policy_refused=true retired_carrier_closed=true current_ok=true")
}

// The switch must cancel and join the old runtime before returning, so no
// goroutine from the retired generation outlives it.
func TestProtectedTCPReplacementJoinsOldRuntime(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	alloc := newProtectedPortAllocator()
	dialer := &countingCarrierDialer{}

	holder := newProtectedRuntimeHolder()
	var retired []*protectedTCPRuntime

	// Several consecutive re-registrations.
	for i := 0; i < 4; i++ {
		state := replacementState(t, cfg, alloc)
		rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		rt.BindPortRelease(alloc, state.generation)
		if i == 0 {
			holder.adopt(rt)
			continue
		}
		previous := holder.current()
		if err := holder.replace(rt); err != nil {
			t.Fatalf("replace %d: %v", i, err)
		}
		// The predecessor must already be joined when replace returns: this is the
		// property that makes the switch safe rather than merely eventual.
		if !previous.Closed() || !previous.Joined() {
			t.Fatalf("predecessor %d was not joined by the time replace returned", i-1)
		}
		retired = append(retired, previous)
	}

	if len(retired) != 3 {
		t.Fatalf("retired runtimes = %d, want 3", len(retired))
	}
	// Exactly one generation is live at the end.
	if got := alloc.activeCount(); got != 1 {
		t.Fatalf("active generations = %d, want 1", got)
	}
	// Every retired carrier is closed exactly once.
	for i, carrier := range dialer.carriers() {
		if i == len(dialer.carriers())-1 {
			continue // the current one is still live
		}
		if got := carrier.closeCount(); got != 1 {
			t.Fatalf("retired carrier %d closes = %d, want 1", i, got)
		}
	}
	holder.closeCurrent()
	if got := alloc.activeCount(); got != 0 {
		t.Fatalf("active generations after final close = %d, want 0", got)
	}
	t.Logf("MEASURED replacements=3 all_joined=true final_active=0")
}

// Concurrent replacements must leave exactly one live runtime and must not
// double-close any predecessor.
func TestProtectedTCPConcurrentReplacementKeepsOneRuntime(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	alloc := newProtectedPortAllocator()
	dialer := &countingCarrierDialer{}

	holder := newProtectedRuntimeHolder()
	first := replacementState(t, cfg, alloc)
	firstRT, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *first)
	if err != nil {
		t.Fatalf("start first: %v", err)
	}
	firstRT.BindPortRelease(alloc, first.generation)
	holder.adopt(firstRT)

	const workers = 8
	candidates := make([]*protectedTCPRuntime, workers)
	for i := 0; i < workers; i++ {
		state := replacementState(t, cfg, alloc)
		rt, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
		if err != nil {
			t.Fatalf("start candidate %d: %v", i, err)
		}
		rt.BindPortRelease(alloc, state.generation)
		candidates[i] = rt
	}

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(rt *protectedTCPRuntime) {
			defer wg.Done()
			_ = holder.replace(rt)
		}(candidates[i])
	}
	wg.Wait()

	current := holder.current()
	if current == nil {
		t.Fatal("no runtime survived the concurrent replacements")
	}
	// Exactly one generation holds a port.
	if got := alloc.activeCount(); got != 1 {
		t.Fatalf("active generations = %d, want 1", got)
	}
	// Every non-current runtime is closed and joined exactly once.
	closedCount := 0
	for _, rt := range append([]*protectedTCPRuntime{firstRT}, candidates...) {
		if rt == current {
			continue
		}
		if !rt.Closed() || !rt.Joined() {
			t.Fatal("a displaced runtime was not closed and joined")
		}
		closedCount++
	}
	if closedCount != workers {
		t.Fatalf("displaced runtimes = %d, want %d", closedCount, workers)
	}
	for _, carrier := range dialer.carriers() {
		if got := carrier.closeCount(); got > 1 {
			t.Fatalf("a carrier was closed %d times", got)
		}
	}
	holder.closeCurrent()
	t.Logf("MEASURED concurrent_replacements=%d survivors=1 displaced=%d double_closes=0",
		workers, closedCount)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// replacementState builds an installed state from a fresh allocation on the
// SAME allocator, which is what a re-registration does.
func replacementState(t *testing.T, cfg Config, alloc *protectedPortAllocator) *registerState {
	t.Helper()
	allocation, err := alloc.tryNext()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	state := syntheticProtectedRegisterState(cfg)
	state.portC = allocation.clientPort
	state.portS = allocation.serverPort
	state.generation = allocation.generation
	if err := installIPSecFromChallenge(cfg, state, syntheticChallengeResponse(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	return state
}
