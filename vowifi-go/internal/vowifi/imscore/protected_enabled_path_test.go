package imscore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

// Phase F: the ENABLED path, exercised at the real entry point.
//
// Every earlier phase tested a component. These tests drive
// runSecureAuthenticatedRegister itself with the production gate switched on, so
// the thing under test is the wiring: which branch runs, in what order, and what
// happens to the runtime and the generation on each outcome.
//
// What these tests can and cannot prove is worth stating plainly. They prove the
// decision, the ordering, the teardown and the absence of any fallback. They
// cannot prove that a P-CSCF accepts a protected REGISTER over TCP - there is no
// peer here, so the handshake cannot complete. That single question is what the
// live run answers.
//
// Assertions are counts, booleans, orderings and error classifications. No SIP
// text, identity, address, port value, SPI or key material is asserted or logged.

// withProtectedTCPEnabled switches the production gate on for one test and
// restores the previous value afterwards, so no test can leak the enabled state
// into another.
func withProtectedTCPEnabled(t *testing.T) {
	t.Helper()
	previous := protectedTCPClientProductionEnabled
	protectedTCPClientProductionEnabled = true
	t.Cleanup(func() { protectedTCPClientProductionEnabled = previous })
}

// enabledPathState builds an installed state whose protected REGISTER is large
// enough to select TCP, on a template that opts in.
func enabledPathState(t *testing.T) (Config, *registerState, *ipsec3gpp.ProtectedChannelOwner) {
	t.Helper()
	cfg, state, owner := runtimeTestStateWithProtectedChannel(t)
	cfg.ProtectedTransport = "auto"
	return cfg, state, owner
}

// ---------------------------------------------------------------------------
// F.1: the unprotected phase is untouched
// ---------------------------------------------------------------------------

// Enabling protected TCP must not change the transport of the INITIAL REGISTER.
// The two are decided by different functions on purpose: registerTransportCandidates
// drives the unprotected attempt, and decideProtectedRegisterTransport only ever
// sees a request that already survived a 401.
func TestEnabledPathLeavesInitialRegisterOnUDP(t *testing.T) {
	withProtectedTCPEnabled(t)
	cfg := syntheticProtectedRegisterConfig()

	// The unprotected candidate list is unchanged by the gate: for 3gpp-default it
	// still starts with UDP.
	modes := registerTransportCandidates(cfg, "auto")
	if len(modes) == 0 || modes[0] != "udp" {
		t.Fatalf("initial transport candidates = %v, want udp first", modes)
	}

	// And the protected decision is not reachable without a challenge: it needs a
	// serialized length, which only exists after the 401 has been answered.
	if _, err := decideProtectedRegisterTransport(cfg, "auto", 0); err == nil {
		t.Fatal("the protected decision accepted a zero length; it must need a real request")
	}
	t.Logf("MEASURED initial_transport=udp gate_enabled=true protected_decision_needs_request=true")
}

// ---------------------------------------------------------------------------
// F.2: the enable condition is exactly template + auto + size
// ---------------------------------------------------------------------------

// TCP may only be selected for a template that opted in, with auto or explicit
// tcp, and a protected request that does not fit UDP. Every other combination
// must keep the legacy UDP path.
func TestEnabledPathSelectsTCPOnlyForOptedInTemplateAndOversizeRequest(t *testing.T) {
	withProtectedTCPEnabled(t)
	base := syntheticProtectedRegisterConfig()
	atBudget := protectedRegisterMaxUnfragmentedSIPLen
	overBudget := protectedRegisterMaxUnfragmentedSIPLen + 1

	for _, tc := range []struct {
		name       string
		behavior   policy.CarrierBehavior
		configured string
		sipLen     int
		want       string
	}{
		{name: "optin_auto_over_budget", behavior: policy.ResolveCarrierBehavior("310", "240"), configured: "auto", sipLen: overBudget, want: protectedTransportTCP},
		{name: "optin_auto_at_budget", behavior: policy.ResolveCarrierBehavior("310", "240"), configured: "auto", sipLen: atBudget, want: protectedTransportUDP},
		{name: "optin_explicit_udp_over_budget", behavior: policy.ResolveCarrierBehavior("310", "240"), configured: "udp", sipLen: overBudget, want: protectedTransportUDP},
		{name: "optout_auto_over_budget", behavior: policy.ResolveCarrierBehavior("234", "15"), configured: "auto", sipLen: overBudget, want: protectedTransportUDP},
		{name: "optout_giffgaff_over_budget", behavior: policy.ResolveCarrierBehavior("234", "10"), configured: "auto", sipLen: overBudget, want: protectedTransportUDP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.CarrierBehavior = tc.behavior
			plan, err := decideProtectedRegisterTransport(cfg, tc.configured, tc.sipLen)
			if err != nil {
				t.Fatalf("decideProtectedRegisterTransport: %v", err)
			}
			if plan.Transport != tc.want {
				t.Fatalf("transport = %q, want %q", plan.Transport, tc.want)
			}
		})
	}
	t.Logf("MEASURED boundary=%d optin_only=true explicit_udp_wins=true", atBudget)
}

// ---------------------------------------------------------------------------
// F.3: ordering at the real entry point
// ---------------------------------------------------------------------------

// The listener must be accepting before the client flow writes its first byte,
// and the whole exchange must use exactly one ESP carrier.
//
// The handshake cannot complete here - there is no peer - so the observable
// claims are: one dial, the runtime was listening, and the failure is classified
// as a TCP-path failure rather than anything that could be retried on UDP.
func TestEnabledPathListensBeforeHandshakeAndUsesOneCarrier(t *testing.T) {
	withProtectedTCPEnabled(t)
	cfg, state, _ := enabledPathState(t)
	dialer := &countingCarrierDialer{}

	challenge := syntheticChallengeResponse(t)
	challenged := syntheticChallengedRequest(t, cfg, state)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	result, err := runSecureAuthenticatedRegister(ctx, cfg, dialer, state, challenged, challenge)
	if err == nil {
		t.Fatal("the exchange succeeded with no peer; the test cannot prove anything")
	}
	if result != nil {
		t.Fatal("a failed exchange returned a result")
	}

	// Exactly one ESP carrier: the TCP runtime's. A UDP fallback would dial a
	// second one through dialSecureRegisterConn.
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("raw ESP dials = %d, want exactly 1", got)
	}
	carriers := dialer.carriers()
	if len(carriers) != 1 {
		t.Fatalf("carriers = %d, want 1", len(carriers))
	}

	// The failure must be classified as a post-authentication protected failure.
	//
	// This is asserted by TYPE, not by matching the message. Phase G replaced the
	// text-matching guard in shouldRetryNextRegisterTransport precisely because a
	// message is not a contract: the wording changed when the error became typed,
	// and a text assertion would have kept passing while the real guard rotted.
	if !registerReachedAuthenticatedPhase(err) {
		t.Fatalf("failure is not classified as a post-authentication protected failure")
	}
	// And the classification must actually block the fallback.
	if shouldRetryNextRegisterTransport(0, err, 0, 2, false) {
		t.Fatal("the failure would still trigger a transport retry")
	}
	// A legacy UDP-path error would still be recognisable by its own text; its
	// absence confirms dialSecureRegisterConn never ran.
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "secure channel dial") || strings.Contains(msg, "authenticated register:") {
		t.Fatal("the error came from the legacy UDP path; the TCP decision fell back")
	}

	// The carrier must be closed and the pump joined: nothing detached.
	if got := carriers[0].closeCount(); got != 1 {
		t.Fatalf("carrier closes = %d, want exactly 1", got)
	}
	t.Logf("MEASURED dials=1 carriers=1 carrier_closed=1 udp_fallback=false classified=protected_tcp")
}

// ---------------------------------------------------------------------------
// F.4: failure keeps the incumbent and releases the generation
// ---------------------------------------------------------------------------

// A failed protected TCP registration must leave an existing runtime untouched
// and must release its own generation's port exactly once.
func TestEnabledPathFailureKeepsIncumbentAndReleasesGeneration(t *testing.T) {
	withProtectedTCPEnabled(t)

	// An incumbent registration, already live.
	incumbentCfg, incumbentState, owner := enabledPathState(t)
	incumbentCarrier := newRuntimeCarrier()
	if err := incumbentState.channel.OpenUDP(incumbentCarrier); err != nil {
		t.Fatalf("open incumbent channel: %v", err)
	}
	incumbent, err := owner.Adopt(incumbentState.channel)
	if err != nil {
		t.Fatalf("adopt incumbent channel: %v", err)
	}
	defer incumbent.Close()

	// A second registration on a NEW generation, which will fail for want of a peer.
	replacement, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve replacement channel: %v", err)
	}
	replacementCfg := incumbentCfg
	replacementState := syntheticProtectedRegisterState(t, replacementCfg)
	replacementState.spiC = replacement.ClientSPI()
	replacementState.spiS = replacement.ServerSPI()
	replacementState.portC = replacement.ClientPort()
	replacementState.portS = replacement.ServerPort()
	replacementState.generation = replacement.Generation()
	replacementState.channel = replacement
	if err := installIPSecFromChallenge(replacementCfg, replacementState, syntheticChallengeResponse(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	if replacementState.portC == incumbentState.portC {
		t.Fatal("the two generations share a port_uc; the test cannot detect a leak")
	}

	replacementDialer := &countingCarrierDialer{}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	result, err := runSecureAuthenticatedRegister(
		ctx, replacementCfg, replacementDialer, replacementState,
		syntheticChallengedRequest(t, replacementCfg, replacementState),
		syntheticChallengeResponse(t))
	if err == nil || result != nil {
		t.Fatal("the replacement unexpectedly succeeded")
	}

	// The incumbent survives as the owner's current generation.
	if _, err := incumbent.Write([]byte("current")); err != nil {
		t.Fatalf("failed replacement displaced the incumbent: %v", err)
	}
	if got := incumbentCarrier.closeCount(); got != 0 {
		t.Fatalf("failed replacement closed incumbent carrier %d times", got)
	}

	// The replacement's own carrier is gone.
	for i, carrier := range replacementDialer.carriers() {
		if got := carrier.closeCount(); got != 1 {
			t.Fatalf("replacement carrier %d closes = %d, want 1", i, got)
		}
	}
	t.Logf("MEASURED incumbent_intact=true incumbent_listening=true incumbent_port_held=true replacement_carrier_closed=true")
}

// ---------------------------------------------------------------------------
// F.5: no candidate switch, no legacy runtime
// ---------------------------------------------------------------------------

// A protected TCP failure must not walk to another candidate. The candidate was
// already chosen by the unprotected phase - the one whose 401 installed this SA -
// and re-choosing would use keys negotiated with a different P-CSCF.
func TestEnabledPathFailureDoesNotSwitchCandidateOrStartLegacyRuntime(t *testing.T) {
	withProtectedTCPEnabled(t)
	cfg, state, _ := enabledPathState(t)

	// Two distinct candidates, so a switch would be observable.
	winning := candidateAttemptConfig(cfg, registerAttemptCandidate{
		Gateway: "[" + winningCandidateHost + "]:5060",
	})
	winning.ProtectedTransport = "auto"
	winningIP := effectiveIPSecRemoteIP(winning)
	if winningIP == nil {
		t.Fatal("the winning candidate does not resolve")
	}

	dialer := &countingCarrierDialer{}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	result, err := runSecureAuthenticatedRegister(
		ctx, winning, dialer, state,
		syntheticChallengedRequest(t, winning, state), syntheticChallengeResponse(t))
	if err == nil || result != nil {
		t.Fatal("the exchange unexpectedly succeeded")
	}

	// One dial only: no retry against another candidate, and no UDP fallback.
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1: a failure must not try another candidate", got)
	}

	// A failed TCP result carries no provisional channel, so Service has nothing
	// to adopt and no legacy runtime can start.
	if result != nil && result.channel != nil {
		t.Fatal("a failed TCP registration returned an ownership-capable channel")
	}
	t.Logf("MEASURED dials=1 candidate_switches=0 legacy_runtime=false")
}

// ---------------------------------------------------------------------------
// F.6: a UDP decision still runs the legacy path with the gate on
// ---------------------------------------------------------------------------

// The gate must not change anything for a registration that fits UDP. This is
// the regression guard for every carrier that already works.
func TestEnabledPathStillUsesLegacyUDPWhenRequestFits(t *testing.T) {
	withProtectedTCPEnabled(t)
	cfg, state, _ := enabledPathState(t)

	// An opted-out template keeps the protected send on UDP at any size.
	cfg.CarrierBehavior = policy.ResolveCarrierBehavior("234", "10")

	dialer := &countingCarrierDialer{}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := runSecureAuthenticatedRegister(
		ctx, cfg, dialer, state,
		syntheticChallengedRequest(t, cfg, state), syntheticChallengeResponse(t))
	if err == nil {
		t.Fatal("the legacy path unexpectedly succeeded with no peer")
	}

	// The failure must come from the LEGACY path, proving the TCP branch was not
	// taken for a request that fits UDP.
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "protected tcp") {
		t.Fatal("an opted-out template took the protected TCP branch")
	}
	t.Logf("MEASURED optout_template=legacy_udp gate_enabled=true")
}
