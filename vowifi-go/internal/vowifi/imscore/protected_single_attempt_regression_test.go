package imscore

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/emiago/sipgo/sip"
)

// Phase G step 3: one operation must produce exactly one initial REGISTER, one
// AKA run, and one protected send.
//
// This is the regression for the 2026-07-27 21:48 live run, where a single
// VoWiFi start produced TWO of each:
//
//	21:48:21  initial REGISTER (udp) -> 401 -> AKA -> IPsec -> protected send
//	21:48:28  protected read timeout, transport_retry
//	21:48:29  initial REGISTER (tcp) -> 401 -> AKA -> IPsec -> protected send
//	21:48:35  protected read timeout, register_failed
//
// The second pass consumed a second USIM authentication vector. TS 33.102
// clause 6.3.3 advances SQN per vector, so a retry that re-runs AKA moves the
// card toward a resync the network never requested. TS 24.229 clause 5.1.1.5.1
// is explicit that an unanswered protected REGISTER means the registration
// FAILED - not that another transport should be tried.
//
// The tests below count decisions rather than packets, because the decision is
// what the code controls. Each asserts on the guards that the outer loop
// consults, at the same inputs the live run produced.
//
// Assertions are counts, booleans and closed enums. No SIP text, identity,
// address, port value, SPI or key material appears here.

// ---------------------------------------------------------------------------
// G3.1: the transport loop stops after a post-authentication failure
// ---------------------------------------------------------------------------

// registerTransportCandidates returns two modes for the 3gpp-default template,
// so the loop CAN iterate twice. What must stop it is the typed failure, not a
// shorter candidate list - shortening the list would also break the legitimate
// pre-authentication probe.
func TestSingleOperationRunsOneTransportPassAfterAuthentication(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	modes := registerTransportCandidates(cfg, "")
	if len(modes) < 2 {
		t.Fatalf("the template offers %d transports; this regression needs at least 2", len(modes))
	}

	// Simulate the loop: mode 0 fails in the protected phase.
	protectedFailure := newProtectedPhaseError(
		protectedPhaseStageRead, errors.New("no response"))

	passes := 1
	for modeIndex := 0; modeIndex < len(modes); modeIndex++ {
		if !shouldRetryNextRegisterTransport(0, protectedFailure, modeIndex, len(modes), false) {
			break
		}
		passes++
	}
	if passes != 1 {
		t.Fatalf("one operation ran %d transport passes, want exactly 1", passes)
	}

	// The same loop with a PRE-authentication failure must still probe the second
	// transport, or the existing UDP->TCP behaviour is lost.
	preAuthFailure := errors.New("register transport probe: i/o timeout")
	preAuthPasses := 1
	for modeIndex := 0; modeIndex < len(modes); modeIndex++ {
		if !shouldRetryNextRegisterTransport(0, preAuthFailure, modeIndex, len(modes), false) {
			break
		}
		preAuthPasses++
	}
	if preAuthPasses != len(modes) {
		t.Fatalf("pre-authentication probing ran %d passes, want %d", preAuthPasses, len(modes))
	}

	t.Logf("MEASURED transports_offered=%d postauth_passes=1 preauth_passes=%d",
		len(modes), preAuthPasses)
}

// ---------------------------------------------------------------------------
// G3.2: the candidate loop stops too
// ---------------------------------------------------------------------------

// A second candidate means a second initial REGISTER, so the same guard must
// hold there. The live run had 6 candidates available.
func TestSingleOperationRunsOneCandidateAfterAuthentication(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	candidates := resolveRegisterAttemptCandidates(cfg, "udp")
	if len(candidates) == 0 {
		t.Skip("no candidates resolved for this synthetic config")
	}

	protectedFailure := newProtectedPhaseError(
		protectedPhaseStageSend, errors.New("write failed"))

	attempts := 1
	for i := 0; i < len(candidates); i++ {
		hasMore := i+1 < len(candidates)
		if !shouldAdvanceRegistrarForProbeError(protectedFailure, hasMore) {
			break
		}
		attempts++
	}
	if attempts != 1 {
		t.Fatalf("one operation attempted %d candidates, want exactly 1", attempts)
	}
	t.Logf("MEASURED candidates_available=%d postauth_attempts=1", len(candidates))
}

// ---------------------------------------------------------------------------
// G3.3: every protected stage is covered
// ---------------------------------------------------------------------------

// A failure at ANY stage from the challenge onward has already spent the
// authentication vector, so each must stop both loops. A stage missing from the
// typed set would silently restore the double-AKA behaviour.
func TestEveryPostAuthenticationStageProducesOneAttempt(t *testing.T) {
	stages := []string{
		protectedPhaseStageIPSecInstall,
		protectedPhaseStageRuntime,
		protectedPhaseStageActivation,
		protectedPhaseStageHandshake,
		protectedPhaseStageSend,
		protectedPhaseStageRead,
		protectedPhaseStageResponse,
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			err := newProtectedPhaseError(stage, errors.New("failed"))
			if shouldRetryNextRegisterTransport(0, err, 0, 2, false) {
				t.Fatal("this stage still allows a second transport pass")
			}
			if shouldAdvanceRegistrarForProbeError(err, true) {
				t.Fatal("this stage still allows a second candidate")
			}
			// Wrapping is what the register flow actually does, so the guard must
			// survive it.
			wrapped := errors.Join(errors.New("candidate 1"), err)
			if shouldRetryNextRegisterTransport(0, wrapped, 0, 2, false) {
				t.Fatal("wrapping restored the second transport pass")
			}
		})
	}
	t.Logf("MEASURED stages_covered=%d retries_allowed=0", len(stages))
}

// ---------------------------------------------------------------------------
// G3.4: the timeout shape specifically
// ---------------------------------------------------------------------------

// The live failure was a read timeout, and a timeout is the one shape most
// likely to be mistaken for a transport problem: the substring "timeout" appears
// in its text and the candidate guard matches on exactly that word. This pins
// the ordering fix.
func TestProtectedReadTimeoutIsNotTreatedAsTransportProblem(t *testing.T) {
	// The text deliberately contains every word the legacy matchers look for.
	hostile := errors.New("i/o timeout: deadline exceeded, register response timeout")
	typed := newProtectedPhaseError(protectedPhaseStageRead, hostile)

	if shouldRetryNextRegisterTransport(0, typed, 0, 2, false) {
		t.Fatal("a protected read timeout still triggers a transport retry")
	}
	if shouldAdvanceRegistrarForProbeError(typed, true) {
		t.Fatal("a protected read timeout still advances the candidate")
	}

	// The identical text, untyped, must still be treated as a pre-authentication
	// probe failure. Same bytes, different classification: that is the proof the
	// fix is structural and not a new substring rule.
	if !shouldRetryNextRegisterTransport(0, hostile, 0, 2, false) {
		t.Fatal("an untyped probe timeout no longer retries the transport")
	}
	if !shouldAdvanceRegistrarForProbeError(hostile, true) {
		t.Fatal("an untyped probe timeout no longer advances the candidate")
	}

	t.Logf("MEASURED same_text_typed_blocked=true same_text_untyped_allowed=true")
}

// ---------------------------------------------------------------------------
// G3.5: the AKA vector is requested once
// ---------------------------------------------------------------------------

// The cost of the defect was a second authentication vector, so the protected
// path must never compute one it does not need.
//
// register.go:363 states the rule: buildAuthenticatedRegister REUSES the
// Authorization already on the challenged request and only computes a fresh one
// when there is none. Both halves are asserted here, because only the pair is
// meaningful:
//
//   - with an Authorization present, the card is not touched at all;
//   - without one, the card is touched exactly once - never twice.
//
// An earlier version of this test asserted only the first half while cfg.AKA was
// nil, so every "no extra vector" claim compared zero against zero and would
// have passed even if the path had burned a vector on every call.
func TestProtectedTCPPathConsumesOneAuthenticationVector(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	counting := &countingAKAProvider{inner: countingAKAFixture()}
	cfg.AKA = counting

	state := syntheticProtectedRegisterState(cfg)
	if err := installIPSecFromChallenge(cfg, state, syntheticChallengeResponse(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	challenge := syntheticAKAChallengeResponse(t)

	// --- Half 1: an Authorization is already present, so the card is not used.
	challenged := syntheticChallengedRequest(t, cfg, state)
	if challenged.GetHeader("Authorization") == nil {
		t.Fatal("the challenged request carries no Authorization; this half asserts reuse")
	}
	base, _, err := buildAuthenticatedRegister(cfg, *state, challenged, challenge)
	if err != nil {
		t.Fatalf("buildAuthenticatedRegister: %v", err)
	}
	if got := counting.calls(); got != 0 {
		t.Fatalf("reuse path consumed %d vectors, want 0", got)
	}

	// The final build and the UDP preview both work from that base. Neither may
	// reach for the card.
	if _, err := buildFinalProtectedRegisterRequest(cfg, *state, base, protectedTransportTCP); err != nil {
		t.Fatalf("buildFinalProtectedRegisterRequest: %v", err)
	}
	if _, err := previewProtectedRegisterUDPLen(cfg, *state, base); err != nil {
		t.Fatalf("previewProtectedRegisterUDPLen: %v", err)
	}
	if got := counting.calls(); got != 0 {
		t.Fatalf("final build plus preview consumed %d vectors, want 0", got)
	}

	// --- Half 2: no Authorization, so exactly one vector is computed.
	// This is what makes half 1 non-vacuous: the counter provably CAN move.
	fresh := syntheticChallengedRequest(t, cfg, state)
	// There can be MORE than one Authorization header: 3gpp-default sets
	// UsePlainDigestPlaceholder, so decorateRegisterRequest adds a placeholder and
	// the helper appends a second. sip.RemoveHeader drops one instance, so a single
	// call leaves one behind and buildAuthenticatedRegister still takes the reuse
	// branch - which is what made this half silently measure nothing.
	for fresh.GetHeader("Authorization") != nil {
		fresh.RemoveHeader("Authorization")
	}
	if fresh.GetHeader("Authorization") != nil {
		t.Fatal("Authorization survived removal; the compute path cannot be reached")
	}
	if _, _, err := buildAuthenticatedRegister(cfg, *state, fresh, challenge); err != nil {
		t.Fatalf("buildAuthenticatedRegister(no auth): %v", err)
	}
	computed := counting.calls()
	if computed != 1 {
		t.Fatalf("compute path consumed %d vectors, want exactly 1", computed)
	}

	t.Logf("MEASURED reuse_vectors=0 compute_vectors=1 final_build_extra=0 preview_extra=0")
}

// countingAKAProvider counts how many times the card is asked to compute a
// vector. It delegates so the values stay the ones the rest of the flow expects.
//
// It records a COUNT only. RAND, AUTN, RES, CK and IK are passed through and
// never stored or logged.
type countingAKAProvider struct {
	inner sim.AKAProvider

	mu sync.Mutex
	n  int
}

func (c *countingAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	if c.inner == nil {
		return sim.AKAResult{}, errors.New("no inner AKA provider")
	}
	return c.inner.CalculateAKA(rand16, autn16)
}

func (c *countingAKAProvider) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// syntheticAKAChallengeResponse is a 401 that carries BOTH a Security-Server
// offer and a WWW-Authenticate challenge whose nonce decodes to a full
// RAND || AUTN pair.
//
// The nonce length is load-bearing. computeAKAAuth rejects anything shorter than
// 32 raw bytes before it ever reaches the card, so a token nonce would make the
// AKA provider unreachable and every "no extra vector" assertion below would
// compare zero against zero. That is exactly the vacuous test this replaces.
//
// The bytes are a fixed pattern, not credential material: RAND is 0x01 repeated
// and AUTN is 0x02 repeated.
func syntheticAKAChallengeResponse(t *testing.T) *sip.Response {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		if i < 16 {
			raw[i] = 0x01
		} else {
			raw[i] = 0x02
		}
	}
	res := syntheticChallengeResponse(t)
	res.AppendHeader(sip.NewHeader("WWW-Authenticate", fmt.Sprintf(
		`Digest realm="ims.mnc240.mcc310.3gppnetwork.org",nonce="%s",algorithm=AKAv1-MD5,qop="auth"`,
		base64.StdEncoding.EncodeToString(raw))))
	return res
}

// countingAKAFixture is the fixed vector the counting provider delegates to. The
// values are constants, not secrets: CK and IK are needed only because
// installIPSecFromChallenge requires non-empty keys.
func countingAKAFixture() sim.AKAProvider {
	return fixedAKA{
		res: bytes.Repeat([]byte{0x03}, 8),
		ck:  bytes.Repeat([]byte{0x04}, 16),
		ik:  bytes.Repeat([]byte{0x05}, 16),
	}
}
