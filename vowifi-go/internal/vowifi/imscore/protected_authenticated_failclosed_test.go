package imscore

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
)

type invalidIPSecKeysAKA struct{}

func (*invalidIPSecKeysAKA) CalculateAKA([]byte, []byte) (sim.AKAResult, error) {
	return sim.AKAResult{
		RES: make([]byte, 8),
		CK:  []byte{1},
		IK:  []byte{2},
	}, nil
}

// Phase G step 1: once a registration has reached the authenticated phase, a
// protected failure must NOT be retried on another transport or candidate.
//
// The 2026-07-27 21:48 run showed the defect end to end. The protected TCP
// REGISTER timed out at 21:48:28, and instead of failing the registration the
// outer loop logged transport_retry and ran the WHOLE flow again on TCP: a
// second initial REGISTER, a second 401, a second AKA run, a second IPsec
// install, and a second protected send at 21:48:30.
//
// Why that is not a cosmetic retry:
//
//   - It consumes a second USIM authentication vector. TS 33.102 clause 6.3.3
//     advances SQN per vector, so burning vectors on retries moves the card
//     toward a resync the network did not ask for.
//   - TS 24.229 clause 5.1.1.5.1 says a protected REGISTER that gets no answer
//     before the temporary SA lifetime expires means the registration FAILED and
//     the temporary SAs must be deleted - not that another transport should be
//     tried.
//   - TS 24.229 clause 5.1.1.2.1 forbids a new registration procedure until the
//     ongoing one has a final response or has timed out.
//
// The root cause is that shouldRetryNextRegisterTransport cannot see the
// authenticated phase in this path:
//
//	statusCode                    = 0     (timeout, no SIP response)
//	reachedAuth                   = false (set only for *registrarAttemptError)
//	registerErrorReachedAuthPhase = false (string match, and the protected TCP
//	                                      error text contains none of its markers)
//
// so it falls through to `return true`.
//
// A string-matching guard is the wrong fix: every new error message on the path
// would have to remember to include a magic substring. These tests demand a
// typed, explicit signal instead.
//
// Assertions are booleans, counts and closed enums. No SIP text, identity,
// address, port value, SPI or key material appears here.

// ---------------------------------------------------------------------------
// G1.1: the typed signal
// ---------------------------------------------------------------------------

// A protected-phase failure must be recognisable as post-authentication without
// matching on its message text.
func TestProtectedPhaseFailureIsTypedNotStringMatched(t *testing.T) {
	inner := errors.New("read timeout")
	err := newProtectedPhaseError(protectedPhaseStageSend, inner)

	if !registerReachedAuthenticatedPhase(err) {
		t.Fatal("a protected-phase error is not recognised as post-authentication")
	}
	// The wrapped cause must survive, so callers can still classify the transport
	// failure underneath.
	if !errors.Is(err, inner) {
		t.Fatal("the protected-phase error dropped its cause")
	}

	// Wrapping must not defeat the check: the register flow adds context.
	wrapped := fmt.Errorf("candidate 1: %w", err)
	if !registerReachedAuthenticatedPhase(wrapped) {
		t.Fatal("wrapping defeated the post-authentication check")
	}

	// The decisive property: recognition must not depend on the message. An error
	// whose text says nothing about authentication must still be recognised.
	opaque := newProtectedPhaseError(protectedPhaseStageSend, errors.New("xyzzy"))
	if !registerReachedAuthenticatedPhase(opaque) {
		t.Fatal("recognition depends on the error text")
	}

	// And a genuine pre-authentication network error must NOT be recognised, or
	// the UDP->TCP probe fallback would be lost.
	for _, pre := range []error{
		errors.New("dial tcp: connection refused"),
		errors.New("i/o timeout"),
		context.DeadlineExceeded,
	} {
		if registerReachedAuthenticatedPhase(pre) {
			t.Fatalf("a pre-authentication error was treated as post-authentication")
		}
	}
	t.Logf("MEASURED typed=true text_independent=true preauth_unaffected=true")
}

// Every stage at or after the challenge must be covered, since each one has
// already consumed the authentication vector.
func TestProtectedPhaseStagesAllBlockFallback(t *testing.T) {
	for _, stage := range []string{
		protectedPhaseStageIPSecInstall,
		protectedPhaseStageRuntime,
		protectedPhaseStageActivation,
		protectedPhaseStageHandshake,
		protectedPhaseStageSend,
		protectedPhaseStageRead,
		protectedPhaseStageResponse,
	} {
		t.Run(stage, func(t *testing.T) {
			err := newProtectedPhaseError(stage, errors.New("boom"))
			if !registerReachedAuthenticatedPhase(err) {
				t.Fatalf("stage %q does not block fallback", stage)
			}
			if shouldRetryNextRegisterTransport(0, err, 0, 2, false) {
				t.Fatalf("stage %q still allows a transport retry", stage)
			}
		})
	}
	t.Logf("MEASURED protected_stages_blocking=7")
}

// ---------------------------------------------------------------------------
// G1.2: the transport decision at the real entry
// ---------------------------------------------------------------------------

// This is the exact input combination the live run produced. It must not retry.
func TestLiveRunInputCombinationDoesNotRetryTransport(t *testing.T) {
	// statusCode=0 (no SIP response), reachedAuth=false (not a registrarAttemptError),
	// modeIndex=0 of 2 (udp then tcp) - the shape that produced the 21:48:28 retry.
	protectedErr := newProtectedPhaseError(
		protectedPhaseStageRead, errors.New("connection ended mid-message"))

	if shouldRetryNextRegisterTransport(0, protectedErr, 0, 2, false) {
		t.Fatal("the live-run input combination still retries the next transport")
	}

	// The same shape BEFORE authentication must still retry, or we would break the
	// existing UDP->TCP probe that this project relies on.
	preAuthErr := errors.New("register transport probe: i/o timeout")
	if !shouldRetryNextRegisterTransport(0, preAuthErr, 0, 2, false) {
		t.Fatal("a pre-authentication probe failure no longer retries")
	}
	t.Logf("MEASURED postauth_retry=false preauth_retry=true")
}

// A protected failure must also stop candidate advancement, for the same reason:
// a new candidate means a new initial REGISTER and a new AKA run.
func TestProtectedPhaseFailureStopsCandidateAdvancement(t *testing.T) {
	protectedErr := newProtectedPhaseError(
		protectedPhaseStageSend, errors.New("no response"))

	if shouldAdvanceRegistrarForProbeError(protectedErr, true) {
		t.Fatal("a protected-phase failure still advances to the next registrar")
	}

	// The decisive pairing: the SAME word that the substring matcher looks for.
	// "register response timeout" is on that matcher's allow-list, so a
	// pre-authentication error carrying it must still advance...
	preAuth := errors.New("register response timeout")
	if !shouldAdvanceRegistrarForProbeError(preAuth, true) {
		t.Fatal("a pre-authentication probe timeout no longer advances the registrar")
	}
	// ...while the same text wrapped in a protected-phase error must not. This is
	// what proves the type guard runs BEFORE the substring matching rather than
	// relying on the two texts happening to differ.
	sameTextPostAuth := newProtectedPhaseError(protectedPhaseStageRead, preAuth)
	if shouldAdvanceRegistrarForProbeError(sameTextPostAuth, true) {
		t.Fatal("identical text advanced the registrar once typed as post-authentication")
	}
	t.Logf("MEASURED postauth_candidate_advance=false preauth_advance=true same_text_discriminated=true")
}

// ---------------------------------------------------------------------------
// G1.3: the protected TCP path returns the typed error
// ---------------------------------------------------------------------------

// The path must classify its own failures, otherwise the guard above never sees
// them. This drives the real function with a dataplane that cannot connect.
func TestProtectedTCPPathReturnsTypedPhaseError(t *testing.T) {
	withProtectedTCPEnabled(t)
	cfg, state, _ := runtimeTestStateWithProtectedChannel(t)

	challenge := syntheticChallengeResponse(t)
	challenged := syntheticChallengedRequest(t, cfg, state)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	dialer := &countingCarrierDialer{}
	result, handled, err := runProtectedTCPAuthenticatedRegister(
		ctx, cfg, dialer, state, challenged, challenge)

	if result != nil {
		t.Fatal("a failed protected TCP attempt returned a result")
	}
	if !handled {
		t.Fatal("the protected TCP path disowned a TCP decision")
	}
	if err == nil {
		t.Fatal("the protected TCP path reported success without a peer")
	}
	// The decisive assertion: the failure is typed, so the outer loop cannot
	// mistake it for a pre-authentication transport problem.
	if !registerReachedAuthenticatedPhase(err) {
		t.Fatalf("the protected TCP failure is not typed as post-authentication: %v", err)
	}
	if shouldRetryNextRegisterTransport(0, err, 0, 2, false) {
		t.Fatal("the protected TCP failure would still trigger a transport retry")
	}
	if openErr := state.channel.OpenUDP(newRuntimeCarrier()); openErr == nil {
		t.Fatal("the failed TCP attempt left its provisional channel reusable")
	}
	t.Logf("MEASURED typed_failure=true retry=false handled=true")
}

func runtimeTestStateWithProtectedChannel(t *testing.T) (Config, *registerState, *ipsec3gpp.ProtectedChannelOwner) {
	t.Helper()
	cfg := syntheticProtectedRegisterConfig()
	owner := ipsec3gpp.NewProtectedChannelOwner()
	t.Cleanup(func() { _ = owner.Close() })
	channel, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve protected channel: %v", err)
	}
	state := syntheticProtectedRegisterState(t, cfg)
	state.spiC = channel.ClientSPI()
	state.spiS = channel.ServerSPI()
	state.portC = channel.ClientPort()
	state.portS = channel.ServerPort()
	state.generation = channel.Generation()
	state.channel = channel
	if err := installIPSecFromChallenge(cfg, state, syntheticChallengeResponse(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	return cfg, state, owner
}

func TestProtectedTCPPreparationFailureDoesNotFallBackToLegacyUDP(t *testing.T) {
	withProtectedTCPEnabled(t)
	cfg, state, _ := runtimeTestStateWithProtectedChannel(t)
	cfg.ProtectedTransport = "auto"
	dialer := &countingCarrierDialer{}

	result, err := runSecureAuthenticatedRegister(
		context.Background(),
		cfg,
		dialer,
		state,
		nil,
		syntheticChallengeResponse(t),
	)
	if err == nil {
		t.Fatal("protected preparation unexpectedly succeeded")
	}
	if result != nil {
		t.Fatal("protected preparation failure returned a result")
	}
	if got := dialer.dials.Load(); got != 0 {
		t.Fatalf("raw dials = %d, want 0: preparation failure fell back to legacy UDP", got)
	}
	if !registerReachedAuthenticatedPhase(err) {
		t.Fatal("protected preparation failure was not typed as post-auth")
	}
}

func TestIPSecInstallFailureIsTypedAsPostAuthentication(t *testing.T) {
	nonce := base64.StdEncoding.EncodeToString(make([]byte, 32))
	network := &registerSessionTestNetwork{}
	network.serve = func(peer net.Conn) {
		defer peer.Close()
		request, err := readRegisterSessionTestRequest(bufio.NewReader(peer))
		if err != nil {
			return
		}
		_ = writeRegisterSessionTestAKAChallenge(peer, request, nonce)
	}
	cfg := registerSessionTestConfig()
	cfg.AKA = &invalidIPSecKeysAKA{}
	session := newRegisterSession(cfg, nil, network, "udp", 0)

	_, err := session.runInitialRegisterFlow(context.Background())
	if err == nil {
		t.Fatal("IPsec installation unexpectedly succeeded with invalid key lengths")
	}
	if !registerReachedAuthenticatedPhase(err) {
		t.Fatal("IPsec installation failure was not typed as post-authentication")
	}
}
