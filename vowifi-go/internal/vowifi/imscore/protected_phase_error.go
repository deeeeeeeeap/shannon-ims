package imscore

import "errors"

// Phase G step 1: a typed marker for "this registration already authenticated".
//
// The 2026-07-27 21:48 run showed why a typed marker is required. The protected
// TCP REGISTER timed out, and the outer transport loop treated that as a
// pre-authentication transport problem: it logged transport_retry and re-ran the
// entire flow on the next transport, producing a second initial REGISTER, a
// second 401, a second AKA run, a second IPsec install and a second protected
// send.
//
// shouldRetryNextRegisterTransport had three chances to recognise the
// authenticated phase and missed all three:
//
//	statusCode                    = 0     - a timeout carries no SIP status
//	reachedAuth                   = false - set only for *registrarAttemptError
//	registerErrorReachedAuthPhase = false - matches on message substrings, and
//	                                        the protected TCP error text contains
//	                                        none of them
//
// Widening that substring list would have been the wrong fix: every future error
// message on the protected path would have to remember to embed a magic phrase,
// and forgetting one reintroduces the same silent AKA re-run.
//
// Why re-running matters rather than being merely wasteful:
//
//   - Each AKA run consumes a USIM authentication vector and advances SQN
//     (TS 33.102 clause 6.3.3), moving the card toward a resync the network never
//     asked for.
//   - TS 24.229 clause 5.1.1.5.1: a protected REGISTER with no answer before the
//     temporary SA lifetime expires means the registration FAILED and the
//     temporary SAs must be deleted - not that another transport should be tried.
//   - TS 24.229 clause 5.1.1.2.1 forbids starting a new registration procedure
//     while one is ongoing.
//
// Stages are a closed enum. They name where in the protected exchange the failure
// happened and carry nothing else - no address, port, SPI, identity or SIP text.
const (
	// protectedPhaseStageIPSecInstall and everything after it are all AFTER the
	// 401 has been answered, so the authentication vector is already spent.
	protectedPhaseStageIPSecInstall = "ipsec_install"
	protectedPhaseStageRuntime      = "runtime"
	protectedPhaseStageActivation   = "activation"
	protectedPhaseStageHandshake    = "handshake"
	protectedPhaseStageSend         = "send"
	protectedPhaseStageRead         = "read"
	protectedPhaseStageResponse     = "response"
)

// protectedPhaseError marks a failure that happened after the registration
// reached the authenticated phase.
//
// It wraps its cause so a caller can still classify the underlying transport
// failure, while errors.As gives the outer loop an unambiguous answer to the only
// question it needs: may this be retried elsewhere? It may not.
type protectedPhaseError struct {
	stage string
	cause error
}

func newProtectedPhaseError(stage string, cause error) *protectedPhaseError {
	return &protectedPhaseError{stage: stage, cause: cause}
}

func (e *protectedPhaseError) Error() string {
	if e == nil {
		return ""
	}
	if e.cause == nil {
		return "imscore: protected phase failed (stage=" + e.stage + ")"
	}
	return "imscore: protected phase failed (stage=" + e.stage + "): " + e.cause.Error()
}

// Unwrap keeps the cause reachable for errors.Is and for transport
// classification further up.
func (e *protectedPhaseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Stage exposes the closed-enum stage for diagnostics.
func (e *protectedPhaseError) Stage() string {
	if e == nil {
		return ""
	}
	return e.stage
}

// registerReachedAuthenticatedPhase reports whether an error came from after the
// authentication vector was spent.
//
// It is deliberately type-based. A pre-authentication network failure - a refused
// dial, an i/o timeout probing a candidate - returns false, so the existing
// UDP->TCP probe fallback that this project relies on keeps working.
func registerReachedAuthenticatedPhase(err error) bool {
	if err == nil {
		return false
	}
	var phase *protectedPhaseError
	return errors.As(err, &phase)
}
