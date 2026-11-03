package imscore

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/emiago/sipgo/sip"
)

type registerFailureOutcome struct {
	advanceRegistrar bool
	retryVariant     bool
	retryTransport   bool
	reason           string
}

type safeRegisterFailureError struct {
	cause  error
	status int
	result string
	// stage names the post-auth step that failed, empty when the failure happened
	// before authentication. Always a closed-enum value -- see
	// canonicalProtectedPhaseStage -- because this string is logged.
	stage string
}

func (e *safeRegisterFailureError) Error() string {
	if e.stage != "" {
		return fmt.Sprintf("IMS REGISTER failed: status=%d result=%s stage=%s", e.status, e.result, e.stage)
	}
	return fmt.Sprintf("IMS REGISTER failed: status=%d result=%s", e.status, e.result)
}

// Stage exposes the failing post-auth stage for diagnostics.
func (e *safeRegisterFailureError) Stage() string {
	if e == nil {
		return ""
	}
	return e.stage
}

func (e *safeRegisterFailureError) Unwrap() error {
	return e.cause
}

// Preserve the protocol phase independently of the status/cause. A protected
// failure may still be a cancellation, a deadline, or an explicit SIP rejection.
func newSafeRegisterFailure(err error) error {
	if err == nil {
		return nil
	}
	return classifyRegisterFailure(err)
}

func classifyRegisterFailure(err error) *safeRegisterFailureError {
	status := 0
	result := "network_failure"
	stage := ""

	var attemptErr *registrarAttemptError
	var phaseErr *protectedPhaseError
	if errors.As(err, &phaseErr) {
		stage = phaseErr.Stage()
	}
	switch {
	case errors.As(err, &attemptErr):
		status = attemptErr.statusCode
		result = canonicalRegisterDiagnosticResult(attemptErr.reason)
		if result == "unknown" {
			result = registerStatusResult(status)
		}
	case errors.Is(err, context.Canceled):
		result = "canceled"
	// Both deadline sentinels: context cancellation and socket read deadlines are
	// separate error values and either one means the same thing to a reader.
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		result = "no_sip_response"
	case phaseErr != nil || registerErrorReachedAuthPhase(err):
		result = "auth_phase_reached"
	}
	return &safeRegisterFailureError{
		cause:  err,
		status: status,
		result: canonicalRegisterDiagnosticResult(result),
		stage:  canonicalProtectedPhaseStage(stage),
	}
}

// decideRegisterFailureOutcome maps an initial REGISTER failure to the next FSM step.
func decideRegisterFailureOutcome(cfg Config, statusCode int, reason string, variantIndex, variantTotal int, hasMoreRegistrar bool) registerFailureOutcome {
	_ = reason
	out := registerFailureOutcome{reason: registerStatusResult(statusCode)}

	if shouldRetryInitialRegisterForStatus(cfg, statusCode) {
		if variantIndex+1 < variantTotal {
			out.retryVariant = true
			out.reason = "initial_reject_fallback"
			return out
		}
		if statusCode == sip.StatusBadRequest && cfg.CarrierBehavior.RegisterTemplate.RetryInitialWithoutRequiredSecAgreeOnBadRequest {
			out.reason = "initial_variants_exhausted_after_bad_request"
			return out
		}
	}

	if shouldAdvanceRegistrarForNextRetry(statusCode, reason, hasMoreRegistrar) {
		out.advanceRegistrar = true
		out.reason = "registrar_candidate_rejected"
		return out
	}

	if statusCode == 0 && hasMoreRegistrar {
		out.advanceRegistrar = true
		out.reason = "registrar_probe_timeout"
		return out
	}

	return out
}

func isForbiddenRegisterSIPResponse(code int) bool {
	return code == sip.StatusForbidden
}

func isTemporaryRegisterSIPResponse(code int) bool {
	switch code {
	case sip.StatusRequestTimeout,
		sip.StatusInternalServerError,
		sip.StatusBadGateway,
		sip.StatusServiceUnavailable,
		sip.StatusGatewayTimeout,
		sip.StatusTemporarilyUnavailable:
		return true
	default:
		return false
	}
}
