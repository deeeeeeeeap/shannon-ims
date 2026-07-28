package imscore

import (
	"context"
	"errors"
	"fmt"

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
}

func (e *safeRegisterFailureError) Error() string {
	return fmt.Sprintf("IMS REGISTER failed: status=%d result=%s", e.status, e.result)
}

func (e *safeRegisterFailureError) Unwrap() error {
	return e.cause
}

func newSafeRegisterFailure(err error) error {
	if err == nil {
		return nil
	}
	status := 0
	result := "network_failure"
	var attemptErr *registrarAttemptError
	switch {
	case errors.As(err, &attemptErr):
		status = attemptErr.statusCode
		result = canonicalRegisterDiagnosticResult(attemptErr.reason)
		if result == "unknown" {
			result = registerStatusResult(status)
		}
	case errors.Is(err, context.Canceled):
		result = "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		result = "no_sip_response"
	case registerErrorReachedAuthPhase(err):
		result = "auth_phase_reached"
	}
	return &safeRegisterFailureError{
		cause:  err,
		status: status,
		result: canonicalRegisterDiagnosticResult(result),
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
