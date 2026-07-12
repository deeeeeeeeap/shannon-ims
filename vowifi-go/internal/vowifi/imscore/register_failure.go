package imscore

import (
	"strings"

	"github.com/emiago/sipgo/sip"
)

type registerFailureOutcome struct {
	advanceRegistrar bool
	retryVariant     bool
	retryTransport   bool
	reason           string
}

// decideRegisterFailureOutcome maps an initial REGISTER failure to the next FSM step.
func decideRegisterFailureOutcome(cfg Config, statusCode int, reason string, variantIndex, variantTotal int, hasMoreRegistrar bool) registerFailureOutcome {
	out := registerFailureOutcome{reason: strings.TrimSpace(reason)}

	if shouldRetryInitialRegisterForStatus(cfg, statusCode) && variantIndex+1 < variantTotal {
		out.retryVariant = true
		out.reason = "initial_reject_fallback"
		return out
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