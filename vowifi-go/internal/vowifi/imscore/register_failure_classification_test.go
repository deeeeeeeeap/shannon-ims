package imscore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// A failure report has one job: say enough that the next step is obvious.
//
// These tests exist because a real 310/240 failure reported
//
//	IMS REGISTER failed: status=0 result=network_failure
//
// while the actual cause, still present in the wrapped error, was
//
//	protected phase failed (stage=response): status=100 result=sip_response
//
// Every fact needed to act on it -- that authentication had succeeded, that IPsec
// was installed, that a SIP response had arrived, and what it said -- was thrown
// away by the classifier. "network_failure" then sent the investigation after the
// tunnel, which was working perfectly.
//
// status=0 must mean "no response arrived", not "we lost track of the response".

func TestPostAuthFailureIsNotReportedAsNetworkFailure(t *testing.T) {
	// Every post-auth stage: reaching any of these means the AKA vector was spent
	// and the registration got past the network entirely.
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
			cause := errors.New("status=100 result=sip_response")
			err := newSafeRegisterFailure(newProtectedPhaseError(stage, cause))
			text := err.Error()

			if strings.Contains(text, "network_failure") {
				t.Errorf("post-auth failure reported as a network fault: %s", text)
			}
			if !strings.Contains(text, "auth_phase_reached") {
				t.Errorf("report does not say authentication had succeeded: %s", text)
			}
		})
	}
}

func TestReadDeadlineIsReportedAsNoSipResponse(t *testing.T) {
	// SetReadDeadline yields os.ErrDeadlineExceeded, not context.DeadlineExceeded.
	// Only checking the context sentinel classified a plain read timeout -- the one
	// case where "no response arrived" is literally true -- as network_failure.
	err := newSafeRegisterFailure(fmt.Errorf("register response timeout: %w", os.ErrDeadlineExceeded))
	text := err.Error()

	if !strings.Contains(text, "no_sip_response") {
		t.Errorf("read timeout should report no_sip_response, got: %s", text)
	}
	if strings.Contains(text, "network_failure") {
		t.Errorf("read timeout misreported as a network fault: %s", text)
	}
}

func TestContextDeadlineStillReportsNoSipResponse(t *testing.T) {
	// The pre-existing behaviour must not regress while fixing the os sentinel.
	err := newSafeRegisterFailure(fmt.Errorf("dial: %w", context.DeadlineExceeded))
	if !strings.Contains(err.Error(), "no_sip_response") {
		t.Errorf("context deadline should still report no_sip_response, got: %s", err.Error())
	}
}

func TestGenuineNetworkFaultsStillReportNetworkFailure(t *testing.T) {
	// The fallback has to keep working for what it was meant for: a failure with no
	// SIP response, no deadline, and no evidence of having reached authentication.
	for _, cause := range []error{
		errors.New("dial tcp: connect: no route to host"),
		errors.New("imscore: protected channel owner is unavailable"),
	} {
		err := newSafeRegisterFailure(cause)
		if !strings.Contains(err.Error(), "network_failure") {
			t.Errorf("genuine network fault should report network_failure, got: %s", err.Error())
		}
	}
}

func TestSipResponseFailuresKeepTheirStatusCode(t *testing.T) {
	// A response that arrived and was understood must be reported with its code, so
	// a 403 is never confused with an unreachable peer.
	err := newSafeRegisterFailure(&registrarAttemptError{
		statusCode: 403,
		reason:     "forbidden",
	})
	text := err.Error()
	if !strings.Contains(text, "status=403") {
		t.Errorf("lost the SIP status code: %s", text)
	}
	if strings.Contains(text, "network_failure") {
		t.Errorf("a 403 was reported as a network fault: %s", text)
	}
}

func TestCancellationIsDistinctFromFailure(t *testing.T) {
	// A user-initiated stop is not a fault; conflating them makes shutdown look
	// like an outage in the logs.
	err := newSafeRegisterFailure(fmt.Errorf("aborted: %w", context.Canceled))
	if !strings.Contains(err.Error(), "canceled") {
		t.Errorf("cancellation should report canceled, got: %s", err.Error())
	}
}

func TestFailureReportNeverLeaksSipContent(t *testing.T) {
	// The report is safe to log, so a cause carrying identifiers or raw SIP must not
	// reach the message. Only the closed-enum result and the numeric status may.
	cause := errors.New("REGISTER sip:ims.mnc240.mcc310.3gppnetwork.org SIP/2.0\r\n" +
		"Authorization: Digest username=\"310240123456789@ims.mnc240.mcc310\"")
	text := newSafeRegisterFailure(newProtectedPhaseError(protectedPhaseStageResponse, cause)).Error()

	for _, leak := range []string{"310240123456789", "Authorization", "Digest", "REGISTER sip:"} {
		if strings.Contains(text, leak) {
			t.Errorf("failure report leaked %q: %s", leak, text)
		}
	}
}
