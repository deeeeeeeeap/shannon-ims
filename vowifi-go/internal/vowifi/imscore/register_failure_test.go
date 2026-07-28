package imscore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

func TestRegisterTransportDeadlineFallsBackButCancellationStops(t *testing.T) {
	for name, err := range map[string]error{
		"candidate deadline": context.DeadlineExceeded,
		"EOF":                io.EOF,
		"connection failure": fmt.Errorf("synthetic connection failure"),
	} {
		t.Run(name, func(t *testing.T) {
			if !shouldRetryNextRegisterTransport(0, err, 0, 2, false) {
				t.Fatal("failure without SIP response must try the next transport")
			}
		})
	}
	if shouldRetryNextRegisterTransport(0, context.Canceled, 0, 2, false) {
		t.Fatal("lifecycle cancellation must not try the next transport")
	}
	if shouldAdvanceRegistrarForProbeError(context.Canceled, true) {
		t.Fatal("lifecycle cancellation must not try the next registrar candidate")
	}
}

func TestVodafoneUKSecurityMechanismProbeAdvancesOnlyOnBadRequest(t *testing.T) {
	cfg := Config{CarrierBehavior: policy.ResolveCarrierBehavior("234", "15")}
	tests := []struct {
		name       string
		statusCode int
		wantRetry  bool
	}{
		{name: "bad request", statusCode: 400, wantRetry: true},
		{name: "extension required", statusCode: 421, wantRetry: false},
		{name: "forbidden", statusCode: 403, wantRetry: false},
		{name: "unauthorized", statusCode: 401, wantRetry: false},
		{name: "proxy auth required", statusCode: 407, wantRetry: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome := decideRegisterFailureOutcome(cfg, tt.statusCode, "rejected", 0, 6, false)
			if outcome.retryVariant != tt.wantRetry {
				t.Fatalf("status %d retryVariant = %v, want %v", tt.statusCode, outcome.retryVariant, tt.wantRetry)
			}
		})
	}
}

func TestGenericRepeatedBadRequestExhaustsVariantsWithoutRawReason(t *testing.T) {
	cfg := Config{CarrierBehavior: policy.Default3GPPBehavior()}
	outcome := decideRegisterFailureOutcome(cfg, sip.StatusBadRequest, "synthetic raw reason", 1, 2, false)
	if outcome.retryVariant {
		t.Fatal("final generic variant retried after repeated 400")
	}
	if outcome.reason != "initial_variants_exhausted_after_bad_request" {
		t.Fatal("repeated 400 did not return the bounded failure classification")
	}
}

func TestRegistrarAttemptErrorDoesNotExposeRawReason(t *testing.T) {
	err := (&registrarAttemptError{
		statusCode: sip.StatusBadRequest,
		reason:     "synthetic-private-marker",
	}).Error()
	if strings.Contains(err, "synthetic-private-marker") {
		t.Fatal("registrar attempt error exposed its raw reason")
	}
}

func TestSafeRegisterFailurePreservesCauseWithoutExposingText(t *testing.T) {
	cause := errors.New("synthetic-private-marker")
	err := newSafeRegisterFailure(cause)
	if !errors.Is(err, cause) {
		t.Fatal("safe REGISTER failure did not preserve its cause")
	}
	if strings.Contains(err.Error(), "synthetic-private-marker") {
		t.Fatal("safe REGISTER failure exposed its raw cause")
	}
	if !strings.Contains(err.Error(), "result=network_failure") {
		t.Fatal("safe REGISTER failure lost its bounded classification")
	}
}

func TestGenericSecAgree421RejectsMissingOrAdditionalExtensions(t *testing.T) {
	cfg := Config{CarrierBehavior: policy.Default3GPPBehavior()}
	variant := initialRegisterVariants(cfg)[1]
	tests := []struct {
		name    string
		require []string
		want    string
	}{
		{name: "missing", want: "sec_agree_challenge_invalid"},
		{name: "other extension", require: []string{"synthetic-extension"}, want: "sec_agree_challenge_invalid"},
		{name: "mixed extensions", require: []string{"sec-agree,synthetic-extension"}, want: "sec_agree_challenge_invalid"},
		{name: "duplicate", require: []string{"sec-agree", "sec-agree"}, want: "sec_agree_challenge_invalid"},
		{name: "exact sec-agree", require: []string{"sec-agree"}, want: "sec_agree_equivalent_variant_already_rejected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := sip.NewResponse(sip.StatusExtensionRequired, "Extension Required")
			for _, value := range tt.require {
				res.AppendHeader(sip.NewHeader("Require", value))
			}
			decision := decideInitialRegisterSecAgreeChallenge(cfg, variant, 1, res)
			if decision.retry {
				t.Fatal("invalid or equivalent 421 triggered another REGISTER")
			}
			if decision.reason != tt.want {
				t.Fatal("421 classification mismatch")
			}
		})
	}
}

func TestBadRequestDoesNotRetryNextRegisterTransport(t *testing.T) {
	err := &registrarAttemptError{
		pcscf:      "10.0.0.1:5060",
		statusCode: 400,
		reason:     "Bad Request",
	}
	if shouldRetryNextRegisterTransport(400, err, 0, 2, false) {
		t.Fatalf("400 with registrarAttemptError should not retry next transport")
	}
	if shouldRetryNextRegisterTransport(400, fmt.Errorf("unexpected initial REGISTER response: 400 Bad Request"), 0, 2, false) {
		t.Fatalf("400 with non-nil err should not retry next transport when status is known")
	}
	if shouldRetryNextRegisterTransport(0, fmt.Errorf("authenticated REGISTER failed: 400 Bad Request"), 0, 2, false) {
		t.Fatalf("authenticated REGISTER failure must not be misclassified as a transport probe failure")
	}
	if !shouldRetryNextRegisterTransport(0, fmt.Errorf("connection reset"), 0, 2, false) {
		t.Fatalf("transport/connection errors without SIP status should still retry next transport")
	}
	for _, status := range []int{400, 403, 408, 421, 500, 502, 503, 504} {
		if shouldRetryNextRegisterTransport(status, nil, 0, 2, false) {
			t.Fatalf("explicit SIP status %d must not retry next transport", status)
		}
		if shouldAdvanceRegistrarForNextRetry(status, "synthetic reason", true) {
			t.Fatalf("explicit SIP status %d must not advance registrar candidate", status)
		}
	}
}

func TestRegisterResponseHeaderNamesPreservesWireOrderWithoutValues(t *testing.T) {
	res := sip.NewResponse(sip.StatusExtensionRequired, "Extension Required")
	res.AppendHeader(sip.NewHeader("Via", "SIP/2.0/UDP example.invalid"))
	res.AppendHeader(sip.NewHeader("Require", "sec-agree"))
	res.AppendHeader(sip.NewHeader("X-Vodafone-Extension", "sensitive-value"))
	res.AppendHeader(sip.NewHeader("Content-Length", "0"))

	want := []string{"Via", "Require", "X-Vodafone-Extension", "Content-Length"}
	if got := registerResponseHeaderNames(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("header names = %v, want %v", got, want)
	}
}
