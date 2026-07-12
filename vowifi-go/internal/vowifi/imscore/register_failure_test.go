package imscore

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/emiago/sipgo/sip"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

func TestVodafoneUKSecurityMechanismProbeAdvancesOnlyOnBadRequest(t *testing.T) {
	cfg := Config{Template: policy.VodafoneUKTemplate()}
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
	if !shouldRetryNextRegisterTransport(503, nil, 0, 2, false) {
		t.Fatalf("temporary SIP failures should still retry next transport")
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
