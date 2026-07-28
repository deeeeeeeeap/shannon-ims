package imscore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	swulogger "github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

// Synthetic warn-agent and warn-text fragments. The wiring must never surface
// either of them, so the assertions below search every emitted field for them.
const (
	syntheticSessionWarnAgent = "warnagent.invalid:5060"
	syntheticSessionWarnText  = "zzsyntheticwarntextzz"
)

func syntheticSessionWarningValue(code string) string {
	return code + " " + syntheticSessionWarnAgent + ` "` + syntheticSessionWarnText + `"`
}

// writeForbiddenWithWarning answers a REGISTER with a synthetic 403 that carries
// the supplied Warning header values.
func writeForbiddenWithWarning(conn net.Conn, req *sip.Request, warnings ...string) error {
	res := sip.NewResponseFromRequest(req, sip.StatusForbidden, "Forbidden", nil)
	for _, warning := range warnings {
		res.AppendHeader(sip.NewHeader("Warning", warning))
	}
	_, err := io.WriteString(conn, res.String())
	return err
}

// initialResponseWarningEntries returns the warning metadata of every
// stage=initial_response diagnostic that was observed.
func initialResponseWarningEntries(t *testing.T, entries []observer.LoggedEntry) []map[string]zap.Field {
	t.Helper()
	out := make([]map[string]zap.Field, 0, 2)
	for _, entry := range entries {
		if !strings.Contains(entry.Message, "REGISTER") {
			continue
		}
		fields := map[string]zap.Field{}
		for _, field := range entry.Context {
			fields[field.Key] = field
		}
		stage, ok := fields["stage"]
		if !ok || stage.String != "initial_response" {
			continue
		}
		out = append(out, fields)
	}
	return out
}

// assertNoWarningMaterialLeaked proves no emitted field carries warn-agent,
// warn-text, or raw SIP fragments.
func assertNoWarningMaterialLeaked(t *testing.T, entries []observer.LoggedEntry) {
	t.Helper()
	for _, entry := range entries {
		for _, field := range entry.Context {
			value := field.String
			if value == "" {
				continue
			}
			for _, forbidden := range []string{
				syntheticSessionWarnText,
				syntheticSessionWarnAgent,
				"warnagent",
				"SIP/2.0",
				"REGISTER",
			} {
				if strings.Contains(value, forbidden) {
					t.Fatalf("diagnostic field %q leaked raw Warning or SIP material", field.Key)
				}
			}
		}
		if strings.Contains(entry.Message, syntheticSessionWarnText) {
			t.Fatal("diagnostic message leaked warn-text")
		}
	}
}

// runForbiddenWarningSession drives one bounded initial REGISTER against a
// synthetic registrar that answers 403 with the supplied Warning headers, and
// optionally repeats the response to model a duplicate or late answer.
func runForbiddenWarningSession(t *testing.T, duplicateResponse bool, warnings ...string) ([]observer.LoggedEntry, int, error) {
	t.Helper()

	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	type capture struct {
		requests int
		err      error
	}
	captureCh := make(chan capture, 1)
	network := &registerSessionTestNetwork{}
	network.serve = func(peer net.Conn) {
		defer peer.Close()
		observedCapture := capture{}
		defer func() { captureCh <- observedCapture }()

		reader := bufio.NewReader(peer)
		req, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			observedCapture.err = fmt.Errorf("read initial REGISTER: %w", err)
			return
		}
		observedCapture.requests++
		if err := writeForbiddenWithWarning(peer, req, warnings...); err != nil {
			observedCapture.err = fmt.Errorf("write 403: %w", err)
			return
		}
		if duplicateResponse {
			// A duplicate or late answer must not drive another classification.
			if err := writeForbiddenWithWarning(peer, req, warnings...); err != nil &&
				!errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
				observedCapture.err = fmt.Errorf("write duplicate 403: %w", err)
				return
			}
		}

		// Observe that the session does not send a second variant.
		if err := peer.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			return
		}
		if _, err := readRegisterSessionTestRequest(reader); err == nil {
			observedCapture.requests++
		}
	}

	cfg := registerSessionTestConfig()
	cfg.CarrierBehavior = policy.Default3GPPBehavior()
	session := newRegisterSession(cfg, nil, network, "udp", 0)
	session.jitter = false
	session.localPort = 41234

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, runErr := session.runInitialRegisterFlow(ctx)

	observedCapture := <-captureCh
	if observedCapture.err != nil {
		t.Fatal(observedCapture.err)
	}
	return observed.All(), observedCapture.requests, runErr
}

func TestForbiddenInitialResponseClassifiesWarningOnceAndFailsClosed(t *testing.T) {
	entries, requests, err := runForbiddenWarningSession(t, false, syntheticSessionWarningValue("399"))

	var attemptErr *registrarAttemptError
	if !errors.As(err, &attemptErr) {
		t.Fatal("403 with Warning did not fail closed")
	}
	if attemptErr.statusCode != sip.StatusForbidden {
		t.Fatalf("status = %d, want 403", attemptErr.statusCode)
	}
	if got := canonicalRegisterDiagnosticResult(attemptErr.reason); got != "forbidden" {
		t.Fatalf("result = %q, want forbidden", got)
	}
	if requests != 1 {
		t.Fatalf("REGISTER request count = %d, want 1; 403 must not send variant 2", requests)
	}

	initial := initialResponseWarningEntries(t, entries)
	if len(initial) != 1 {
		t.Fatalf("initial_response diagnostic count = %d, want exactly 1", len(initial))
	}
	fields := initial[0]
	if got := fields["status"].Integer; got != int64(sip.StatusForbidden) {
		t.Fatalf("status field = %d, want 403", got)
	}
	// zap encodes Bool fields into Integer as 1 or 0.
	if got := fields["warning_present"].Integer; got != 1 {
		t.Fatal("warning_present was not set from the real response")
	}
	if got := fields["warning_code"].Integer; got != 399 {
		t.Fatalf("warning_code = %d, want 399", got)
	}
	if got := fields["warning_count"].Integer; got != 1 {
		t.Fatalf("warning_count = %d, want 1", got)
	}
	if got := fields["warning_class"].String; got != registerWarningClassMiscellaneous {
		t.Fatalf("warning_class = %q, want miscellaneous", got)
	}
	if got := fields["warning_parse_result"].String; got != registerWarningParseKnown {
		t.Fatalf("warning_parse_result = %q, want known", got)
	}
	assertNoWarningMaterialLeaked(t, entries)

	// The registrar and transport gates must remain closed for 403.
	if shouldRetryNextRegisterTransport(sip.StatusForbidden, attemptErr, 0, 2, false) {
		t.Fatal("403 would retry the next transport")
	}
	if shouldAdvanceRegistrarForNextRetry(sip.StatusForbidden, attemptErr.reason, true) {
		t.Fatal("403 would advance the registrar candidate")
	}
}

func TestForbiddenDuplicateResponseDoesNotReclassifyWarning(t *testing.T) {
	entries, requests, err := runForbiddenWarningSession(t, true, syntheticSessionWarningValue("399"))

	var attemptErr *registrarAttemptError
	if !errors.As(err, &attemptErr) {
		t.Fatal("duplicated 403 did not fail closed")
	}
	if requests != 1 {
		t.Fatalf("REGISTER request count = %d, want 1", requests)
	}
	if initial := initialResponseWarningEntries(t, entries); len(initial) != 1 {
		t.Fatalf("initial_response diagnostic count = %d, want exactly 1", len(initial))
	}
	assertNoWarningMaterialLeaked(t, entries)
}

func TestForbiddenWithoutWarningReportsAbsentMetadata(t *testing.T) {
	entries, requests, err := runForbiddenWarningSession(t, false)

	var attemptErr *registrarAttemptError
	if !errors.As(err, &attemptErr) {
		t.Fatal("403 without Warning did not fail closed")
	}
	if requests != 1 {
		t.Fatalf("REGISTER request count = %d, want 1", requests)
	}
	initial := initialResponseWarningEntries(t, entries)
	if len(initial) != 1 {
		t.Fatalf("initial_response diagnostic count = %d, want exactly 1", len(initial))
	}
	fields := initial[0]
	if got := fields["warning_code"].Integer; got != 0 {
		t.Fatalf("warning_code = %d, want 0", got)
	}
	if got := fields["warning_count"].Integer; got != 0 {
		t.Fatalf("warning_count = %d, want 0", got)
	}
	if got := fields["warning_class"].String; got != registerWarningClassUnknown {
		t.Fatalf("warning_class = %q, want unknown", got)
	}
	if got := fields["warning_parse_result"].String; got != registerWarningParseAbsent {
		t.Fatalf("warning_parse_result = %q, want absent", got)
	}
}

func TestForbiddenAmbiguousWarningKeepsCodeZero(t *testing.T) {
	entries, _, err := runForbiddenWarningSession(
		t,
		false,
		syntheticSessionWarningValue("300"),
		syntheticSessionWarningValue("399"),
	)

	var attemptErr *registrarAttemptError
	if !errors.As(err, &attemptErr) {
		t.Fatal("ambiguous 403 Warning did not fail closed")
	}
	initial := initialResponseWarningEntries(t, entries)
	if len(initial) != 1 {
		t.Fatalf("initial_response diagnostic count = %d, want exactly 1", len(initial))
	}
	fields := initial[0]
	if got := fields["warning_parse_result"].String; got != registerWarningParseAmbiguous {
		t.Fatalf("warning_parse_result = %q, want ambiguous", got)
	}
	if got := fields["warning_code"].Integer; got != 0 {
		t.Fatalf("ambiguous Warning emitted warning_code = %d, want 0", got)
	}
	assertNoWarningMaterialLeaked(t, entries)
}
