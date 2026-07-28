package imscore

import (
	"bufio"
	"context"
	"fmt"
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

func TestIMSRegisterDiagnosticsUseStrictFieldWhitelist(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	captureCh := make(chan registerSessionTestCapture, 1)
	network := &registerSessionTestNetwork{}
	network.serve = func(peer net.Conn) {
		defer peer.Close()
		capture := registerSessionTestCapture{}
		defer func() { captureCh <- capture }()
		reader := bufio.NewReader(peer)
		for index, status := range []int{sip.StatusBadRequest, sip.StatusForbidden} {
			req, err := readRegisterSessionTestRequest(reader)
			if err != nil {
				capture.err = fmt.Errorf("read REGISTER %d: %w", index+1, err)
				return
			}
			capture.requests = append(capture.requests, req)
			if err := writeRegisterSessionTestResponse(peer, req, status, "Synthetic Rejection", false); err != nil {
				capture.err = fmt.Errorf("write response %d: %w", index+1, err)
				return
			}
		}
	}

	cfg := registerSessionTestConfig()
	cfg.CarrierBehavior = policy.Default3GPPBehavior()
	cfg.TraceID = "synthetic-trace"
	cfg.DeviceID = "synthetic-device"
	session := newRegisterSession(cfg, nil, network, "udp", 0)
	session.jitter = false
	session.localPort = 41234
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := session.runInitialRegisterFlow(ctx); err == nil {
		t.Fatal("synthetic REGISTER unexpectedly succeeded")
	}
	if capture := <-captureCh; capture.err != nil {
		t.Fatal(capture.err)
	}

	imsCfg := IMSConfig{
		DeviceID:        cfg.DeviceID,
		Registrar:       cfg.PCSCFAddr,
		Transport:       "udp",
		CarrierBehavior: cfg.CarrierBehavior,
	}
	logIMSConfigResolved(imsCfg, cfg, 2)
	logRegisterTransportAttempt(cfg, "udp", 1, 2, registerAttemptCandidate{
		Registrar: cfg.PCSCFAddr,
		Gateway:   cfg.TransportPCSCFAddr,
	})
	logRegistrarRejected(cfg.TraceID, cfg.DeviceID, cfg.PCSCFAddr, sip.StatusBadRequest, "Synthetic Rejection", 1, 2)

	allowed := registerDiagnosticAllowedFieldKeys()

	entries := observed.All()
	if len(entries) == 0 {
		t.Fatal("REGISTER diagnostics were not observed")
	}
	for _, entry := range entries {
		if !strings.Contains(entry.Message, "REGISTER") && entry.Message != "IMS config resolved" {
			continue
		}
		for _, field := range entry.Context {
			if _, ok := allowed[field.Key]; !ok {
				t.Fatalf("REGISTER diagnostic uses forbidden field key %q", field.Key)
			}
		}
	}
}

// registerDiagnosticForbiddenFieldKeys are keys that would carry raw SIP,
// identity, address, or credential material. None may ever be emitted.
var registerDiagnosticForbiddenFieldKeys = []string{
	"warning_value", "warning_text", "warning_agent", "header_value",
	"uri", "registrar", "pcscf", "local", "remote", "identity",
	"authorization", "nonce", "raw_error", "payload",
}

func TestIMSRegisterDiagnosticsNeverAllowSensitiveFieldKeys(t *testing.T) {
	allowed := registerDiagnosticAllowedFieldKeys()
	for _, key := range registerDiagnosticForbiddenFieldKeys {
		if _, ok := allowed[key]; ok {
			t.Fatalf("diagnostic allowlist contains sensitive key %q", key)
		}
	}
}

func TestIMSRegisterDiagnosticsEmitWarningMetadataFields(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	logRegisterDiagnostic(registerDiagnostic{
		stage:              "initial_response",
		status:             sip.StatusForbidden,
		result:             "forbidden",
		warningPresent:     true,
		warningCount:       1,
		warningCode:        399,
		warningClass:       registerWarningClassMiscellaneous,
		warningParseResult: registerWarningParseKnown,
	})

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic entry count = %d, want 1", len(entries))
	}
	fields := map[string]zap.Field{}
	for _, field := range entries[0].Context {
		fields[field.Key] = field
	}
	allowed := registerDiagnosticAllowedFieldKeys()
	for _, key := range []string{
		"warning_present", "warning_count", "warning_code",
		"warning_class", "warning_parse_result",
	} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("diagnostic is missing whitelisted field %q", key)
		}
		if _, ok := allowed[key]; !ok {
			t.Fatalf("field %q is emitted but not whitelisted", key)
		}
	}
	if got := fields["warning_code"].Integer; got != 399 {
		t.Fatalf("warning_code = %d, want 399", got)
	}
	if got := fields["warning_class"].String; got != registerWarningClassMiscellaneous {
		t.Fatalf("warning_class = %q, want miscellaneous", got)
	}
	if got := fields["warning_parse_result"].String; got != registerWarningParseKnown {
		t.Fatalf("warning_parse_result = %q, want known", got)
	}
}

func TestIMSRegisterDiagnosticsClampHostileWarningMetadata(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	logRegisterDiagnostic(registerDiagnostic{
		stage:              "initial_response",
		status:             sip.StatusForbidden,
		result:             "forbidden",
		warningPresent:     true,
		warningCount:       registerWarningMaxValues + 250,
		warningCode:        606,
		warningClass:       "synthetic-class-should-not-appear",
		warningParseResult: "synthetic-parse-should-not-appear",
	})

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic entry count = %d, want 1", len(entries))
	}
	fields := map[string]zap.Field{}
	for _, field := range entries[0].Context {
		fields[field.Key] = field
	}
	if got := fields["warning_code"].Integer; got != 0 {
		t.Fatalf("non-allowlisted warning_code was emitted as %d, want 0", got)
	}
	if got := fields["warning_count"].Integer; got != int64(registerWarningMaxValues) {
		t.Fatalf("warning_count = %d, want clamped %d", got, registerWarningMaxValues)
	}
	if got := fields["warning_class"].String; got != registerWarningClassUnknown {
		t.Fatalf("warning_class = %q, want unknown", got)
	}
	if got := fields["warning_parse_result"].String; got != registerWarningParseAbsent {
		t.Fatalf("warning_parse_result = %q, want absent", got)
	}
}

func TestIMSRegisterDiagnosticsWarningFieldsDoNotChangeLogLevel(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	// warning_present must not promote the entry; only has_warning may.
	logRegisterDiagnostic(registerDiagnostic{
		stage:              "initial_response",
		status:             sip.StatusForbidden,
		result:             "forbidden",
		warningPresent:     true,
		warningParseResult: registerWarningParseKnown,
	})
	logRegisterDiagnostic(registerDiagnostic{
		stage:      "initial_response",
		status:     sip.StatusForbidden,
		result:     "forbidden",
		hasWarning: true,
	})

	entries := observed.All()
	if len(entries) != 2 {
		t.Fatalf("diagnostic entry count = %d, want 2", len(entries))
	}
	if entries[0].Level != zap.InfoLevel {
		t.Fatalf("warning_present changed log level to %v", entries[0].Level)
	}
	if entries[1].Level != zap.WarnLevel {
		t.Fatalf("has_warning no longer selects Warn level, got %v", entries[1].Level)
	}
}
