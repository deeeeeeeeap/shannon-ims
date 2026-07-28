package imscore

import (
	"testing"

	swulogger "github.com/1239t/swu-go/pkg/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// Stage 1: a standalone diagnostic defect, deliberately kept separate from the
// protocol investigation.
//
// The stage=ipsec_install diagnostic reports ipsec_installed=true, and the very
// next line — stage=protected_send, emitted after the SA is already installed —
// reports ipsec_installed=false. Both protected_send emit sites simply omit the
// field, so it defaults to false:
//
//   - register_session.go, right before runSecureAuthenticatedRegister
//   - register_diagnostics.go, logProtectedRegisterMessageSize
//
// Reading the device logs, that made it look as though the SA had been torn down
// between install and send. It had not. This is a missing struct field, nothing
// more, and it must not be confused with the reason the P-CSCF stays silent.
//
// stage=protected_read_timeout already reports ipsec_installed=true, which is
// what makes the false on protected_send obviously wrong rather than a
// deliberate distinction.
//
// These tests assert one boolean per stage. No SIP text, identity, address,
// nonce, Authorization or key material is asserted or logged.

// TestProtectedSendDiagnosticMarksIPSecInstalled pins the size-reporting emit
// site, which is the one that fires on every protected send.
func TestProtectedSendDiagnosticMarksIPSecInstalled(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	logProtectedRegisterMessageSize(1360)

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic entry count = %d, want 1", len(entries))
	}
	fields := map[string]zap.Field{}
	for _, field := range entries[0].Context {
		fields[field.Key] = field
	}
	if got := fields["stage"].String; got != "protected_send" {
		t.Fatalf("stage = %q, want protected_send", got)
	}
	// protected must already be true today; this guards against the fix
	// accidentally swapping the two flags.
	if fields["protected"].Integer != 1 {
		t.Fatal("protected must be true on protected_send")
	}
	if fields["ipsec_installed"].Integer != 1 {
		t.Fatal("ipsec_installed must be true on protected_send: the SA is installed before the request is sent")
	}
}

// TestProtectedSendDiagnosticFlagsAreConsistentAcrossStages proves the whole
// install -> send -> timeout sequence agrees on ipsec_installed, which is the
// property that made the device logs misleading.
func TestProtectedSendDiagnosticFlagsAreConsistentAcrossStages(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	// Mirrors the production order: install, then send, then the read timeout.
	logRegisterDiagnostic(registerDiagnostic{
		stage:          "ipsec_install",
		result:         "installed",
		transport:      "udp",
		reachedAuth:    true,
		ipsecInstalled: true,
	})
	logProtectedRegisterMessageSize(1360)
	logRegisterDiagnostic(registerDiagnostic{
		stage:          "protected_read_timeout",
		result:         "no_sip_response",
		protected:      true,
		ipsecInstalled: true,
	})

	entries := observed.All()
	if len(entries) != 3 {
		t.Fatalf("diagnostic entry count = %d, want 3", len(entries))
	}
	for _, entry := range entries {
		stage := ""
		installed := int64(-1)
		for _, field := range entry.Context {
			switch field.Key {
			case "stage":
				stage = field.String
			case "ipsec_installed":
				installed = field.Integer
			}
		}
		switch stage {
		case "ipsec_install", "protected_send", "protected_read_timeout":
			if installed != 1 {
				t.Fatalf("stage %s reports ipsec_installed=false after the SA was installed", stage)
			}
		default:
			t.Fatalf("unexpected stage %q", stage)
		}
	}
}

// The fix must not turn ipsec_installed into a constant: stages that run before
// installation have to keep reporting false.
func TestPreInstallDiagnosticsStillReportIPSecNotInstalled(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	for _, stage := range []string{"initial_attempt", "initial_response", "auth_challenge"} {
		logRegisterDiagnostic(registerDiagnostic{
			stage:     stage,
			result:    "none",
			transport: "udp",
		})
	}

	for _, entry := range observed.All() {
		for _, field := range entry.Context {
			if field.Key == "ipsec_installed" && field.Integer != 0 {
				t.Fatal("a pre-install stage reported ipsec_installed=true")
			}
		}
	}
}
