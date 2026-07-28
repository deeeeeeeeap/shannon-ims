package imscore

import (
	"strings"
	"testing"

	swulogger "github.com/1239t/swu-go/pkg/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// The protected REGISTER is the only REGISTER in the flow that never gets a
// response. The initial REGISTER and the protected REGISTER differ in exactly
// one measurable way that nothing currently records: serialized SIP length.
//
// RFC 3261 §18.1.1 requires a UAC to switch to a congestion-controlled
// transport when a request is within 200 bytes of the path MTU, and treats
// 1300 bytes as the threshold when the path MTU is unknown. The protected
// REGISTER is sent over UDP unconditionally (dialSecureRegisterConn rejects
// anything else), so if it crosses that threshold the request is
// standards-noncompliant and a silent drop is a legitimate peer behaviour.
//
// These fields are lengths and booleans only: no SIP text, no header values,
// no addresses, no identities.

func TestRegisterDiagnosticsEmitBoundedSIPMessageSize(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	logRegisterDiagnostic(registerDiagnostic{
		stage:              "protected_send",
		result:             "sending",
		protected:          true,
		sipMessageLen:      1390,
		exceedsUDPMTULimit: true,
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
	for _, key := range []string{"sip_message_len", "exceeds_udp_mtu_limit"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("diagnostic is missing field %q", key)
		}
		if _, ok := allowed[key]; !ok {
			t.Fatalf("field %q is emitted but not whitelisted", key)
		}
	}
	if got := fields["sip_message_len"].Integer; got != 1390 {
		t.Fatalf("sip_message_len = %d, want 1390", got)
	}
	// zap encodes bools in Field.Integer (1/0), not Field.Interface.
	if got := fields["exceeds_udp_mtu_limit"]; got.Type != zapcore.BoolType || got.Integer != 1 {
		t.Fatalf("exceeds_udp_mtu_limit = type:%v integer:%d, want BoolType/1", got.Type, got.Integer)
	}
}

// A hostile or corrupt length must be clamped like every other counter.
func TestRegisterDiagnosticsClampSIPMessageSize(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	logRegisterDiagnostic(registerDiagnostic{
		stage:         "protected_send",
		result:        "sending",
		sipMessageLen: -5,
	})
	logRegisterDiagnostic(registerDiagnostic{
		stage:         "protected_send",
		result:        "sending",
		sipMessageLen: registerESPCounterMax + 9000,
	})

	for _, entry := range observed.All() {
		for _, field := range entry.Context {
			if field.Key != "sip_message_len" {
				continue
			}
			if field.Integer < 0 || field.Integer > int64(registerESPCounterMax) {
				t.Fatalf("sip_message_len = %d, want clamped to 0..%d", field.Integer, registerESPCounterMax)
			}
		}
	}
}

// registerSIPMessageExceedsUDPLimit is the single decision point for the
// RFC 3261 §18.1.1 threshold, so the emit site and any future transport
// decision cannot drift apart.
func TestRegisterSIPMessageExceedsUDPLimit(t *testing.T) {
	cases := []struct {
		name string
		size int
		want bool
	}{
		{name: "small initial register", size: 1130, want: false},
		{name: "just under threshold", size: registerUDPSafeMessageLimit - 1, want: false},
		{name: "at threshold", size: registerUDPSafeMessageLimit, want: false},
		{name: "over threshold", size: registerUDPSafeMessageLimit + 1, want: true},
		{name: "observed protected register", size: 1390, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := registerSIPMessageExceedsUDPLimit(tc.size); got != tc.want {
				t.Fatalf("registerSIPMessageExceedsUDPLimit(%d) = %v, want %v", tc.size, got, tc.want)
			}
		})
	}
}

// The threshold itself must match RFC 3261 §18.1.1 (1300 bytes when the path
// MTU is unknown), not an arbitrary local guess.
func TestRegisterUDPSafeMessageLimitMatchesRFC3261(t *testing.T) {
	if registerUDPSafeMessageLimit != 1300 {
		t.Fatalf("registerUDPSafeMessageLimit = %d, want 1300 per RFC 3261 §18.1.1", registerUDPSafeMessageLimit)
	}
}

// The whitelist must never accept a key that could carry the message itself.
func TestRegisterMessageSizeFieldsNeverCarryPayload(t *testing.T) {
	allowed := registerDiagnosticAllowedFieldKeys()
	for _, key := range []string{
		"sip_message", "sip_body", "sip_text", "request_line", "message_bytes",
	} {
		if _, ok := allowed[key]; ok {
			t.Fatalf("diagnostic allowlist contains payload-bearing key %q", key)
		}
	}
	for key := range allowed {
		if strings.Contains(key, "message") && !strings.HasSuffix(key, "_len") {
			t.Fatalf("message-related key %q must be a length, not content", key)
		}
	}
}
