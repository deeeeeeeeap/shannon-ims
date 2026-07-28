package imscore

import (
	"strings"
	"testing"

	swulogger "github.com/1239t/swu-go/pkg/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// When the protected REGISTER is sent over ESP but no response arrives, the
// bounded userspace-ESP counters are the only thing that can tell apart
// "nothing came back at all" from "packets arrived and failed to transform".
// Transport.Stats() already tracks both, but nothing ever logs them, so the
// timeout is indistinguishable from a silent decrypt/replay drop.
//
// These fields are counters only: no SIP, no ESP payload, no address, no SPI,
// no key material.

func TestRegisterDiagnosticsEmitBoundedESPCounters(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	logRegisterDiagnostic(registerDiagnostic{
		stage:                 "protected_read_timeout",
		result:                "no_sip_response",
		protected:             true,
		peerIPInboundPackets:  2,
		espOutboundPackets:    1,
		espInboundPackets:     0,
		espTransformErrors:    0,
		espPassthroughPackets: 0,
		espReplayDuplicate:    0,
		espReplayTooOld:       0,
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
		"peer_ip_inbound_count", "esp_outbound_packets", "esp_inbound_packets", "esp_transform_errors",
		"esp_passthrough_packets", "esp_replay_duplicate", "esp_replay_too_old",
	} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("diagnostic is missing ESP counter field %q", key)
		}
		if _, ok := allowed[key]; !ok {
			t.Fatalf("field %q is emitted but not whitelisted", key)
		}
	}
	if got := fields["peer_ip_inbound_count"].Integer; got != 2 {
		t.Fatalf("peer_ip_inbound_count = %d, want 2", got)
	}
	if got := fields["esp_outbound_packets"].Integer; got != 1 {
		t.Fatalf("esp_outbound_packets = %d, want 1", got)
	}
	if got := fields["esp_inbound_packets"].Integer; got != 0 {
		t.Fatalf("esp_inbound_packets = %d, want 0", got)
	}
}

// A hostile or overflowing counter must be clamped, never logged raw.
func TestRegisterDiagnosticsClampESPCounters(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	logRegisterDiagnostic(registerDiagnostic{
		stage:                 "protected_read_timeout",
		result:                "no_sip_response",
		peerIPInboundPackets:  registerESPCounterMax + 2000,
		espOutboundPackets:    registerESPCounterMax + 5000,
		espInboundPackets:     -17,
		espTransformErrors:    registerESPCounterMax * 3,
		espPassthroughPackets: -1,
		espReplayDuplicate:    registerESPCounterMax + 1,
		espReplayTooOld:       -99,
	})

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic entry count = %d, want 1", len(entries))
	}
	for _, field := range entries[0].Context {
		if !strings.HasPrefix(field.Key, "esp_") && field.Key != "peer_ip_inbound_count" {
			continue
		}
		if field.Integer < 0 {
			t.Fatalf("%s = %d, want clamped to >= 0", field.Key, field.Integer)
		}
		if field.Integer > int64(registerESPCounterMax) {
			t.Fatalf("%s = %d, want clamped to <= %d", field.Key, field.Integer, registerESPCounterMax)
		}
	}
}

// The new stage and result must be inside the existing closed enums, otherwise
// they would silently degrade to "unknown".
func TestProtectedReadTimeoutStageAndResultAreCanonical(t *testing.T) {
	if got := canonicalRegisterDiagnosticStage("protected_read_timeout"); got != "protected_read_timeout" {
		t.Fatalf("stage = %q, want protected_read_timeout", got)
	}
	if got := canonicalRegisterDiagnosticResult("no_sip_response"); got != "no_sip_response" {
		t.Fatalf("result = %q, want no_sip_response", got)
	}
}

// boundRegisterESPCounter is the single clamp used for every ESP counter.
func TestBoundRegisterESPCounter(t *testing.T) {
	cases := []struct {
		in   uint64
		want int
	}{
		{in: 0, want: 0},
		{in: 1, want: 1},
		{in: uint64(registerESPCounterMax) - 1, want: registerESPCounterMax - 1},
		{in: uint64(registerESPCounterMax), want: registerESPCounterMax},
		{in: uint64(registerESPCounterMax) + 1, want: registerESPCounterMax},
		{in: ^uint64(0), want: registerESPCounterMax},
	}
	for _, tc := range cases {
		if got := boundRegisterESPCounterU64(tc.in); got != tc.want {
			t.Fatalf("boundRegisterESPCounterU64(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
