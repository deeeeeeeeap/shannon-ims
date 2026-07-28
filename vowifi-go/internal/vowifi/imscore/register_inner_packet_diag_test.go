package imscore

import (
	"testing"

	swulogger "github.com/1239t/swu-go/pkg/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// The acceptance criteria for the protected REGISTER are stated in terms of the
// inner packet, not just the SIP length: the inner IPv6+UDP+ESP packet must fit
// the SWu raw IP MTU. sip_message_len alone cannot show that, because the ESP
// ciphertext is block-aligned before framing.
//
// "fragment_count" was ambiguous: 1 could be read either as "one fragment was
// produced" (i.e. fragmentation happened) or as "one packet, unfragmented". The
// two facts are now reported separately and unambiguously:
//
//   - raw_ip_packet_count: how many raw IP packets the SWu connection writes.
//   - fragmented: whether IPv6 fragmentation was required at all.
//
// The initial REGISTER is packet_count=1, fragmented=false. The protected
// REGISTER at its measured size is packet_count=2, fragmented=true.
//
// These are derived integers and a bool only. No SIP text, header value,
// address, identity or key material is recorded.

func TestProtectedRegisterDiagnosticEmitsRawIPPacketCountAndFragmented(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	// A size that fits unfragmented: inner = 76 + roundUp16(1172+10) = 1260.
	logProtectedRegisterMessageSize(1172)

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic entry count = %d, want 1", len(entries))
	}
	fields := map[string]zap.Field{}
	for _, field := range entries[0].Context {
		fields[field.Key] = field
	}
	allowed := registerDiagnosticAllowedFieldKeys()
	for _, key := range []string{"inner_packet_len", "raw_ip_packet_count", "fragmented"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("diagnostic is missing field %q", key)
		}
		if _, ok := allowed[key]; !ok {
			t.Fatalf("field %q is emitted but not whitelisted", key)
		}
	}
	// The ambiguous field must be gone entirely, not merely supplemented.
	if _, ok := fields["fragment_count"]; ok {
		t.Fatal("fragment_count is still emitted; it was replaced by raw_ip_packet_count + fragmented")
	}
	if _, ok := allowed["fragment_count"]; ok {
		t.Fatal("fragment_count is still whitelisted")
	}

	if got := fields["inner_packet_len"].Integer; got != 1260 {
		t.Fatalf("inner_packet_len = %d, want 1260", got)
	}
	if got := fields["raw_ip_packet_count"].Integer; got != 1 {
		t.Fatalf("raw_ip_packet_count = %d, want 1", got)
	}
	if got := fields["fragmented"].Integer; got != 0 {
		t.Fatalf("fragmented = %d, want 0 (false)", got)
	}
	if got := fields["sip_message_len"].Integer; got != 1172 {
		t.Fatalf("sip_message_len = %d, want 1172", got)
	}
}

// The measured production size must report as fragmented, so a regression that
// re-inflates the request stays visible in the same log line.
func TestProtectedRegisterDiagnosticReportsFragmentationForOversizedRequest(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	// The size measured on device.
	logProtectedRegisterMessageSize(1360)

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic entry count = %d, want 1", len(entries))
	}
	fields := map[string]zap.Field{}
	for _, field := range entries[0].Context {
		fields[field.Key] = field
	}
	if got := fields["inner_packet_len"].Integer; got != 1452 {
		t.Fatalf("inner_packet_len = %d, want 1452", got)
	}
	if got := fields["raw_ip_packet_count"].Integer; got != 2 {
		t.Fatalf("raw_ip_packet_count = %d, want 2", got)
	}
	if got := fields["fragmented"].Integer; got != 1 {
		t.Fatalf("fragmented = %d, want 1 (true)", got)
	}
}

// The boundary itself: the largest SIP length that still needs one packet, and
// the first that needs two. This pins raw_ip_packet_count to the derived budget
// rather than to a hand-picked number.
func TestProtectedRegisterDiagnosticPacketCountBoundary(t *testing.T) {
	for _, tc := range []struct {
		name        string
		sipLen      int
		wantCount   int64
		wantFragged int64
	}{
		{name: "at budget", sipLen: protectedRegisterMaxUnfragmentedSIPLen, wantCount: 1, wantFragged: 0},
		{name: "one over budget", sipLen: protectedRegisterMaxUnfragmentedSIPLen + 1, wantCount: 2, wantFragged: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, observed := observer.New(zap.DebugLevel)
			swulogger.SetLogger(zap.New(core))
			t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

			logProtectedRegisterMessageSize(tc.sipLen)

			entries := observed.All()
			if len(entries) != 1 {
				t.Fatalf("diagnostic entry count = %d, want 1", len(entries))
			}
			fields := map[string]zap.Field{}
			for _, field := range entries[0].Context {
				fields[field.Key] = field
			}
			if got := fields["raw_ip_packet_count"].Integer; got != tc.wantCount {
				t.Fatalf("raw_ip_packet_count = %d, want %d", got, tc.wantCount)
			}
			if got := fields["fragmented"].Integer; got != tc.wantFragged {
				t.Fatalf("fragmented = %d, want %d", got, tc.wantFragged)
			}
		})
	}
}

// A hostile or corrupt length must be clamped like every other counter, and the
// derived fields must never carry payload-bearing keys.
func TestProtectedRegisterInnerPacketDiagnosticIsBoundedAndOpaque(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	logProtectedRegisterMessageSize(-1)
	logProtectedRegisterMessageSize(registerESPCounterMax + 5000)

	for _, entry := range observed.All() {
		for _, field := range entry.Context {
			switch field.Key {
			case "inner_packet_len", "raw_ip_packet_count":
				if field.Integer < 0 || field.Integer > int64(registerESPCounterMax) {
					t.Fatalf("%s = %d, want clamped to 0..%d", field.Key, field.Integer, registerESPCounterMax)
				}
			}
		}
	}

	allowed := registerDiagnosticAllowedFieldKeys()
	for _, key := range []string{
		"inner_packet", "esp_payload", "inner_bytes", "packet_hex",
	} {
		if _, ok := allowed[key]; ok {
			t.Fatalf("diagnostic allowlist contains payload-bearing key %q", key)
		}
	}
}
