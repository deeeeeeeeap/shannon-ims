package logger

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestRedactingCoreRemovesSensitiveMessagesAndFields(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	log := zap.New(newRedactingCore(core))

	phone := "+" + strings.Repeat("7", 11)
	imei := strings.Repeat("8", 15)
	imsi := strings.Repeat("9", 15)
	iccid := strings.Repeat("6", 19)
	token := strings.Repeat("T", 48)
	auts := strings.Repeat("A", 28)

	log.Info(
		"request Authorization: Digest token="+token+" peer="+phone,
		zap.String("phone", phone),
		zap.String("imei", imei),
		zap.String("imsi", imsi),
		zap.String("iccid", iccid),
		zap.String("access_token", token),
		zap.String("auts", auts),
		zap.Reflect("headers", map[string]string{"Authorization": "Bearer " + token}),
		zap.Error(fmt.Errorf("subscriber=%s token=%s", imsi, token)),
		zap.Int("challenge_round", 2),
		zap.Int("auts_len", len(auts)),
		zap.String("nonce_fingerprint", "synthetic-fingerprint"),
		zap.Bool("iccid_changed", true),
		zap.Int64("identity_refresh_ms", 7),
	)

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("observed entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	ctx := entry.ContextMap()
	combined := entry.Message + fmt.Sprint(ctx)
	for name, raw := range map[string]string{
		"phone": phone,
		"imei":  imei,
		"imsi":  imsi,
		"iccid": iccid,
		"token": token,
		"auts":  auts,
	} {
		if strings.Contains(combined, raw) {
			t.Fatalf("redacted log still contains %s", name)
		}
	}
	if got := ctx["challenge_round"]; got != int64(2) {
		t.Fatalf("challenge_round = %#v, want 2", got)
	}
	if got := ctx["auts_len"]; got != int64(len(auts)) {
		t.Fatalf("auts_len = %#v, want %d", got, len(auts))
	}
	if got := ctx["nonce_fingerprint"]; got != "synthetic-fingerprint" {
		t.Fatalf("nonce_fingerprint = %#v", got)
	}
	if got := ctx["iccid_changed"]; got != true {
		t.Fatalf("iccid_changed = %#v, want true", got)
	}
	if got := ctx["identity_refresh_ms"]; got != int64(7) {
		t.Fatalf("identity_refresh_ms = %#v, want 7", got)
	}
	for _, key := range []string{"phone", "imei", "imsi", "iccid", "auts"} {
		if got := fmt.Sprint(ctx[key]); !strings.Contains(got, "len=") || !strings.Contains(got, "fp=") {
			t.Fatalf("%s redaction summary = %q, want length and fingerprint", key, got)
		}
	}
	if got := fmt.Sprint(ctx["access_token"]); got != "[REDACTED]" {
		t.Fatalf("access_token = %q, want opaque redaction", got)
	}
	if got := fmt.Sprint(ctx["headers"]); !strings.Contains(got, "[REDACTED") {
		t.Fatalf("reflected headers = %q, want summarized redaction", got)
	}
}

func TestDevicePrefixIsRedactedBeforeEmission(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	log := zap.New(&devicePrefixCore{Core: newRedactingCore(core)})
	identity := strings.Repeat("5", 15)

	log.Info("device attached", zap.String("device", identity))

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("observed entries = %d, want 1", len(entries))
	}
	if strings.Contains(entries[0].Message, identity) {
		t.Fatal("device prefix exposed a raw device identity")
	}
}

func TestRedactingCoreProtectsWithFieldsAndSSE(t *testing.T) {
	broadcaster := NewBroadcaster(1)
	ch := broadcaster.Subscribe()
	defer broadcaster.Unsubscribe(ch)

	raw := strings.Repeat("4", 15)
	core := newRedactingCore(NewSSECore(broadcaster, zap.DebugLevel))
	log := zap.New(core).With(zap.String("imsi", raw))
	log.Info("subscriber=" + raw)

	select {
	case entry := <-ch:
		combined := entry.Message + entry.Fields
		if strings.Contains(combined, raw) {
			t.Fatal("SSE entry exposed a raw identity from With fields")
		}
		if !strings.Contains(entry.Fields, "fingerprint") && !strings.Contains(entry.Fields, "fp=") {
			t.Fatalf("SSE entry lacks redaction metadata: %s", entry.Fields)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SSE log entry")
	}
}
