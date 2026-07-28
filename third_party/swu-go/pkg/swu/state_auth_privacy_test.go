package swu

import (
	"fmt"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestBuildIKEAuthInitPayloadsDoesNotLogFastReauthIdentity(t *testing.T) {
	const identityMarker = "synthetic-private-identity-marker"
	core, observed := observer.New(zap.DebugLevel)
	session := &Session{
		cfg: &Config{
			FastReauthID: identityMarker,
			APN:          "ims.test.invalid",
		},
		Logger: zap.New(core),
	}
	if _, err := session.buildIKEAuthInitPayloads(); err != nil {
		t.Fatalf("buildIKEAuthInitPayloads() error = %v", err)
	}
	for _, entry := range observed.All() {
		for key, value := range entry.ContextMap() {
			if strings.EqualFold(key, "nai") || strings.EqualFold(key, "reauthID") || strings.Contains(fmt.Sprint(value), identityMarker) {
				t.Fatal("IKE_AUTH logger exposed a private identity field")
			}
		}
	}
}

func TestIKEAuthNotifyDiagnosticsDoNotExposeRawData(t *testing.T) {
	notify := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 1,
		SPI:        []byte{0xfe, 0xed, 0xfa, 0xce},
		NotifyType: 24,
		NotifyData: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	err := newIKEAuthNotifyError(notify)
	for _, forbidden := range []string{"feedface", "deadbeef", "254 237", "222 173"} {
		if strings.Contains(strings.ToLower(err.Error()), forbidden) {
			t.Fatal("IKE_AUTH notify error exposed raw SPI or Notify Data")
		}
	}

	core, observed := observer.New(zap.DebugLevel)
	session := &Session{Logger: zap.New(core)}
	session.logIKEAuthNotify(notify)
	entries := observed.FilterMessage("IKE_AUTH received status notify").All()
	if len(entries) != 1 {
		t.Fatalf("IKE_AUTH notify log count = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	allowed := map[string]bool{"notify_type": true, "protocol_id": true, "data_len": true}
	for key, value := range fields {
		if !allowed[key] {
			t.Fatalf("IKE_AUTH notify log contains disallowed field %q", key)
		}
		for _, forbidden := range []string{"feedface", "deadbeef", "254 237", "222 173"} {
			if strings.Contains(strings.ToLower(fmt.Sprint(value)), forbidden) {
				t.Fatal("IKE_AUTH notify log exposed raw SPI or Notify Data")
			}
		}
	}
}

func TestEAPAKAPrimeMACMismatchDoesNotExposeMACMaterial(t *testing.T) {
	receivedMAC := []byte{
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	}
	err := verifyEAPAKAPrimeMAC([]byte("synthetic-eap-packet"), nil, []byte("synthetic-key"), receivedMAC)
	if err == nil {
		t.Fatal("verifyEAPAKAPrimeMAC() unexpectedly accepted mismatched MAC")
	}
	if strings.Contains(strings.ToLower(err.Error()), "deadbeef") {
		t.Fatal("AKA prime MAC mismatch error exposed MAC material")
	}
}
