package imscore

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	swulogger "github.com/1239t/swu-go/pkg/logger"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

// The Digest AKA realm either came from the card's ISIM (an operator-specific
// home domain) or was synthesised from MCC/MNC per 3GPP TS 23.003. A network
// that only knows the ISIM-provisioned domain cannot resolve a subscriber
// presented under the synthesised one, which is a pre-auth 403 shape.
//
// classifyRegisterRealmSource reports which of the two produced the realm
// currently in use. It returns a closed enum only: the realm, domain, PLMN
// digits, and identity are never returned or logged.

func TestClassifyRegisterRealmSourceDetects3GPPDerivedRealm(t *testing.T) {
	cases := []struct {
		name  string
		realm string
		mcc   string
		mnc   string
	}{
		{name: "two digit MNC padded", realm: "ims.mnc024.mcc310.3gppnetwork.org", mcc: "310", mnc: "24"},
		{name: "three digit MNC", realm: "ims.mnc240.mcc310.3gppnetwork.org", mcc: "310", mnc: "240"},
		{name: "leading zero MNC", realm: "ims.mnc010.mcc234.3gppnetwork.org", mcc: "234", mnc: "10"},
		{name: "mixed case", realm: "IMS.MNC240.MCC310.3GPPNETWORK.ORG", mcc: "310", mnc: "240"},
		{name: "surrounding whitespace", realm: "  ims.mnc240.mcc310.3gppnetwork.org  ", mcc: "310", mnc: "240"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyRegisterRealmSource(tc.realm, tc.mcc, tc.mnc)
			if got != registerRealmSource3GPPDerived {
				t.Fatalf("realm source = %q, want %q", got, registerRealmSource3GPPDerived)
			}
		})
	}
}

func TestClassifyRegisterRealmSourceDetectsOperatorSpecificRealm(t *testing.T) {
	// Synthetic operator-style domains: shape only, no real carrier host.
	cases := []string{
		"ims.synthetic-operator.invalid",
		"msg.pc.synthetic.invalid",
		"ims.mnc999.mcc999.3gppnetwork.org",
		"ims.mnc240.mcc311.3gppnetwork.org",
		"3gppnetwork.org",
		"ims.mnc240.mcc310.3gppnetwork.org.synthetic.invalid",
	}
	for _, realm := range cases {
		t.Run(realm, func(t *testing.T) {
			got := classifyRegisterRealmSource(realm, "310", "240")
			if got != registerRealmSourceOperatorSpecific {
				t.Fatalf("realm source = %q, want %q", got, registerRealmSourceOperatorSpecific)
			}
		})
	}
}

func TestClassifyRegisterRealmSourceReportsAbsentRealm(t *testing.T) {
	for _, realm := range []string{"", "   ", "\t"} {
		if got := classifyRegisterRealmSource(realm, "310", "240"); got != registerRealmSourceAbsent {
			t.Fatalf("realm source = %q, want %q", got, registerRealmSourceAbsent)
		}
	}
}

func TestClassifyRegisterRealmSourceReportsUnknownWithoutUsablePLMN(t *testing.T) {
	cases := []struct{ mcc, mnc string }{
		{mcc: "", mnc: "240"},
		{mcc: "310", mnc: ""},
		{mcc: "", mnc: ""},
		{mcc: "310", mnc: "2"},
		{mcc: "310", mnc: "2404"},
		{mcc: "31", mnc: "240"},
		{mcc: "abc", mnc: "240"},
		{mcc: "310", mnc: "abc"},
	}
	for _, tc := range cases {
		got := classifyRegisterRealmSource("ims.mnc240.mcc310.3gppnetwork.org", tc.mcc, tc.mnc)
		if got != registerRealmSourceUnknown {
			t.Fatalf("realm source = %q, want %q", got, registerRealmSourceUnknown)
		}
	}
}

// The classifier must never echo any part of its input.
func TestClassifyRegisterRealmSourceReturnsClosedEnumOnly(t *testing.T) {
	allowed := map[string]struct{}{
		registerRealmSourceAbsent:           {},
		registerRealmSource3GPPDerived:      {},
		registerRealmSourceOperatorSpecific: {},
		registerRealmSourceUnknown:          {},
	}
	inputs := []struct{ realm, mcc, mnc string }{
		{"ims.mnc240.mcc310.3gppnetwork.org", "310", "240"},
		{"synthetic-secret-domain.invalid", "310", "240"},
		{"", "", ""},
		{strings.Repeat("s", 4096), "310", "240"},
		{"ims.mnc240.mcc310.3gppnetwork.org", "zz", "zz"},
	}
	for _, in := range inputs {
		got := classifyRegisterRealmSource(in.realm, in.mcc, in.mnc)
		if _, ok := allowed[got]; !ok {
			t.Fatal("realm source classifier returned a value outside the closed enum")
		}
		if strings.Contains(got, "synthetic") || strings.Contains(got, "secret") {
			t.Fatal("realm source classifier echoed part of its input")
		}
	}
}

// The realm-source field must reach diagnostics as a whitelisted closed enum.
func TestIMSConfigResolvedEmitsRealmSourceField(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	imsCfg := IMSConfig{
		Registrar:       "192.0.2.10:5060",
		Transport:       "udp",
		Realm:           "ims.mnc240.mcc310.3gppnetwork.org",
		CarrierBehavior: policy.Default3GPPBehavior(),
	}
	cfg := Config{
		Realm: "ims.mnc240.mcc310.3gppnetwork.org",
		MCC:   "310",
		MNC:   "240",
	}
	logIMSConfigResolved(imsCfg, cfg, 1)

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic entry count = %d, want 1", len(entries))
	}
	fields := map[string]zap.Field{}
	for _, field := range entries[0].Context {
		fields[field.Key] = field
	}
	field, ok := fields["realm_source"]
	if !ok {
		t.Fatal("IMS config diagnostic is missing realm_source")
	}
	if field.String != registerRealmSource3GPPDerived {
		t.Fatalf("realm_source = %q, want %q", field.String, registerRealmSource3GPPDerived)
	}
	if _, ok := registerDiagnosticAllowedFieldKeys()["realm_source"]; !ok {
		t.Fatal("realm_source is emitted but not whitelisted")
	}
}

// A hostile or non-enum realm-source value must be clamped before logging.
func TestRegisterDiagnosticsClampRealmSource(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	logRegisterDiagnostic(registerDiagnostic{
		stage:       "config_resolved",
		result:      "none",
		realmSource: "synthetic-should-not-appear",
	})

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic entry count = %d, want 1", len(entries))
	}
	for _, field := range entries[0].Context {
		if field.Key != "realm_source" {
			continue
		}
		if field.String != registerRealmSourceUnknown {
			t.Fatalf("realm_source = %q, want clamped %q", field.String, registerRealmSourceUnknown)
		}
		return
	}
	t.Fatal("realm_source field was not emitted")
}
