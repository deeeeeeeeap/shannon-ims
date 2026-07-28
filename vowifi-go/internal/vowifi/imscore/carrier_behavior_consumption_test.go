package imscore

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

func TestUnprotectedAutoTransportConsumesCarrierBehaviorNotTemplateID(t *testing.T) {
	behavior := policy.ResolveCarrierBehavior("310", "240")
	behavior.RegisterTemplate.ID = "diagnostic-id-must-not-drive-policy"
	cfg := Config{CarrierBehavior: behavior}

	if got := registerTransportCandidates(cfg, "auto"); !slices.Equal(got, []string{"udp", "tcp"}) {
		t.Fatalf("unprotected auto transports = %v, want [udp tcp] from typed CarrierBehavior", got)
	}
}

func TestIMSConfigPreservesResolvedCarrierBehavior(t *testing.T) {
	behavior := policy.ResolveCarrierBehavior("234", "015")
	imsCfg := IMSConfigFromVoice(voiceclient.Config{Transport: "auto"}, behavior, "3gpp-default")
	if imsCfg.CarrierBehavior.RegisterTemplate.ID != "vodafone_uk_23415" ||
		imsCfg.CarrierBehavior.UnprotectedAutoTransport != policy.UnprotectedRegisterUDPThenTCP ||
		imsCfg.CarrierBehavior.ProtectedAutoTransport != policy.ProtectedRegisterUDPOnly ||
		imsCfg.CarrierBehavior.RegisterWireFormat != policy.RegisterWireVodafoneUK {
		t.Fatalf("IMSConfig lost resolved CarrierBehavior: %+v", imsCfg.CarrierBehavior)
	}
	internal := internalConfigFromIMS(imsCfg, StartSessionInput{})
	if internal.CarrierBehavior.RegisterWireFormat != policy.RegisterWireVodafoneUK ||
		internal.CarrierBehavior.MessagingPresentation != policy.MessagingPresentationSimAdminGBEE {
		t.Fatalf("internal Config lost resolved CarrierBehavior: %+v", internal.CarrierBehavior)
	}
}

func TestMessagingPresentationConsumesCarrierBehavior(t *testing.T) {
	for _, behavior := range []policy.CarrierBehavior{
		policy.ResolveCarrierBehavior("310", "240"),
		policy.ResolveCarrierBehavior("234", "15"),
	} {
		behavior.RegisterTemplate.ID = "diagnostic-id-must-not-drive-policy"
		got, err := messagingRegisterProfileForBehavior(behavior)
		if err != nil {
			t.Fatalf("messagingRegisterProfileForBehavior() error = %v", err)
		}
		if want := voiceclient.SimAdminGBEERegisterProfile(); !reflect.DeepEqual(got, want) {
			t.Fatal("messaging presentation changed from the validated profile")
		}
	}
}

func TestInitialRegisterWireFormatConsumesCarrierBehaviorNotTemplateID(t *testing.T) {
	behavior := policy.ResolveCarrierBehavior("234", "15")
	behavior.RegisterTemplate.ID = "3gpp-default"
	cfg := registerSessionTestConfig()
	cfg.CarrierBehavior = behavior
	session := newRegisterSession(cfg, nil, nil, "udp", 0)

	req, err := buildRegisterRequest(cfg, *session.state, true, initialRegisterVariant{})
	if err != nil {
		t.Fatalf("buildRegisterRequest() error = %v", err)
	}
	if err := session.decorateRegisterRequest(req); err != nil {
		t.Fatalf("decorateRegisterRequest() error = %v", err)
	}
	wire := req.String()
	maxForwards := strings.Index(wire, "\r\nMax-Forwards:")
	from := strings.Index(wire, "\r\nFrom:")
	if maxForwards < 0 || from < 0 || maxForwards > from {
		t.Fatal("234/15 initial REGISTER did not use the CarrierBehavior-selected header order")
	}
}

func TestProtectedAutoTransportConsumesCarrierBehaviorNotTemplateID(t *testing.T) {
	tests := []struct {
		name          string
		behavior      policy.CarrierBehavior
		diagnosticID  string
		wantTransport string
	}{
		{
			name:          "generic size-aware",
			behavior:      policy.ResolveCarrierBehavior("310", "240"),
			diagnosticID:  "vodafone_uk_23415",
			wantTransport: protectedTransportTCP,
		},
		{
			name:          "234/15 UDP-only",
			behavior:      policy.ResolveCarrierBehavior("234", "15"),
			diagnosticID:  "3gpp-default",
			wantTransport: protectedTransportUDP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			behavior := tt.behavior
			behavior.RegisterTemplate.ID = tt.diagnosticID
			plan, err := decideProtectedRegisterTransport(
				Config{CarrierBehavior: behavior},
				"auto",
				protectedRegisterMaxUnfragmentedSIPLen+1,
			)
			if err != nil {
				t.Fatalf("decideProtectedRegisterTransport() error = %v", err)
			}
			if plan.Transport != tt.wantTransport {
				t.Fatalf("protected auto transport = %q, want %q from typed CarrierBehavior", plan.Transport, tt.wantTransport)
			}
		})
	}
}
