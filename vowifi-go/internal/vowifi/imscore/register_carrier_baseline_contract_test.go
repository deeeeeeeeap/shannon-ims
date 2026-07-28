package imscore

import (
	"slices"
	"testing"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/1239t/vowifi-go/runtimehost/carrier"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

func TestCarrierRegisterBaselineContract(t *testing.T) {
	tests := []struct {
		name                                string
		mcc                                 string
		mncs                                []string
		wantTemplateID                      string
		wantPresetID                        string
		wantTemplateUserAgent               string
		wantResolvedUserAgent               string
		wantContactParamOrder               []string
		wantRequireSecAgree                 bool
		wantProxyRequireSecAgree            bool
		wantRetryWithoutRequiredSecAgree    bool
		wantProbeSecurityClientOnBadRequest bool
		wantOmitRoute                       bool
		wantProtectedTransport              string
		wantProtectedReason                 string
	}{
		{
			name:                             "US 310/240 generic 3GPP",
			mcc:                              "310",
			mncs:                             []string{"240"},
			wantTemplateID:                   "3gpp-default",
			wantPresetID:                     "3gpp-default",
			wantResolvedUserAgent:            "SimAdmin VoWiFi",
			wantContactParamOrder:            []string{"access_type", "audio", "smsip", "icsi_ref", "sip_instance"},
			wantRequireSecAgree:              true,
			wantProxyRequireSecAgree:         true,
			wantRetryWithoutRequiredSecAgree: true,
			wantProtectedTransport:           protectedTransportTCP,
			wantProtectedReason:              protectedTransportReasonESPOverBudget,
		},
		{
			name:                                "specialized preset 234/15",
			mcc:                                 "234",
			mncs:                                []string{"15", "015"},
			wantTemplateID:                      "vodafone_uk_23415",
			wantPresetID:                        "3gpp-default",
			wantTemplateUserAgent:               "Vodafone VOLTE Qualcomm",
			wantResolvedUserAgent:               "Vodafone VOLTE Qualcomm",
			wantContactParamOrder:               []string{"access_type", "audio", "smsip", "icsi_ref", "sip_instance", "reg_id"},
			wantProbeSecurityClientOnBadRequest: true,
			wantOmitRoute:                       true,
			wantProtectedTransport:              protectedTransportUDP,
			wantProtectedReason:                 protectedTransportReasonTemplateOptOut,
		},
	}

	for _, tt := range tests {
		for _, mnc := range tt.mncs {
			t.Run(tt.name+"/mnc_"+mnc, func(t *testing.T) {
				behavior := policy.ResolveCarrierBehavior(tt.mcc, mnc)
				template := behavior.RegisterTemplate
				if template.ID != tt.wantTemplateID {
					t.Fatalf("template ID = %q, want %q", template.ID, tt.wantTemplateID)
				}
				if template.SecAgreeMode != "on" {
					t.Fatalf("SecAgreeMode = %q, want on", template.SecAgreeMode)
				}
				if !template.UsePlainDigestPlaceholder || !template.MinimalInitialHeaders ||
					!template.StrictSecurityServerOffer {
					t.Fatal("baseline REGISTER template invariants are not enabled")
				}
				if template.SupportedHeader != "path,sec-agree" {
					t.Fatalf("SupportedHeader = %q, want path,sec-agree", template.SupportedHeader)
				}
				if len(template.SecurityClientMechanisms) != 6 {
					t.Fatalf("SecurityClient mechanism count = %d, want 6", len(template.SecurityClientMechanisms))
				}
				if template.UserAgent != tt.wantTemplateUserAgent {
					t.Fatalf("template UserAgent metadata = %q, want %q", template.UserAgent, tt.wantTemplateUserAgent)
				}
				if !slices.Equal(template.ContactParamOrder, tt.wantContactParamOrder) {
					t.Fatalf("ContactParamOrder = %v, want %v", template.ContactParamOrder, tt.wantContactParamOrder)
				}
				if template.RequireSecAgree != tt.wantRequireSecAgree ||
					template.ProxyRequireSecAgree != tt.wantProxyRequireSecAgree ||
					template.RetryInitialWithoutRequiredSecAgreeOnBadRequest != tt.wantRetryWithoutRequiredSecAgree ||
					template.ProbeInitialSecurityClientOnBadRequest != tt.wantProbeSecurityClientOnBadRequest ||
					template.OmitRoute != tt.wantOmitRoute {
					t.Fatal("carrier-specific REGISTER template metadata changed")
				}

				effective := carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{
					MCC: tt.mcc,
					MNC: mnc,
				})
				if effective.PresetID != tt.wantPresetID {
					t.Fatalf("carrier preset ID = %q, want %q", effective.PresetID, tt.wantPresetID)
				}
				if effective.EPDGAddr != "" || effective.AKAAppPreference != "" ||
					effective.E911.Enabled || effective.E911.Provider != "" {
					t.Fatal("unexpected optional carrier override metadata")
				}
				profile := carrier.ResolveIMSRegisterProfile(tt.mcc, mnc)
				if profile.Profile != (voiceclient.RegisterProfile{}) ||
					profile.SIPInstanceURN != "" || profile.RegisterExpiry != 0 {
					t.Fatal("unexpected optional REGISTER profile override metadata")
				}

				voiceCfg := voiceclient.Config{Transport: "auto"}
				voiceCfg.RegisterProfile.UserAgent = template.UserAgent
				imsCfg := IMSConfigFromVoice(voiceCfg, behavior, effective.PresetID)
				if imsCfg.CarrierPresetID != tt.wantPresetID ||
					imsCfg.CarrierBehavior.RegisterTemplate.ID != tt.wantTemplateID ||
					imsCfg.IMSRegisterPolicySource != "default" ||
					imsCfg.Transport != "auto" ||
					imsCfg.UserAgent != tt.wantResolvedUserAgent {
					t.Fatal("IMSConfig carrier baseline metadata changed")
				}

				cfg := internalConfigFromIMS(imsCfg, StartSessionInput{MCC: tt.mcc, MNC: mnc})
				if cfg.CarrierBehavior.RegisterTemplate.ID != tt.wantTemplateID || cfg.UserAgent != tt.wantResolvedUserAgent {
					t.Fatal("internal IMS config did not preserve carrier metadata")
				}
				if got := registerTransportCandidates(cfg, imsCfg.Transport); !slices.Equal(got, []string{"udp", "tcp"}) {
					t.Fatalf("unprotected auto transports = %v, want [udp tcp]", got)
				}

				plan, err := decideProtectedRegisterTransport(
					cfg,
					"auto",
					protectedRegisterMaxUnfragmentedSIPLen+1,
				)
				if err != nil {
					t.Fatalf("protected transport decision: %v", err)
				}
				if plan.Transport != tt.wantProtectedTransport || plan.Reason != tt.wantProtectedReason {
					t.Fatalf(
						"protected auto decision = %s/%s, want %s/%s",
						plan.Transport,
						plan.Reason,
						tt.wantProtectedTransport,
						tt.wantProtectedReason,
					)
				}
			})
		}
	}
}
