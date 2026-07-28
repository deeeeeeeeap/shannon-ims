package policy

import "testing"

func TestResolveCarrierBehaviorPreservesValidatedCarrierDecisions(t *testing.T) {
	tests := []struct {
		name                      string
		mcc                       string
		mnc                       string
		wantTemplateID            string
		wantUnprotectedAuto       UnprotectedRegisterTransportPolicy
		wantProtectedAuto         ProtectedRegisterTransportPolicy
		wantWireFormat            RegisterWireFormat
		wantMessagingPresentation MessagingPresentation
	}{
		{
			name:                      "US 310/240 generic 3GPP",
			mcc:                       "310",
			mnc:                       "240",
			wantTemplateID:            "3gpp-default",
			wantUnprotectedAuto:       UnprotectedRegisterUDPThenTCP,
			wantProtectedAuto:         ProtectedRegisterSizeAware,
			wantWireFormat:            RegisterWireStandard,
			wantMessagingPresentation: MessagingPresentationSimAdminGBEE,
		},
		{
			name:                      "specialized 234/15",
			mcc:                       "234",
			mnc:                       "15",
			wantTemplateID:            "vodafone_uk_23415",
			wantUnprotectedAuto:       UnprotectedRegisterUDPThenTCP,
			wantProtectedAuto:         ProtectedRegisterUDPOnly,
			wantWireFormat:            RegisterWireVodafoneUK,
			wantMessagingPresentation: MessagingPresentationSimAdminGBEE,
		},
		{
			name:                      "specialized normalized 234/015",
			mcc:                       "234",
			mnc:                       "015",
			wantTemplateID:            "vodafone_uk_23415",
			wantUnprotectedAuto:       UnprotectedRegisterUDPThenTCP,
			wantProtectedAuto:         ProtectedRegisterUDPOnly,
			wantWireFormat:            RegisterWireVodafoneUK,
			wantMessagingPresentation: MessagingPresentationSimAdminGBEE,
		},
		{
			name:                      "Giffgaff 234/10 compatibility",
			mcc:                       "234",
			mnc:                       "10",
			wantTemplateID:            "giffgaff",
			wantUnprotectedAuto:       UnprotectedRegisterTCPOnly,
			wantProtectedAuto:         ProtectedRegisterUDPOnly,
			wantWireFormat:            RegisterWireStandard,
			wantMessagingPresentation: MessagingPresentationSimAdminGBEE,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			behavior := ResolveCarrierBehavior(tt.mcc, tt.mnc)
			if behavior.RegisterTemplate.ID != tt.wantTemplateID ||
				behavior.UnprotectedAutoTransport != tt.wantUnprotectedAuto ||
				behavior.ProtectedAutoTransport != tt.wantProtectedAuto ||
				behavior.RegisterWireFormat != tt.wantWireFormat ||
				behavior.MessagingPresentation != tt.wantMessagingPresentation {
				t.Fatalf("carrier behavior = %+v, want template=%s unprotected=%s protected=%s wire=%s messaging=%s",
					behavior,
					tt.wantTemplateID,
					tt.wantUnprotectedAuto,
					tt.wantProtectedAuto,
					tt.wantWireFormat,
					tt.wantMessagingPresentation,
				)
			}
		})
	}
}
