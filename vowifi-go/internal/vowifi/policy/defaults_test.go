package policy

import "testing"

func TestResolveCarrierBehaviorPLMNMappings(t *testing.T) {
	tests := []struct {
		name   string
		mcc    string
		mnc    string
		wantID string
	}{
		{name: "unknown US PLMN", mcc: "310", mnc: "240", wantID: "3gpp-default"},
		{name: "unknown PLMN with zero MNC", mcc: "454", mnc: "00", wantID: "3gpp-default"},
		{name: "Giffgaff", mcc: "234", mnc: "010", wantID: "giffgaff"},
		{name: "Vodafone UK", mcc: "234", mnc: "015", wantID: "vodafone_uk_23415"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveCarrierBehavior(tt.mcc, tt.mnc).RegisterTemplate.ID; got != tt.wantID {
				t.Fatalf("template ID = %q, want %q", got, tt.wantID)
			}
		})
	}
}

func TestResolveCarrierBehaviorVodafoneUK(t *testing.T) {
	tmpl := ResolveCarrierBehavior("234", "15").RegisterTemplate

	if tmpl.ID != "vodafone_uk_23415" {
		t.Fatalf("template ID = %q, want vodafone_uk_23415", tmpl.ID)
	}
	if tmpl.SecAgreeMode != "on" {
		t.Fatalf("SecAgreeMode = %q, want on", tmpl.SecAgreeMode)
	}
	if !tmpl.UsePlainDigestPlaceholder {
		t.Fatal("Vodafone UK initial REGISTER must use the AKA empty Authorization handset profile")
	}
	if tmpl.IncludePANI || tmpl.IncludePANIAuthenticated {
		t.Fatal("Vodafone UK initial REGISTER must omit P-Access-Network-Info")
	}
}
