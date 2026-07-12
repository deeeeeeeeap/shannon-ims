package policy

import "testing"

func TestResolveIMSRegisterTemplateVodafoneUK(t *testing.T) {
	tmpl := ResolveIMSRegisterTemplate("234", "15")

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
