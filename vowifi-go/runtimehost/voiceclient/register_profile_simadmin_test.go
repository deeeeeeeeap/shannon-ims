package voiceclient

import "testing"

func TestBuildIMSIdentityHomeDomain(t *testing.T) {
	privateID, publicURI := BuildIMSIdentity(
		"001010000000001",
		"ims.mnc001.mcc001.3gppnetwork.org",
		"ims.mnc001.mcc001.3gppnetwork.org",
		"imsi_home_domain",
	)
	if privateID != "001010000000001@ims.mnc001.mcc001.3gppnetwork.org" {
		t.Fatalf("private id = %q", privateID)
	}
	if publicURI != "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org" {
		t.Fatalf("public uri = %q", publicURI)
	}
}

func TestSimAdminGBEERegisterVariantsCount(t *testing.T) {
	if len(registerVariantsForProfile(SimAdminGBEERegisterProfile())) != 11 {
		t.Fatalf("expected 11 variants, got %d", len(registerVariantsForProfile(SimAdminGBEERegisterProfile())))
	}
}

func TestBuildAkaZeroAuthorization(t *testing.T) {
	cfg := Config{
		PrivateID: "001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
		Realm:     "ims.mnc001.mcc001.3gppnetwork.org",
	}
	profile := RegisterProfile{InitialAuthorization: "aka_zero_response_uri_first"}
	auth := buildInitialAuthorization(cfg, profile, "sip:ims.mnc001.mcc001.3gppnetwork.org")
	if auth == "" {
		t.Fatal("empty authorization")
	}
	for _, want := range []string{
		`response="00000000000000000000000000000000"`,
		"001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
	} {
		if !containsSubstring(auth, want) {
			t.Fatalf("authorization %q missing %q", auth, want)
		}
	}
}