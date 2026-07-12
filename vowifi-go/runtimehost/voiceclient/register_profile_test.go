package voiceclient

import (
	"net"
	"testing"
)

func TestGBEERegisterVariants(t *testing.T) {
	variants := gbEERegisterVariants()
	if len(variants) != 11 {
		t.Fatalf("expected 11 SimAdmin GB EE variants, got %d", len(variants))
	}
	if variants[0].InitialAuthorization != "aka_empty_uri_first" {
		t.Fatalf("first variant auth = %q", variants[0].InitialAuthorization)
	}
}

func TestRegisterProfileForGiffgaff(t *testing.T) {
	cfg := Config{MCC: "234", MNC: "10"}
	profile := registerProfileForConfig(cfg).Normalized()
	if profile.ContactFeatures != "ims_features" {
		t.Fatalf("contact features = %q, want ims_features", profile.ContactFeatures)
	}
	if !profile.IncludeCellularNetwork {
		t.Fatal("expected cellular network info for giffgaff")
	}
	if profile.InitialAuthorization != "aka_empty_uri_first" {
		t.Fatalf("initial auth = %q", profile.InitialAuthorization)
	}
}

func TestBuildCellularNetworkInfoPlaceholder(t *testing.T) {
	got := buildCellularNetworkInfo("23410", "")
	want := "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=234100000000;cell-info-age=0"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildGBEEContactHeader(t *testing.T) {
	cfg := Config{
		PublicURI: "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
		PrivateID: "001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
		LocalIP:   parseIP("2a02:800:8000:c000:0:0:0:1"),
		Transport: "tcp",
	}
	profile := DefaultGBEERegisterProfile()
	header := cfg.buildContactHeader(profile, "urn:uuid:test", "")
	if header == "" {
		t.Fatal("empty contact header")
	}
	for _, want := range []string{`+g.3gpp.icsi-ref=`, `+sip.instance=`, "audio", "expires=3600"} {
		if !containsSubstring(header, want) {
			t.Fatalf("contact header %q missing %q", header, want)
		}
	}
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

func containsSubstring(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexSubstring(s, sub) >= 0)
}

func indexSubstring(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}