package voiceclient

import (
	"strings"
	"testing"
)

func TestXiaomiMi11RegisterProfile(t *testing.T) {
	profile := XiaomiMi11RegisterProfile()
	if profile.ContactFeatures != "phone_xiaomi" {
		t.Fatalf("ContactFeatures = %q", profile.ContactFeatures)
	}
	if profile.UserAgent != "_M2011K2G_Qualcomm_1690275146_Android13" {
		t.Fatalf("UserAgent = %q", profile.UserAgent)
	}
	if profile.IncludeRoute || profile.IncludePAccessNetworkInfo || profile.IncludePVisitedNetworkID {
		t.Fatal("phone profile should omit route/pani/p-visited-network-id")
	}
	if profile.RegisterExpirySeconds != 600000 {
		t.Fatalf("RegisterExpirySeconds = %d", profile.RegisterExpirySeconds)
	}
}

func TestFormatGSMAIMEIURN(t *testing.T) {
	got := FormatGSMAIMEIURN("869988776655443")
	want := "urn:gsma:imei:8699887-766554-4"
	if got != want {
		t.Fatalf("FormatGSMAIMEIURN() = %q, want %q", got, want)
	}
}

func TestBuildPhoneContactHeader(t *testing.T) {
	cfg := Config{
		PublicURI: "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
		PrivateID: "001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
		LocalIP:   parseIP("2a03:dd00:130e:b989:d078:baff:febd:9661"),
		Transport: "tcp",
	}
	profile := XiaomiMi11RegisterProfile()
	header := cfg.buildContactHeader(profile, "urn:gsma:imei:8699887-766554-4", "49400748-008d-44e9-a258-2fae9bb4b2be")
	for _, want := range []string{
		`+g.3gpp.accesstype="wlan1"`,
		"audio",
		`urn:gsma:imei:8699887-766554-4`,
		"expires=600000",
	} {
		if !strings.Contains(header, want) {
			t.Fatalf("contact header %q missing %q", header, want)
		}
	}
	if strings.Contains(header, "smsip") {
		t.Fatalf("phone contact should not include smsip: %q", header)
	}
}

func TestBuildPhoneSecurityClient(t *testing.T) {
	state := securityClientState{spiC: 1, spiS: 2, portC: 100, portS: 200}
	got := buildSecurityClientHeader(XiaomiMi11RegisterProfile(), state)
	if !strings.Contains(got, "hmac-md5-96") || !strings.Contains(got, "hmac-sha-1-96") {
		t.Fatalf("expected md5 and sha1 variants: %q", got)
	}
	if strings.Count(got, "ipsec-3gpp") != 6 {
		t.Fatalf("expected 6 security-client variants, got %q", got)
	}
}