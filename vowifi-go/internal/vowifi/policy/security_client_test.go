package policy

import (
	"strings"
	"testing"
)

func TestBuildSecurityClientHeaderGiffgaff(t *testing.T) {
	tmpl := DefaultGiffgaffTemplate()
	got := BuildSecurityClientHeader(tmpl, 1389119324, 1486172233, 43661, 40137)

	if strings.Count(got, "ipsec-3gpp") != 6 {
		t.Fatalf("expected 6 mechanisms, got %q", got)
	}
	for _, want := range []string{
		"alg=hmac-md5-96;ealg=des-ede3-cbc",
		"alg=hmac-md5-96;ealg=aes-cbc",
		"alg=hmac-md5-96;ealg=null",
		"alg=hmac-sha-1-96;ealg=des-ede3-cbc",
		"alg=hmac-sha-1-96;ealg=aes-cbc",
		"alg=hmac-sha-1-96;ealg=null",
		"spi-c=1389119324",
		"spi-s=1486172233",
		"port-c=43661",
		"port-s=40137",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("header %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "; ") {
		t.Fatalf("header %q still contains spaced parameters", got)
	}
}

func TestBuildSecurityClientHeaderUsesDefaultsWhenEmpty(t *testing.T) {
	got := BuildSecurityClientHeader(IMSRegisterTemplate{}, 1, 2, 3, 4)
	if strings.Count(got, "ipsec-3gpp") != 6 {
		t.Fatalf("expected default mechanisms, got %q", got)
	}
	if strings.Contains(got, "; ") {
		t.Fatalf("header %q still contains spaced parameters", got)
	}
}

func TestBuildSecurityClientHeaderCompactQualcommOrder(t *testing.T) {
	got := BuildSecurityClientHeader(IMSRegisterTemplate{
		SecurityClientMechanisms: []IPSec3GPPSecurityMechanism{
			{Alg: "hmac-sha-1-96", EAlg: "null", Prot: "esp", Mode: "trans"},
		},
	}, 10, 11, 5062, 5063)
	want := "ipsec-3gpp;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=null;spi-c=10;spi-s=11;port-c=5062;port-s=5063"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
