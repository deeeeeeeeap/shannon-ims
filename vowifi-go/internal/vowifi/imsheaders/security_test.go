package imsheaders

import (
	"errors"
	"strings"
	"testing"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

const sampleSecurityServer = "ipsec-3gpp;q=0.88;alg=hmac-md5-96;mod=trans," +
	"ipsec-3gpp;q=0.9;alg=hmac-md5-96;mod=trans;ealg=des-ede3-cbc," +
	"ipsec-3gpp;q=0.92;alg=hmac-md5-96;mod=trans;ealg=aes-cbc," +
	"ipsec-3gpp;q=0.94;alg=hmac-sha-1-96;mod=trans," +
	"ipsec-3gpp;q=0.96;alg=hmac-sha-1-96;mod=trans;ealg=des-ede3-cbc," +
	"ipsec-3gpp;q=0.98;alg=hmac-sha-1-96;mod=trans;ealg=aes-cbc;spi-c=111060141;spi-s=117229022;port-c=6050;port-s=6060"

func TestBuildSecurityVerifyEcho(t *testing.T) {
	offers, err := ParseSecurityServer(sampleSecurityServer)
	if err != nil {
		t.Fatalf("ParseSecurityServer: %v", err)
	}
	got := BuildSecurityVerifyEcho(offers)
	if strings.Count(got, "ipsec-3gpp") != 6 {
		t.Fatalf("echo count = %d, got %q", strings.Count(got, "ipsec-3gpp"), got)
	}
	if !strings.Contains(got, "spi-c=111060141") {
		t.Fatalf("missing shared server params: %q", got)
	}
}

func TestParseSecurityServer(t *testing.T) {
	offers, err := ParseSecurityServer(sampleSecurityServer)
	if err != nil {
		t.Fatalf("ParseSecurityServer: %v", err)
	}
	if len(offers) != 6 {
		t.Fatalf("offers = %d, want 6", len(offers))
	}

	last := offers[5]
	if last.Q != 0.98 {
		t.Fatalf("last q = %v, want 0.98", last.Q)
	}
	if last.Alg != "hmac-sha-1-96" || last.EAlg != "aes-cbc" {
		t.Fatalf("last mechanism = %+v", last.SecurityMechanism)
	}
	if last.SPIC != 111060141 || last.SPIS != 117229022 || last.PortC != 6050 || last.PortS != 6060 {
		t.Fatalf("last server params = %+v", last)
	}

	for i, offer := range offers {
		if offer.SPIC != 111060141 || offer.SPIS != 117229022 || offer.PortC != 6050 || offer.PortS != 6060 {
			t.Fatalf("offer[%d] missing propagated server params: %+v", i, offer)
		}
	}

	nullOffer := offers[0]
	if nullOffer.EAlg != "null" {
		t.Fatalf("offer without ealg should normalize to null, got %q", nullOffer.EAlg)
	}
}

func TestSelectSecurityServerOfferStrict(t *testing.T) {
	offers, err := ParseSecurityServer(sampleSecurityServer)
	if err != nil {
		t.Fatalf("ParseSecurityServer: %v", err)
	}

	selected, err := SelectSecurityServerOffer(offers, policy.DefaultGiffgaffTemplate().SecurityClientMechanisms, true)
	if err != nil {
		t.Fatalf("SelectSecurityServerOffer: %v", err)
	}
	if selected.Alg != "hmac-sha-1-96" || selected.EAlg != "aes-cbc" || selected.Q != 0.98 {
		t.Fatalf("selected = %+v, want hmac-sha-1-96/aes-cbc q=0.98", selected)
	}
}

func TestSelectSecurityServerOfferStrictNoMatch(t *testing.T) {
	offers, err := ParseSecurityServer(sampleSecurityServer)
	if err != nil {
		t.Fatalf("ParseSecurityServer: %v", err)
	}

	client := []policy.IPSec3GPPSecurityMechanism{
		{Alg: "hmac-sha-256-128", EAlg: "aes-cbc"},
	}
	_, err = SelectSecurityServerOffer(offers, client, true)
	if !errors.Is(err, ErrNoMatchingSecurityOffer) {
		t.Fatalf("err = %v, want %v", err, ErrNoMatchingSecurityOffer)
	}
}

func TestSelectSecurityServerOfferNonStrictFallback(t *testing.T) {
	offers, err := ParseSecurityServer(sampleSecurityServer)
	if err != nil {
		t.Fatalf("ParseSecurityServer: %v", err)
	}

	client := []policy.IPSec3GPPSecurityMechanism{
		{Alg: "hmac-sha-256-128", EAlg: "aes-cbc"},
	}
	selected, err := SelectSecurityServerOffer(offers, client, false)
	if err != nil {
		t.Fatalf("SelectSecurityServerOffer: %v", err)
	}
	if selected.Q != 0.98 {
		t.Fatalf("fallback selected q = %v, want 0.98", selected.Q)
	}
}

func TestBuildSecurityVerify(t *testing.T) {
	offers, err := ParseSecurityServer(sampleSecurityServer)
	if err != nil {
		t.Fatalf("ParseSecurityServer: %v", err)
	}
	selected, err := SelectSecurityServerOffer(offers, policy.DefaultGiffgaffTemplate().SecurityClientMechanisms, true)
	if err != nil {
		t.Fatalf("SelectSecurityServerOffer: %v", err)
	}

	got := BuildSecurityVerify(*selected)
	for _, want := range []string{
		"ipsec-3gpp",
		"q=0.98",
		"alg=hmac-sha-1-96",
		"mod=trans",
		"ealg=aes-cbc",
		"spi-c=111060141",
		"spi-s=117229022",
		"port-c=6050",
		"port-s=6060",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("verify %q missing %q", got, want)
		}
	}
}