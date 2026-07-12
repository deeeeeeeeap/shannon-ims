package ipsec3gpp

import (
	"strings"
	"testing"
)

func TestParseSecurityMechanisms(t *testing.T) {
	header := strings.Join([]string{
		"ipsec-3gpp; alg=hmac-md5-96; ealg=des-ede3-cbc; spi-c=100; spi-s=200; port-c=6100; port-s=6101",
		"ipsec-3gpp; alg=hmac-sha-1-96; ealg=aes-cbc; prot=esp; mod=trans; spi-c=153296183; spi-s=161970575; port-c=6054; port-s=6060",
	}, ",")
	mechs, err := ParseSecurityMechanisms(header)
	if err != nil {
		t.Fatalf("ParseSecurityMechanisms: %v", err)
	}
	if len(mechs) != 2 {
		t.Fatalf("got %d mechanisms, want 2", len(mechs))
	}
	got := mechs[1]
	if got.Alg != "hmac-sha-1-96" || got.EAlg != "aes-cbc" {
		t.Fatalf("unexpected algorithms: %+v", got)
	}
	if got.SPIc != 153296183 || got.SPIs != 161970575 || got.PortC != 6054 || got.PortS != 6060 {
		t.Fatalf("unexpected spi/ports: %+v", got)
	}
	if got.Prot != "esp" || got.Mode != "trans" {
		t.Fatalf("unexpected prot/mod: %+v", got)
	}
}

func TestFormatSecurityMechanism(t *testing.T) {
	raw := FormatSecurityMechanism(SecurityMechanism{
		Alg:   "hmac-sha-1-96",
		EAlg:  "aes-cbc",
		Prot:  "esp",
		Mode:  "trans",
		SPIc:  1,
		SPIs:  2,
		PortC: 6054,
		PortS: 6060,
	})
	mech, err := ParseSecurityMechanism(raw)
	if err != nil {
		t.Fatalf("ParseSecurityMechanism: %v", err)
	}
	if mech.SPIc != 1 || mech.SPIs != 2 || mech.PortC != 6054 || mech.PortS != 6060 {
		t.Fatalf("round-trip mismatch: %+v", mech)
	}
}