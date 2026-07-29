package smscodec

import (
	"bytes"
	"testing"
)

func TestBuildRPDataStrictNormalizesOnlyNumericServiceCentreAddress(t *testing.T) {
	tpdu := []byte{0x01, 0x02}
	canonical, err := BuildRPDataStrict(7, tpdu, "+12345")
	if err != nil {
		t.Fatalf("canonical service-centre address: %v", err)
	}
	for _, input := range []string{
		"tel:+12345",
		"+1 (23)-45",
		"sip:+12345@ims.example.invalid;user=phone",
	} {
		got, err := BuildRPDataStrict(7, tpdu, input)
		if err != nil {
			t.Fatalf("normalizable service-centre address rejected: %v", err)
		}
		if !bytes.Equal(got, canonical) {
			t.Fatal("normalized service-centre address changed RP-DATA bytes")
		}
	}

	for _, input := range []string{
		"",
		"sip:smsc@ims.example.invalid",
		"not-a-number",
	} {
		if _, err := BuildRPDataStrict(7, tpdu, input); err == nil {
			t.Fatal("non-numeric service-centre address was accepted")
		}
	}
}

func TestBuildRPDataStrictRejectsTPDUAboveRPUserDataLimit(t *testing.T) {
	if _, err := BuildRPDataStrict(7, make([]byte, 232), "+12345"); err != nil {
		t.Fatalf("232-byte TPDU was rejected: %v", err)
	}
	if _, err := BuildRPDataStrict(7, make([]byte, 233), "+12345"); err == nil {
		t.Fatal("233-byte TPDU exceeded the RP-User-Data limit but was accepted")
	}
}
