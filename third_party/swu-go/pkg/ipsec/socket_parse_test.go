package ipsec

import (
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestParseIKEPayloadWithAndWithoutMarker(t *testing.T) {
	p := ikev2.NewIKEPacket()
	p.Header.SPIi = 0x1122334455667788
	p.Header.SPIr = 0
	p.Header.Version = 0x20
	p.Header.ExchangeType = ikev2.IKE_SA_INIT
	p.Header.Flags = ikev2.FlagInitiator
	p.Header.MessageID = 0

	raw, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if got, ok := parseIKEPayload(raw); !ok || len(got) != len(raw) {
		t.Fatalf("expected plain IKE to be detected")
	}

	withMarker := append([]byte{0, 0, 0, 0}, raw...)
	got, ok := parseIKEPayload(withMarker)
	if !ok {
		t.Fatalf("expected marker IKE to be detected")
	}
	if len(got) != len(raw) {
		t.Fatalf("expected marker to be stripped")
	}
}

func TestParseIKEPayloadRejectsNonIKE(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0xff, 0xff, 0xff, 0xff}
	if _, ok := parseIKEPayload(data); ok {
		t.Fatalf("expected non-IKE to be rejected")
	}
}
