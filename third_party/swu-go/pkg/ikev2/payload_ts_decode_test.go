package ikev2

import (
	"net"
	"testing"
)

func TestDecodePayloadTSRoundTripIPv4(t *testing.T) {
	ts := &EncryptedPayloadTS{
		IsInitiator: true,
		TrafficSelectors: []*TrafficSelector{
			NewTrafficSelectorIPV4(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 1), 0, 65535),
			NewTrafficSelectorIPV4(net.IPv4(0, 0, 0, 0), net.IPv4(255, 255, 255, 255), 0, 65535),
		},
	}

	raw, err := ts.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodePayloadTS(raw, true)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if !decoded.IsInitiator {
		t.Fatalf("IsInitiator mismatch")
	}
	if len(decoded.TrafficSelectors) != 2 {
		t.Fatalf("selectors count mismatch: %d", len(decoded.TrafficSelectors))
	}
	if decoded.TrafficSelectors[0].TSType != TS_IPV4_ADDR_RANGE {
		t.Fatalf("unexpected selector type: %d", decoded.TrafficSelectors[0].TSType)
	}
	if net.IP(decoded.TrafficSelectors[0].StartAddr).String() != "10.0.0.1" {
		t.Fatalf("start addr mismatch: %s", net.IP(decoded.TrafficSelectors[0].StartAddr).String())
	}
	if net.IP(decoded.TrafficSelectors[1].EndAddr).String() != "255.255.255.255" {
		t.Fatalf("end addr mismatch: %s", net.IP(decoded.TrafficSelectors[1].EndAddr).String())
	}
}
