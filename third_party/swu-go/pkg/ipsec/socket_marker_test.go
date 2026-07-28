package ipsec

import (
	"encoding/binary"
	"testing"
)

func TestNATMarkerStrippedForESP(t *testing.T) {
	spi := uint32(0x12345678)
	esp := make([]byte, 8)
	binary.BigEndian.PutUint32(esp[0:4], spi)
	withMarker := append([]byte{0, 0, 0, 0}, esp...)

	if _, ok := parseIKEPayload(withMarker); ok {
		t.Fatalf("expected marker ESP to not be detected as IKE")
	}

	data := withMarker
	if len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == 0 {
		data = data[4:]
	}
	gotSPI := binary.BigEndian.Uint32(data[0:4])
	if gotSPI != spi {
		t.Fatalf("expected SPI %08x, got %08x", spi, gotSPI)
	}
}
