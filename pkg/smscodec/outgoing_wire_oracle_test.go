package smscodec

import "testing"

func TestOutgoingSMSWireMatchesIndependentOracle(t *testing.T) {
	tpdus, _, err := BuildSubmitTPDUs("+1234567", "HELLO")
	if err != nil {
		t.Fatalf("BuildSubmitTPDUs: %v", err)
	}
	if len(tpdus) != 1 {
		t.Fatalf("parts = %d, want 1", len(tpdus))
	}

	submit := parseSubmitWireOracle(t, tpdus[0])
	if submit.firstOctet&0x03 != 0x01 || submit.firstOctet&0x10 != 0 {
		t.Fatal("TPDU is not SMS-SUBMIT with no validity period")
	}
	if submit.firstOctet&0x04 != 0 || submit.firstOctet&0x20 != 0 || submit.firstOctet&0x40 != 0 {
		t.Fatal("unexpected TP-RD, TP-SRR, or TP-UDHI flag")
	}
	if submit.toa != 0x91 || submit.destination != "+1234567" {
		t.Fatal("international TP-DA classification mismatch")
	}
	if submit.pid != 0 || submit.dcs != 0 || submit.udl != 5 || submit.text != "HELLO" {
		t.Fatal("SMS-SUBMIT PID/DCS/UDL/GSM7 mismatch")
	}

	const rpMR = 0x2a
	rpdu, err := BuildRPDataStrict(rpMR, tpdus[0], "+7654321")
	if err != nil {
		t.Fatalf("BuildRPDataStrict: %v", err)
	}
	assertRPDataWireOracle(t, rpdu, rpMR, "+7654321", tpdus[0])
}

type submitWireOracle struct {
	firstOctet  byte
	toa         byte
	destination string
	pid         byte
	dcs         byte
	udl         int
	text        string
}

func parseSubmitWireOracle(t *testing.T, pdu []byte) submitWireOracle {
	t.Helper()
	if len(pdu) < 8 {
		t.Fatal("SMS-SUBMIT is shorter than mandatory fields")
	}
	offset := 0
	firstOctet := pdu[offset]
	offset++
	offset++ // TP-MR
	digitCount := int(pdu[offset])
	offset++
	toa := pdu[offset]
	offset++
	bcdOctets := (digitCount + 1) / 2
	if digitCount <= 0 || offset+bcdOctets+3 > len(pdu) {
		t.Fatal("TP-DA exceeds SMS-SUBMIT")
	}
	destination := decodeSemiOctetsOracle(t, pdu[offset:offset+bcdOctets], digitCount, toa)
	offset += bcdOctets
	pid := pdu[offset]
	offset++
	dcs := pdu[offset]
	offset++
	if firstOctet&0x18 != 0 {
		t.Fatal("wire oracle fixture unexpectedly carries TP-VP")
	}
	udl := int(pdu[offset])
	offset++
	userDataOctets := (udl*7 + 7) / 8
	if offset+userDataOctets != len(pdu) {
		t.Fatal("GSM7 TP-UD length does not match TP-UDL")
	}
	text := unpackGSM7ASCIIOracle(t, pdu[offset:], udl)
	return submitWireOracle{
		firstOctet:  firstOctet,
		toa:         toa,
		destination: destination,
		pid:         pid,
		dcs:         dcs,
		udl:         udl,
		text:        text,
	}
}

func assertRPDataWireOracle(t *testing.T, rpdu []byte, rpMR byte, wantSC string, wantTPDU []byte) {
	t.Helper()
	if len(rpdu) < 6 || rpdu[0] != 0x00 || rpdu[1] != rpMR {
		t.Fatal("RP-DATA header mismatch")
	}
	offset := 2
	oaLength := int(rpdu[offset])
	offset++
	if oaLength != 0 {
		t.Fatal("mobile-originated RP-DATA must have an empty RP-OA")
	}
	if offset >= len(rpdu) {
		t.Fatal("RP-DATA is missing RP-DA")
	}
	daLength := int(rpdu[offset])
	offset++
	if daLength < 2 || offset+daLength >= len(rpdu) {
		t.Fatal("RP-DA exceeds RP-DATA")
	}
	toa := rpdu[offset]
	if toa != 0x91 {
		t.Fatal("RP-DA TOA is not international/ISDN")
	}
	digits := (daLength - 1) * 2
	bcd := rpdu[offset+1 : offset+daLength]
	if len(bcd) > 0 && bcd[len(bcd)-1]&0xf0 == 0xf0 {
		digits--
	}
	if got := decodeSemiOctetsOracle(t, bcd, digits, toa); got != wantSC {
		t.Fatal("RP-DA service-centre address mismatch")
	}
	offset += daLength
	if offset >= len(rpdu) {
		t.Fatal("RP-DATA is missing RP-User-Data length")
	}
	userDataLength := int(rpdu[offset])
	offset++
	if userDataLength != len(wantTPDU) || offset+userDataLength != len(rpdu) {
		t.Fatal("RP-User-Data length mismatch")
	}
	for index := range wantTPDU {
		if rpdu[offset+index] != wantTPDU[index] {
			t.Fatal("RP-User-Data changed the SMS-SUBMIT TPDU")
		}
	}
}

func decodeSemiOctetsOracle(t *testing.T, encoded []byte, digits int, toa byte) string {
	t.Helper()
	if digits < 0 || (digits+1)/2 != len(encoded) {
		t.Fatal("semi-octet length mismatch")
	}
	out := make([]byte, 0, digits+1)
	if toa&0x70 == 0x10 {
		out = append(out, '+')
	}
	for index := 0; index < digits; index++ {
		nibble := encoded[index/2] & 0x0f
		if index%2 == 1 {
			nibble = encoded[index/2] >> 4
		}
		if nibble > 9 {
			t.Fatal("non-decimal semi-octet")
		}
		out = append(out, '0'+nibble)
	}
	return string(out)
}

func unpackGSM7ASCIIOracle(t *testing.T, packed []byte, septets int) string {
	t.Helper()
	out := make([]byte, septets)
	for index := 0; index < septets; index++ {
		bitOffset := index * 7
		byteOffset := bitOffset / 8
		shift := uint(bitOffset % 8)
		if byteOffset >= len(packed) {
			t.Fatal("GSM7 septet exceeds packed user data")
		}
		value := packed[byteOffset] >> shift
		if shift > 1 {
			if byteOffset+1 >= len(packed) {
				t.Fatal("GSM7 septet crosses missing octet")
			}
			value |= packed[byteOffset+1] << (8 - shift)
		}
		value &= 0x7f
		if value < 0x20 || value > 0x7e {
			t.Fatal("wire oracle fixture decoded outside printable GSM7 ASCII subset")
		}
		out[index] = value
	}
	return string(out)
}
