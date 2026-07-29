package smscodec

import (
	"strings"
	"testing"
)

func TestBuildSubmitTPDUsAdvancesTPMessageReferenceAcrossCalls(t *testing.T) {
	first, _, err := BuildSubmitTPDUs("100", "first")
	if err != nil {
		t.Fatalf("first BuildSubmitTPDUs: %v", err)
	}
	second, _, err := BuildSubmitTPDUs("100", "second")
	if err != nil {
		t.Fatalf("second BuildSubmitTPDUs: %v", err)
	}
	if len(first) != 1 || len(second) != 1 || len(first[0]) < 2 || len(second[0]) < 2 {
		t.Fatalf("unexpected single-part TPDU shape: first=%d second=%d", len(first), len(second))
	}

	firstMR := first[0][1]
	secondMR := second[0][1]
	if secondMR != firstMR+1 {
		t.Fatalf("TP-MR did not advance across calls: first=%d second=%d", firstMR, secondMR)
	}
}

func TestBuildSubmitTPDUsUsesDistinctConcatReferenceAcrossMessages(t *testing.T) {
	first, _, err := BuildSubmitTPDUs("100", strings.Repeat("A", 400))
	if err != nil {
		t.Fatalf("first BuildSubmitTPDUs: %v", err)
	}
	second, _, err := BuildSubmitTPDUs("100", strings.Repeat("B", 400))
	if err != nil {
		t.Fatalf("second BuildSubmitTPDUs: %v", err)
	}
	if len(first) < 2 || len(second) < 2 {
		t.Fatalf("expected multipart messages: first=%d second=%d", len(first), len(second))
	}

	firstRef := independentConcatReference(t, first[0])
	for _, part := range first[1:] {
		if got := independentConcatReference(t, part); got != firstRef {
			t.Fatalf("first message concat reference changed across parts: first=%d got=%d", firstRef, got)
		}
	}
	secondRef := independentConcatReference(t, second[0])
	for _, part := range second[1:] {
		if got := independentConcatReference(t, part); got != secondRef {
			t.Fatalf("second message concat reference changed across parts: first=%d got=%d", secondRef, got)
		}
	}
	if secondRef == firstRef {
		t.Fatalf("concat reference was reused across messages: ref=%d", firstRef)
	}
}

func TestBuildSubmitTPDUsUsesUnknownTONForNationalFormat(t *testing.T) {
	tpdus, _, err := BuildSubmitTPDUs("1234567", "synthetic")
	if err != nil {
		t.Fatalf("BuildSubmitTPDUs: %v", err)
	}
	if len(tpdus) != 1 || len(tpdus[0]) < 4 {
		t.Fatalf("unexpected TPDU shape: parts=%d", len(tpdus))
	}
	if got := tpdus[0][3]; got != 0x81 {
		t.Fatalf("destination TON/NPI=0x%02x, want unknown/ISDN 0x81", got)
	}

	international, _, err := BuildSubmitTPDUs("+1234567", "synthetic")
	if err != nil {
		t.Fatalf("BuildSubmitTPDUs(international): %v", err)
	}
	if len(international) != 1 || len(international[0]) < 4 || international[0][3] != 0x91 {
		t.Fatal("explicit international destination did not retain international/ISDN TON")
	}
}

func independentConcatReference(t *testing.T, pdu []byte) int {
	t.Helper()
	if len(pdu) < 8 || pdu[0]&0x40 == 0 {
		t.Fatal("TPDU is not a concatenated SMS-SUBMIT")
	}
	offset := 2
	destinationDigits := int(pdu[offset])
	offset++
	offset += 1 + (destinationDigits+1)/2
	offset += 2
	switch (pdu[0] >> 3) & 0x03 {
	case 1, 3:
		offset += 7
	case 2:
		offset++
	}
	if offset >= len(pdu) {
		t.Fatal("TPDU ended before user-data length")
	}
	offset++
	if offset >= len(pdu) {
		t.Fatal("TPDU ended before UDH")
	}
	udhLen := int(pdu[offset])
	udhEnd := offset + 1 + udhLen
	if udhEnd > len(pdu) {
		t.Fatal("UDH length exceeds TPDU")
	}
	for cursor := offset + 1; cursor+2 <= udhEnd; {
		identifier := pdu[cursor]
		dataLen := int(pdu[cursor+1])
		cursor += 2
		if cursor+dataLen > udhEnd {
			t.Fatal("UDH information element exceeds declared length")
		}
		switch {
		case identifier == 0x00 && dataLen == 3:
			return int(pdu[cursor])
		case identifier == 0x08 && dataLen == 4:
			return int(pdu[cursor])<<8 | int(pdu[cursor+1])
		}
		cursor += dataLen
	}
	t.Fatal("concatenation information element missing")
	return 0
}
