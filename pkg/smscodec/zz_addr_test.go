package smscodec

import (
	"encoding/hex"
	"testing"
)

// The SMSC accepted every submit (rp_cause=0) but the recipient never got the
// message. An accepted-but-undeliverable submit points at the destination address
// inside the TPDU: the SMSC validates the ENCODING, not whether the number is the
// one the user typed. So check what actually goes on the wire for US numbers.
//
// TP-DA layout (TS 23.040 9.1.2.5): length in DIGITS, then type-of-address, then
// BCD-swapped semi-octets.
func TestSubmitDestinationAddressEncoding(t *testing.T) {
	cases := []string{
		"+12025550123",  // E.164 with plus
		"12025550123",   // no plus, 11 digits with country code
		"2025550123",    // 10-digit US national format
		"+1 202 555 0123",
		"(202) 555-0123",
	}

	for _, in := range cases {
		tpdus, _, err := BuildSubmitTPDUsWithOptions(in, "probe", SubmitOptions{RequestStatusReport: true})
		if err != nil {
			t.Logf("%-18s ENCODE ERROR: %v", in, err)
			continue
		}
		tpdu := tpdus[0]
		// [0] first octet, [1] TP-MR, [2] TP-DA digit count, [3] TOA, [4..] BCD
		if len(tpdu) < 5 {
			t.Errorf("%-18s tpdu too short", in)
			continue
		}
		digits := int(tpdu[2])
		toa := tpdu[3]
		octets := (digits + 1) / 2
		if 4+octets > len(tpdu) {
			t.Errorf("%-18s TP-DA truncated: digits=%d", in, digits)
			continue
		}
		bcd := tpdu[4 : 4+octets]
		t.Logf("%-18s digits=%-3d toa=0x%02x bcd=%s  decoded=%s",
			in, digits, toa, hex.EncodeToString(bcd), decodeBCDSemiOctets(bcd, digits))
	}
}

// decodeBCDSemiOctets reverses the swapped-nibble encoding so the test can show what
// a network would read back.
func decodeBCDSemiOctets(b []byte, digits int) string {
	out := make([]byte, 0, digits)
	for _, octet := range b {
		out = append(out, "0123456789*#abc?"[octet&0x0f])
		if len(out) == digits {
			break
		}
		out = append(out, "0123456789*#abc?"[octet>>4])
		if len(out) == digits {
			break
		}
	}
	return string(out)
}

// The type-of-address nibble decides whether the network treats the digits as
// international or national. Getting it wrong is a classic accepted-but-undelivered
// cause: 0x91 = international/E.164, 0x81 = unknown/national.
func TestDestinationTypeOfAddressIsInternational(t *testing.T) {
	tpdus, _, err := BuildSubmitTPDUsWithOptions("+12025550123", "probe", SubmitOptions{})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	toa := tpdus[0][3]
	t.Logf("TOA for +E.164 = 0x%02x", toa)
	if toa != 0x91 {
		t.Errorf("expected 0x91 (international, E.164) for a +-prefixed number, got 0x%02x", toa)
	}
}
