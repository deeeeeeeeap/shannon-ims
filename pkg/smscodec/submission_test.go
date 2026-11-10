package smscodec

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestNormalizeDestination(t *testing.T) {
	accepted := []struct {
		name string
		in   string
		want string
	}{
		{"international", "+12025550123", "+12025550123"},
		{"national", "2025550123", "2025550123"},
		{"short code", "10086", "10086"},
		{"surrounding space", "  +12025550123\t\n", "+12025550123"},
		{"spaces and brackets", "+1 (202) 555-0123", "+12025550123"},
		{"dots", "202.555.0123", "2025550123"},
		{"no-break space", "+1\u00a0202\u00a0555\u00a00123", "+12025550123"},
		{"typographic dashes", "202\u2011555\u20130123", "2025550123"},
		{"copied with direction marks", "\u202a+1 202 555 0123\u202c", "+12025550123"},
		{"zero width space", "+1202\u200b5550123", "+12025550123"},
		{"full width", "＋１２０２５５５０１２３", "+12025550123"},
		{"full width brackets and space", "（２０２）　５５５－０１２３", "2025550123"},
		{"keypad signs", "*100#", "*100#"},
		{"full width keypad signs", "＊100＃", "*100#"},
		{"twenty digits", "+12345678901234567890", "+12345678901234567890"},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeDestination(tc.in)
			if err != nil {
				t.Fatalf("NormalizeDestination(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeDestination(%q) = %q, want %q", tc.in, got, tc.want)
			}
			again, err := NormalizeDestination(got)
			if err != nil || again != got {
				t.Fatalf("normalised form is not stable: %q -> %q, %v", got, again, err)
			}
		})
	}

	rejected := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrDestinationEmpty},
		{"only space", " \t ", ErrDestinationEmpty},
		{"only separators", "(-)", ErrDestinationEmpty},
		{"only plus", "+", ErrDestinationInvalid},
		{"plus inside", "12+34", ErrDestinationInvalid},
		{"plus after a separator and a digit", "(1)+234", ErrDestinationInvalid},
		{"two plus signs", "++1234", ErrDestinationInvalid},
		{"letters", "1800FLOWERS", ErrDestinationInvalid},
		{"extension", "2025550123x12", ErrDestinationInvalid},
		{"two numbers", "2025550123,2025550124", ErrDestinationInvalid},
		{"sip uri", "sip:2025550123@example.invalid", ErrDestinationInvalid},
		{"twenty one digits", "123456789012345678901", ErrDestinationTooLong},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeDestination(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("NormalizeDestination(%q) = %q, %v; want %v", tc.in, got, err, tc.want)
			}
			if got != "" {
				t.Fatalf("a rejected destination returned %q", got)
			}
		})
	}
}

// The plus sign of a destination written with separators in front of it must
// still be recognised as leading.
func TestNormalizeDestinationAcceptsPlusBehindSeparators(t *testing.T) {
	got, err := NormalizeDestination(" (+1) 202 555 0123")
	if err != nil || got != "+12025550123" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// maskVolatile blanks the two fields that differ between two encodings of the
// same message because they come from process-wide counters: TP-MR and the
// reference number of the concatenation header.
func maskVolatile(t *testing.T, tpdu []byte) []byte {
	t.Helper()
	out := append([]byte(nil), tpdu...)
	if len(out) < 2 {
		t.Fatalf("TPDU too short: %d", len(out))
	}
	out[1] = 0
	if out[0]&0x40 == 0 {
		return out
	}
	// first octet, TP-MR, destination length, type of address, digits,
	// TP-PID, TP-DCS, TP-UDL, UDHL, IEI, IEDL, reference.
	index := 2 + 1 + 1 + (int(out[2])+1)/2 + 2 + 1 + 1 + 2
	if index >= len(out) || out[index-2] != 0x00 || out[index-1] != 0x03 {
		t.Fatalf("unexpected concatenation header layout in %x", out)
	}
	out[index] = 0
	return out
}

func TestPrepareSubmissionMatchesLegacyEncoderOnTheWire(t *testing.T) {
	cases := []struct {
		name string
		to   string
		text string
		opts SubmitOptions
	}{
		{"international gsm7", "+1234567", "HELLO", SubmitOptions{}},
		{"national gsm7", "1234567", "HELLO", SubmitOptions{}},
		{"short code", "55501", "synthetic", SubmitOptions{}},
		{"status report", "+1234567", "HELLO", SubmitOptions{RequestStatusReport: true}},
		{"automatic ucs2", "+1234567", "你好，世界", SubmitOptions{}},
		{"forced ucs2", "+1234567", "HELLO", SubmitOptions{Encoding: SMSEncodingUCS2}},
		{"long gsm7", "+1234567", strings.Repeat("A", 400), SubmitOptions{RequestStatusReport: true}},
		{"long ucs2", "1234567", strings.Repeat("长", 200), SubmitOptions{}},
		{"odd number of digits", "+123456789", "HELLO", SubmitOptions{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacy, lengths, err := BuildSubmitTPDUsWithOptions(tc.to, tc.text, tc.opts)
			if err != nil {
				t.Fatalf("BuildSubmitTPDUsWithOptions: %v", err)
			}
			prepared, err := PrepareSubmission(tc.to, tc.text, tc.opts)
			if err != nil {
				t.Fatalf("PrepareSubmission: %v", err)
			}
			if prepared.PartCount() != len(legacy) {
				t.Fatalf("parts = %d, legacy encoder produced %d", prepared.PartCount(), len(legacy))
			}
			for i := range legacy {
				got := prepared.TPDU(i)
				if len(got) != lengths[i] {
					t.Fatalf("part %d length = %d, legacy %d", i, len(got), lengths[i])
				}
				if !bytes.Equal(maskVolatile(t, got), maskVolatile(t, legacy[i])) {
					t.Fatalf("part %d differs on the wire:\n got    %x\n legacy %x", i, got, legacy[i])
				}
			}
		})
	}
}

func TestPrepareSubmissionNormalisesTheDestination(t *testing.T) {
	plain, err := PrepareSubmission("+12025550123", "HELLO", SubmitOptions{})
	if err != nil {
		t.Fatalf("PrepareSubmission(plain): %v", err)
	}
	for _, written := range []string{
		" +1 (202) 555-0123 ",
		"+1.202.555.0123",
		"＋１２０２５５５０１２３",
		"\u202a+1 202 555 0123\u202c",
	} {
		prepared, err := PrepareSubmission(written, "HELLO", SubmitOptions{})
		if err != nil {
			t.Fatalf("PrepareSubmission(%q): %v", written, err)
		}
		if prepared.To() != "+12025550123" {
			t.Fatalf("To() = %q for %q", prepared.To(), written)
		}
		if !bytes.Equal(maskVolatile(t, prepared.TPDU(0)), maskVolatile(t, plain.TPDU(0))) {
			t.Fatalf("%q is encoded differently from the plain number:\n got  %x\n want %x",
				written, prepared.TPDU(0), plain.TPDU(0))
		}
	}

	// What a person wrote without "+" stays a number without "+": the type
	// of number is not guessed.
	national, err := PrepareSubmission("(202) 555-0123", "HELLO", SubmitOptions{})
	if err != nil {
		t.Fatalf("PrepareSubmission(national): %v", err)
	}
	if got := national.TPDU(0)[3]; got != 0x81 {
		t.Fatalf("national destination type of address = 0x%02x, want 0x81", got)
	}
	if got := plain.TPDU(0)[3]; got != 0x91 {
		t.Fatalf("international destination type of address = 0x%02x, want 0x91", got)
	}
}

func TestPrepareSubmissionReportsAlphabetAndParts(t *testing.T) {
	cases := []struct {
		name      string
		text      string
		opts      SubmitOptions
		alphabet  Alphabet
		partCount int
	}{
		{"gsm7 single", strings.Repeat("A", 160), SubmitOptions{}, AlphabetGSM7, 1},
		{"gsm7 two parts", strings.Repeat("A", 161), SubmitOptions{}, AlphabetGSM7, 2},
		{"gsm7 three parts", strings.Repeat("A", 400), SubmitOptions{}, AlphabetGSM7, 3},
		{"ucs2 single", strings.Repeat("长", 70), SubmitOptions{}, AlphabetUCS2, 1},
		{"ucs2 two parts", strings.Repeat("长", 71), SubmitOptions{}, AlphabetUCS2, 2},
		{"one character outside gsm7", "HELLO 你", SubmitOptions{}, AlphabetUCS2, 1},
		{"forced ucs2", "HELLO", SubmitOptions{Encoding: SMSEncodingUCS2}, AlphabetUCS2, 1},
		{"forced ucs2 long", strings.Repeat("A", 71), SubmitOptions{Encoding: SMSEncodingUCS2}, AlphabetUCS2, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareSubmission("+1234567", tc.text, tc.opts)
			if err != nil {
				t.Fatalf("PrepareSubmission: %v", err)
			}
			if prepared.Alphabet() != tc.alphabet {
				t.Fatalf("Alphabet() = %q, want %q", prepared.Alphabet(), tc.alphabet)
			}
			if prepared.PartCount() != tc.partCount {
				t.Fatalf("PartCount() = %d, want %d", prepared.PartCount(), tc.partCount)
			}
			for i := 0; i < prepared.PartCount(); i++ {
				concatenated := prepared.TPDU(i)[0]&0x40 != 0
				if concatenated != (tc.partCount > 1) {
					t.Fatalf("part %d: user data header present = %v with %d parts", i, concatenated, tc.partCount)
				}
			}
		})
	}
}

func TestPrepareSubmissionRejectsUnusableInput(t *testing.T) {
	cases := []struct {
		name string
		to   string
		text string
		opts SubmitOptions
		want error
	}{
		{"no destination", "  ", "HELLO", SubmitOptions{}, ErrDestinationEmpty},
		{"bad destination", "not a number", "HELLO", SubmitOptions{}, ErrDestinationInvalid},
		{"long destination", strings.Repeat("1", 21), "HELLO", SubmitOptions{}, ErrDestinationTooLong},
		{"no text", "+1234567", "", SubmitOptions{}, ErrMessageEmpty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareSubmission(tc.to, tc.text, tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if prepared != nil {
				t.Fatal("a rejected message was prepared")
			}
		})
	}

	if _, err := PrepareSubmission("+1234567", "HELLO", SubmitOptions{Encoding: "latin1"}); err == nil {
		t.Fatal("an unknown encoding was accepted")
	}
	// A text of white space is a message; only the absence of text is not.
	if _, err := PrepareSubmission("+1234567", " ", SubmitOptions{}); err != nil {
		t.Fatalf("a single space was rejected: %v", err)
	}
}

// The counters of the concatenation header are one octet wide. A message of
// more parts used to be encoded with wrapped counters, which no receiver can
// put together again.
func TestPrepareSubmissionRejectsMoreThan255Parts(t *testing.T) {
	const septetsPerPart = 153

	largest, err := PrepareSubmission("+1234567", strings.Repeat("A", 255*septetsPerPart), SubmitOptions{})
	if err != nil {
		t.Fatalf("a message of exactly 255 parts was rejected: %v", err)
	}
	if largest.PartCount() != 255 {
		t.Fatalf("PartCount() = %d, want 255", largest.PartCount())
	}

	tooLong := strings.Repeat("A", 255*septetsPerPart+1)
	if _, err := PrepareSubmission("+1234567", tooLong, SubmitOptions{}); !errors.Is(err, ErrMessageTooLong) {
		t.Fatalf("PrepareSubmission error = %v, want %v", err, ErrMessageTooLong)
	}
	if _, _, err := BuildSubmitTPDUs("+1234567", tooLong); !errors.Is(err, ErrMessageTooLong) {
		t.Fatalf("BuildSubmitTPDUs error = %v, want %v", err, ErrMessageTooLong)
	}
}

func TestSubmissionFramesEachPartForModemChannels(t *testing.T) {
	prepared, err := PrepareSubmission("+1234567", strings.Repeat("A", 400), SubmitOptions{})
	if err != nil {
		t.Fatalf("PrepareSubmission: %v", err)
	}
	for i := 0; i < prepared.PartCount(); i++ {
		tpdu := prepared.TPDU(i)

		pdu := prepared.PDU(i)
		if len(pdu) != len(tpdu)+1 || pdu[0] != 0x00 || !bytes.Equal(pdu[1:], tpdu) {
			t.Fatalf("part %d: PDU is not the TPDU behind an empty service centre address", i)
		}
		back, err := TPDUFromPDU(pdu)
		if err != nil || !bytes.Equal(back, tpdu) {
			t.Fatalf("part %d: TPDUFromPDU(PDU) = %x, %v", i, back, err)
		}

		tpduLen, pduHex := prepared.ATPDU(i)
		if tpduLen != len(tpdu) {
			t.Fatalf("part %d: AT length = %d, TPDU has %d octets", i, tpduLen, len(tpdu))
		}
		if pduHex != strings.ToUpper(pduHex) {
			t.Fatalf("part %d: AT PDU is not upper-case hexadecimal", i)
		}
		decoded, err := hex.DecodeString(pduHex)
		if err != nil || !bytes.Equal(decoded, pdu) {
			t.Fatalf("part %d: AT PDU does not decode to the PDU: %v", i, err)
		}
	}
}

func TestSubmissionHandsOutCopies(t *testing.T) {
	prepared, err := PrepareSubmission("+1234567", "HELLO", SubmitOptions{})
	if err != nil {
		t.Fatalf("PrepareSubmission: %v", err)
	}
	original := prepared.TPDU(0)

	tpdu := prepared.TPDU(0)
	for i := range tpdu {
		tpdu[i] = 0xff
	}
	pdu := prepared.PDU(0)
	for i := range pdu {
		pdu[i] = 0xff
	}
	if _, err := prepared.RPData(0, 0x7f, "+7654321"); err != nil {
		t.Fatalf("RPData: %v", err)
	}

	if !bytes.Equal(prepared.TPDU(0), original) {
		t.Fatal("the prepared message changed after its parts were handed out")
	}
}

func TestSubmissionRPDataCarriesTheReferenceInBothLayers(t *testing.T) {
	prepared, err := PrepareSubmission("+1234567", strings.Repeat("A", 200), SubmitOptions{RequestStatusReport: true})
	if err != nil {
		t.Fatalf("PrepareSubmission: %v", err)
	}
	if prepared.PartCount() != 2 {
		t.Fatalf("PartCount() = %d, want 2", prepared.PartCount())
	}
	for i := 0; i < prepared.PartCount(); i++ {
		reference := byte(0xa0 + i)
		rpdu, err := prepared.RPData(i, reference, "+7654321")
		if err != nil {
			t.Fatalf("part %d: RPData: %v", i, err)
		}

		// The frame is exactly what the two existing steps produce together.
		expectedTPDU := prepared.TPDU(i)
		if err := SetSubmitMessageReference(expectedTPDU, reference); err != nil {
			t.Fatalf("SetSubmitMessageReference: %v", err)
		}
		expected, err := BuildRPDataStrict(reference, expectedTPDU, "+7654321")
		if err != nil {
			t.Fatalf("BuildRPDataStrict: %v", err)
		}
		if !bytes.Equal(rpdu, expected) {
			t.Fatalf("part %d: RP-DATA differs from the reference construction", i)
		}

		rpMR, _, serviceCentre, tpdu, err := ParseRPDataWithAddresses(rpdu)
		if err != nil {
			t.Fatalf("part %d: ParseRPDataWithAddresses: %v", i, err)
		}
		if rpMR != reference {
			t.Fatalf("part %d: RP-MR = 0x%02x, want 0x%02x", i, rpMR, reference)
		}
		if len(tpdu) < 2 || tpdu[1] != reference {
			t.Fatalf("part %d: TP-MR does not carry the reference", i)
		}
		if !strings.HasSuffix(serviceCentre, "7654321") {
			t.Fatalf("part %d: service centre = %q", i, serviceCentre)
		}
		if tpdu[0]&0x20 == 0 {
			t.Fatalf("part %d: status report request was lost", i)
		}
	}

	if _, err := prepared.RPData(0, 1, "not a service centre"); err == nil {
		t.Fatal("an unusable service centre address was accepted")
	}
}

func TestTPDUFromPDU(t *testing.T) {
	tpdu := []byte{0x04, 0x05, 0x85, 0x55, 0x05, 0xf1, 0x00, 0x00}

	got, err := TPDUFromPDU(append([]byte{0x00}, tpdu...))
	if err != nil || !bytes.Equal(got, tpdu) {
		t.Fatalf("without service centre: %x, %v", got, err)
	}

	withServiceCentre := append([]byte{0x05, 0x91, 0x21, 0x43, 0x65, 0xf7}, tpdu...)
	got, err = TPDUFromPDU(withServiceCentre)
	if err != nil || !bytes.Equal(got, tpdu) {
		t.Fatalf("with service centre: %x, %v", got, err)
	}

	for name, pdu := range map[string][]byte{
		"empty":                         nil,
		"only the length octet":         {0x00},
		"service centre fills the pdu":  {0x02, 0x91, 0x21},
		"service centre beyond the pdu": {0x07, 0x91, 0x21},
	} {
		if got, err := TPDUFromPDU(pdu); err == nil {
			t.Fatalf("%s: accepted, TPDU %x", name, got)
		}
	}
}
