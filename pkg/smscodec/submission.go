package smscodec

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Alphabet is the character encoding a prepared message uses on the air.
type Alphabet string

const (
	AlphabetGSM7 Alphabet = "gsm7"
	AlphabetUCS2 Alphabet = "ucs2"
)

const (
	// maxDestinationDigits is the capacity of TP-Destination-Address: ten
	// address value octets (3GPP TS 23.040, 9.1.2.5).
	maxDestinationDigits = 20
	// maxSubmissionParts is what the one-octet counters of the concatenation
	// header can express.
	maxSubmissionParts = 255
)

var (
	ErrDestinationEmpty   = errors.New("号码为空")
	ErrDestinationInvalid = errors.New("号码只能由数字、* 和 # 组成，国际号码以 + 开头")
	ErrDestinationTooLong = fmt.Errorf("号码超过 %d 位", maxDestinationDigits)
	ErrMessageEmpty       = errors.New("短信内容为空")
	ErrMessageTooLong     = fmt.Errorf("短信内容过长，超过 %d 段", maxSubmissionParts)
)

// NormalizeDestination turns a destination as people write it into the form
// that goes into TP-Destination-Address: an optional leading "+" followed by
// digits (and the "*" and "#" a keypad can dial).
//
// Separators that carry no meaning are dropped: white space, hyphens, dots,
// parentheses and the invisible formatting characters that come along when a
// number is copied from a contact card. Full-width digits and signs, as an
// East Asian input method produces them, are folded to ASCII. Anything else
// is an error rather than a guess: the number is where the message goes.
//
// The "+" is kept as written. A national number, a short code and an
// international number without "+" cannot be told apart here, and the
// service centre interprets a number without "+" in its own dialling plan.
func NormalizeDestination(raw string) (string, error) {
	var out strings.Builder
	digits := 0
	for _, r := range raw {
		switch {
		case r >= '０' && r <= '９':
			r = '0' + (r - '０')
		case r == '＋':
			r = '+'
		case r == '＊':
			r = '*'
		case r == '＃':
			r = '#'
		}
		switch {
		case (r >= '0' && r <= '9') || r == '*' || r == '#':
			out.WriteRune(r)
			digits++
		case r == '+':
			if out.Len() != 0 {
				return "", ErrDestinationInvalid
			}
			out.WriteRune(r)
		case isDestinationSeparator(r):
		default:
			return "", ErrDestinationInvalid
		}
	}
	switch {
	case digits == 0 && out.Len() == 0:
		return "", ErrDestinationEmpty
	case digits == 0:
		return "", ErrDestinationInvalid
	case digits > maxDestinationDigits:
		return "", ErrDestinationTooLong
	}
	return out.String(), nil
}

func isDestinationSeparator(r rune) bool {
	switch r {
	case '-', '.', '(', ')', '（', '）', '‐', '‑', '–', '—', '－':
		return true
	}
	return unicode.IsSpace(r) || unicode.Is(unicode.Cf, r)
}

// Submission is one outgoing text message prepared for sending: the
// destination is validated and normalised, the alphabet is chosen and the
// text is split into SMS-SUBMIT TPDUs.
//
// It does not depend on the channel that will carry the message. Each
// channel takes the framing it needs from the same prepared parts: PDU and
// ATPDU for a modem in PDU mode (AT, QMI, MBIM), RPData for SMS over IMS.
// A Submission is not modified after PrepareSubmission returns it.
type Submission struct {
	to       string
	alphabet Alphabet
	parts    [][]byte
}

// PrepareSubmission validates the destination and the text and encodes the
// message once. The errors of an unusable destination or text are the Err…
// values of this package, so that a caller can tell a bad request from a
// failure to send.
func PrepareSubmission(to, text string, opts SubmitOptions) (*Submission, error) {
	destination, err := NormalizeDestination(to)
	if err != nil {
		return nil, err
	}
	if text == "" {
		return nil, ErrMessageEmpty
	}
	parts, alphabet, err := encodeSubmit(destination, text, opts)
	if err != nil {
		return nil, err
	}
	return &Submission{to: destination, alphabet: alphabet, parts: parts}, nil
}

// To returns the normalised destination.
func (s *Submission) To() string { return s.to }

// Alphabet returns the encoding the parts use. With SMSEncodingAuto it is
// GSM 7-bit when the text fits that alphabet and UCS-2 otherwise.
func (s *Submission) Alphabet() Alphabet { return s.alphabet }

// PartCount returns the number of TPDUs the message was split into.
func (s *Submission) PartCount() int { return len(s.parts) }

// TPDU returns a copy of the SMS-SUBMIT TPDU of part i, counted from zero.
func (s *Submission) TPDU(i int) []byte {
	return append([]byte(nil), s.parts[i]...)
}

// PDU returns part i framed for a modem in PDU mode (3GPP TS 27.005): the
// TPDU behind a service centre address of length zero, which makes the modem
// use the service centre stored on the SIM.
func (s *Submission) PDU(i int) []byte {
	pdu := make([]byte, 0, 1+len(s.parts[i]))
	pdu = append(pdu, 0x00)
	return append(pdu, s.parts[i]...)
}

// ATPDU returns what AT+CMGS needs for part i: the length argument, which
// counts the TPDU without the service centre address, and the PDU in
// upper-case hexadecimal.
func (s *Submission) ATPDU(i int) (tpduLen int, pduHex string) {
	return len(s.parts[i]), strings.ToUpper(hex.EncodeToString(s.PDU(i)))
}

// RPData returns part i framed as RP-DATA for SMS over IMS, addressed to
// serviceCentre. The same reference is used as RP-Message-Reference and as
// TP-Message-Reference, which is what correlates the reports of the service
// centre with the part.
func (s *Submission) RPData(i int, reference byte, serviceCentre string) ([]byte, error) {
	tpdu := s.TPDU(i)
	if err := SetSubmitMessageReference(tpdu, reference); err != nil {
		return nil, err
	}
	return BuildRPDataStrict(reference, tpdu, serviceCentre)
}

// TPDUFromPDU returns the TPDU of a message in PDU mode, as AT and MBIM
// modems store and report it: it skips the service centre address in front.
func TPDUFromPDU(pdu []byte) ([]byte, error) {
	if len(pdu) == 0 {
		return nil, errors.New("PDU 为空")
	}
	offset := 1 + int(pdu[0])
	if offset >= len(pdu) {
		return nil, fmt.Errorf("PDU 的短信中心地址越界: 声明 %d 字节，共 %d 字节", int(pdu[0]), len(pdu))
	}
	return pdu[offset:], nil
}
