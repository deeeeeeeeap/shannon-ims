// Package smssim plays the network side of the short message service for tests
// that run without a modem or a mobile network. It encodes the SMS-DELIVER
// transfer PDUs a service centre delivers to a terminal, and the PDU-mode form
// in which a modem hands such a message over.
package smssim

import (
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/warthog618/sms"
	"github.com/warthog618/sms/encoding/pdumode"
	"github.com/warthog618/sms/encoding/tpdu"
	"github.com/warthog618/sms/encoding/ucs2"
)

// Message is one short message as a service centre delivers it.
type Message struct {
	// From is the originating address: digits with a leading + for an
	// international number, digits alone for a national number or short code,
	// and any other text for an alphanumeric sender.
	From string

	// Text is the message text in UTF-8.
	Text string

	// Time is the service centre time stamp. Its resolution is one second.
	Time time.Time

	// Reference is the concatenation reference that is used when the text
	// needs more than one part. Only the low eight bits are transmitted.
	Reference int

	// UCS2 forces the UCS-2 alphabet. Without it the default alphabet is used,
	// and UCS-2 only for text that the default alphabet cannot express.
	UCS2 bool
}

// fixedCounter makes the encoder use a chosen concatenation reference.
type fixedCounter int

func (c fixedCounter) Count() int { return int(c) }

// Deliver encodes the message as SMS-DELIVER TPDUs, one for each part, in
// sequence order.
func Deliver(msg Message) ([][]byte, error) {
	if msg.From == "" {
		return nil, errors.New("smssim: originating address missing")
	}
	if msg.Time.IsZero() {
		return nil, errors.New("smssim: service centre time stamp missing")
	}

	options := []sms.EncoderOption{
		sms.AsDeliver,
		sms.WithTemplateOption(tpdu.WithOA(originator(msg.From))),
	}
	text := []byte(msg.Text)
	if msg.UCS2 {
		text = ucs2.Encode([]rune(msg.Text))
		options = append(options, sms.AsUCS2)
	}
	encoder := sms.NewEncoder(options...)
	encoder.ConcatRef = fixedCounter(msg.Reference)

	parts, err := encoder.Encode(text)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, errors.New("smssim: nothing encoded")
	}
	encoded := make([][]byte, 0, len(parts))
	for i := range parts {
		parts[i].SCTS = tpdu.Timestamp{Time: msg.Time}
		part, err := parts[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, part)
	}
	return encoded, nil
}

func originator(from string) tpdu.Address {
	digits := strings.TrimPrefix(from, "+")
	numeric := digits != ""
	for _, r := range digits {
		if r < '0' || r > '9' {
			numeric = false
			break
		}
	}
	if !numeric {
		address := tpdu.NewAddress()
		address.Addr = from
		address.SetTypeOfNumber(tpdu.TonAlphanumeric)
		return address
	}

	address := tpdu.NewAddress(tpdu.FromNumber(from))
	if !strings.HasPrefix(from, "+") {
		address.SetTypeOfNumber(tpdu.TonUnknown)
		address.SetNumberingPlan(tpdu.NpISDN)
	}
	return address
}

// PDU puts the service centre address in front of a TPDU. This is the form in
// which the PDU mode of the AT interface and MBIM hand over a stored message.
// An empty service centre gives the one-octet empty address.
func PDU(serviceCentre string, tpduBytes []byte) ([]byte, error) {
	pdu := pdumode.PDU{TPDU: tpduBytes}
	if serviceCentre != "" {
		pdu.SMSC = pdumode.SMSCAddress{Address: tpdu.NewAddress(tpdu.FromNumber(serviceCentre))}
	}
	return pdu.MarshalBinary()
}

// PDUHex is PDU as the upper-case hexadecimal string a modem prints.
func PDUHex(serviceCentre string, tpduBytes []byte) (string, error) {
	pdu, err := PDU(serviceCentre, tpduBytes)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(pdu)), nil
}

// PadSlot appends zero octets up to size. Modems that keep messages in slots
// of a fixed size return them like this.
func PadSlot(pdu []byte, size int) []byte {
	padded := append([]byte(nil), pdu...)
	for len(padded) < size {
		padded = append(padded, 0)
	}
	return padded
}
