package smssim

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/1239t/vohive/pkg/smscodec"
)

func TestDeliverIsReadByTheProductDecoder(t *testing.T) {
	at := time.Date(2026, 3, 9, 8, 30, 15, 0, time.FixedZone("", 8*3600))
	cases := []struct {
		name      string
		msg       Message
		wantParts int
	}{
		{"international number", Message{From: "+12025550123", Text: "hello", Time: at}, 1},
		{"short code", Message{From: "10086", Text: "balance 12.50", Time: at}, 1},
		{"alphanumeric sender", Message{From: "MyBank", Text: "code 482913", Time: at}, 1},
		{"text outside the default alphabet", Message{From: "+12025550123", Text: "你好，世界", Time: at}, 1},
		{"forced UCS-2", Message{From: "+12025550123", Text: "plain text", Time: at, UCS2: true}, 1},
		{"three parts in the default alphabet", Message{From: "+12025550123", Text: strings.Repeat("abcdefghij", 40), Time: at, Reference: 0x5A}, 3},
		{"three parts in UCS-2", Message{From: "10086", Text: strings.Repeat("长短信", 60), Time: at, Reference: 7}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parts, err := Deliver(tc.msg)
			if err != nil {
				t.Fatalf("Deliver() error = %v", err)
			}
			if len(parts) != tc.wantParts {
				t.Fatalf("parts = %d, want %d", len(parts), tc.wantParts)
			}
			var text strings.Builder
			for i, part := range parts {
				if part[0]&0x03 != 0 {
					t.Fatalf("part %d: message type bits = %d, want SMS-DELIVER", i+1, part[0]&0x03)
				}
				sender, content, timestamp, concat, err := smscodec.DecodeDeliverTPDU(part)
				if err != nil {
					t.Fatalf("part %d: DecodeDeliverTPDU() error = %v", i+1, err)
				}
				if sender != tc.msg.From {
					t.Fatalf("part %d: sender = %q, want %q", i+1, sender, tc.msg.From)
				}
				if !timestamp.Equal(at) {
					t.Fatalf("part %d: time stamp = %v, want %v", i+1, timestamp, at)
				}
				if concat.IsConcat != (tc.wantParts > 1) {
					t.Fatalf("part %d: concatenated = %v", i+1, concat.IsConcat)
				}
				if concat.IsConcat && (concat.Total != tc.wantParts || concat.Seq != i+1 || concat.Ref != tc.msg.Reference) {
					t.Fatalf("part %d: concatenation = %+v, want total %d, sequence %d, reference %d",
						i+1, concat, tc.wantParts, i+1, tc.msg.Reference)
				}
				text.WriteString(content)
			}
			if text.String() != tc.msg.Text {
				t.Fatalf("text = %q, want %q", text.String(), tc.msg.Text)
			}
		})
	}
}

func TestDeliverNeedsAnOriginatorAndATimeStamp(t *testing.T) {
	if _, err := Deliver(Message{Text: "x", Time: time.Now()}); err == nil {
		t.Fatal("Deliver() without an originator succeeded")
	}
	if _, err := Deliver(Message{From: "10086", Text: "x"}); err == nil {
		t.Fatal("Deliver() without a time stamp succeeded")
	}
}

func TestPDUPutsTheServiceCentreInFront(t *testing.T) {
	parts, err := Deliver(Message{From: "10086", Text: "hello", Time: time.Date(2026, 3, 9, 8, 30, 15, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}

	withCentre, err := PDU("+7654321", parts[0])
	if err != nil {
		t.Fatalf("PDU() error = %v", err)
	}
	if withCentre[0] == 0 {
		t.Fatal("service centre address is empty")
	}
	tpdu, err := smscodec.TPDUFromPDU(withCentre)
	if err != nil {
		t.Fatalf("TPDUFromPDU() error = %v", err)
	}
	if !bytes.Equal(tpdu, parts[0]) {
		t.Fatalf("TPDU behind the service centre = %X, want %X", tpdu, parts[0])
	}

	withoutCentre, err := PDU("", parts[0])
	if err != nil {
		t.Fatalf("PDU() error = %v", err)
	}
	if withoutCentre[0] != 0 || !bytes.Equal(withoutCentre[1:], parts[0]) {
		t.Fatalf("PDU without a service centre = %X", withoutCentre)
	}

	hexForm, err := PDUHex("+7654321", parts[0])
	if err != nil {
		t.Fatalf("PDUHex() error = %v", err)
	}
	if hexForm != strings.ToUpper(hexForm) || len(hexForm) != 2*len(withCentre) {
		t.Fatalf("PDUHex() = %q", hexForm)
	}
}

func TestPadSlotKeepsTheMessageReadable(t *testing.T) {
	parts, err := Deliver(Message{From: "10086", Text: "hello", Time: time.Date(2026, 3, 9, 8, 30, 15, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	padded := PadSlot(parts[0], 176)
	if len(padded) != 176 || !bytes.Equal(padded[:len(parts[0])], parts[0]) {
		t.Fatalf("padded length = %d", len(padded))
	}
	if len(PadSlot(parts[0], 1)) != len(parts[0]) {
		t.Fatal("PadSlot() shortened the message")
	}
	sender, content, _, _, err := smscodec.DecodeDeliverTPDU(padded)
	if err != nil || sender != "10086" || content != "hello" {
		t.Fatalf("padded message decoded as sender %q, text %q, error %v", sender, content, err)
	}
}
