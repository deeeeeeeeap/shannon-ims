package backend

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/1239t/vohive/pkg/smscodec"
)

// Every cellular backend sends a prepared message the same way; the tests
// below run against each of them.
var (
	_ PreparedSMSSender = (*ATBackend)(nil)
	_ PreparedSMSSender = (*QMIBackend)(nil)
	_ PreparedSMSSender = (*MBIMBackend)(nil)
)

// recordingQMISendSource keeps every PDU handed to the modem and can refuse
// one of them.
type recordingQMISendSource struct {
	qmiBackendSendSourceStub
	sent    [][]byte
	formats []uint8
	failAt  int
}

func (s *recordingQMISendSource) WMSSendRawMessage(_ context.Context, format uint8, pdu []byte) error {
	if s.failAt != 0 && len(s.sent)+1 == s.failAt {
		return errors.New("synthetic modem refusal")
	}
	s.sent = append(s.sent, append([]byte(nil), pdu...))
	s.formats = append(s.formats, format)
	return nil
}

// preparedSMSChannel is one backend under test together with the record of
// what reached its modem.
type preparedSMSChannel struct {
	name   string
	sender interface {
		PreparedSMSSender
		SendSMSWithOptions(ctx context.Context, to, body string, opts smscodec.SubmitOptions) error
	}
	sent func() [][]byte
}

func newPreparedSMSChannels(t *testing.T, failAt int) []preparedSMSChannel {
	t.Helper()

	qmiSource := &recordingQMISendSource{failAt: failAt}
	qmiBackend, err := NewQMIBackend("/dev/null", qmiSource)
	if err != nil {
		t.Fatalf("NewQMIBackend: %v", err)
	}

	var mbimSent [][]byte
	mbimSource := &fakeMBIMSource{}
	mbimSource.sendFn = func(pdu []byte) (uint32, error) {
		if failAt != 0 && len(mbimSent)+1 == failAt {
			return 0, errors.New("synthetic modem refusal")
		}
		mbimSent = append(mbimSent, append([]byte(nil), pdu...))
		return uint32(len(mbimSent)), nil
	}

	return []preparedSMSChannel{
		{name: "qmi", sender: qmiBackend, sent: func() [][]byte { return qmiSource.sent }},
		{name: "mbim", sender: NewMBIMBackend("", mbimSource), sent: func() [][]byte { return mbimSent }},
	}
}

func TestBackendsSendEveryPreparedPartUnchanged(t *testing.T) {
	submission, err := smscodec.PrepareSubmission("+1234567", strings.Repeat("长", 150), smscodec.SubmitOptions{})
	if err != nil {
		t.Fatalf("PrepareSubmission: %v", err)
	}
	if submission.PartCount() != 3 {
		t.Fatalf("PartCount() = %d, want 3", submission.PartCount())
	}

	for _, channel := range newPreparedSMSChannels(t, 0) {
		t.Run(channel.name, func(t *testing.T) {
			if err := channel.sender.SendPreparedSMS(context.Background(), submission); err != nil {
				t.Fatalf("SendPreparedSMS: %v", err)
			}
			sent := channel.sent()
			if len(sent) != submission.PartCount() {
				t.Fatalf("modem received %d PDUs, want %d", len(sent), submission.PartCount())
			}
			for i := range sent {
				if !bytes.Equal(sent[i], submission.PDU(i)) {
					t.Fatalf("part %d reached the modem as %x, want %x", i, sent[i], submission.PDU(i))
				}
			}
		})
	}
}

// The same text to the same number must leave every channel as the same
// octets, apart from the reference numbers that count messages.
func TestBackendsEncodeTheSameMessageAlike(t *testing.T) {
	channels := newPreparedSMSChannels(t, 0)
	var reference [][]byte
	for _, channel := range channels {
		err := channel.sender.SendSMSWithOptions(context.Background(), " +1 (202) 555-0123 ", "synthetic", smscodec.SubmitOptions{})
		if err != nil {
			t.Fatalf("%s: SendSMSWithOptions: %v", channel.name, err)
		}
		sent := channel.sent()
		if len(sent) != 1 || len(sent[0]) < 3 {
			t.Fatalf("%s: unexpected PDUs %x", channel.name, sent)
		}
		pdu := append([]byte(nil), sent[0]...)
		pdu[2] = 0 // TP-MR
		if reference == nil {
			reference = [][]byte{pdu}
			continue
		}
		if !bytes.Equal(pdu, reference[0]) {
			t.Fatalf("%s sent %x, %s sent %x", channel.name, pdu, channels[0].name, reference[0])
		}
	}

	// Empty service centre address, then an international destination of
	// eleven digits: the separators of the written number are gone.
	wantPrefix := []byte{0x00, 0x01, 0x00, 0x0b, 0x91, 0x21, 0x20, 0x55, 0x05, 0x21, 0xf3}
	if !bytes.HasPrefix(reference[0], wantPrefix) {
		t.Fatalf("PDU starts with %x, want %x", reference[0][:len(wantPrefix)], wantPrefix)
	}
}

func TestBackendsStopAtTheFirstRefusedPart(t *testing.T) {
	submission, err := smscodec.PrepareSubmission("+1234567", strings.Repeat("A", 400), smscodec.SubmitOptions{})
	if err != nil {
		t.Fatalf("PrepareSubmission: %v", err)
	}

	for _, channel := range newPreparedSMSChannels(t, 2) {
		t.Run(channel.name, func(t *testing.T) {
			err := channel.sender.SendPreparedSMS(context.Background(), submission)
			if err == nil {
				t.Fatal("SendPreparedSMS() error = nil although the modem refused a part")
			}
			if !strings.Contains(err.Error(), "2/3") {
				t.Fatalf("error does not name the refused part: %v", err)
			}
			if strings.Contains(err.Error(), "1234567") {
				t.Fatalf("error text carries the destination: %v", err)
			}
			if got := len(channel.sent()); got != 1 {
				t.Fatalf("%d parts reached the modem, want only the first", got)
			}
		})
	}
}

func TestBackendsRejectUnusableInputBeforeTheModem(t *testing.T) {
	for _, channel := range newPreparedSMSChannels(t, 0) {
		t.Run(channel.name, func(t *testing.T) {
			ctx := context.Background()
			if err := channel.sender.SendSMSWithOptions(ctx, "someone", "synthetic", smscodec.SubmitOptions{}); !errors.Is(err, smscodec.ErrDestinationInvalid) {
				t.Fatalf("bad destination: error = %v", err)
			}
			if err := channel.sender.SendSMSWithOptions(ctx, "+1234567", "", smscodec.SubmitOptions{}); !errors.Is(err, smscodec.ErrMessageEmpty) {
				t.Fatalf("empty text: error = %v", err)
			}
			if err := channel.sender.SendPreparedSMS(ctx, nil); err == nil {
				t.Fatal("SendPreparedSMS(nil) error = nil")
			}
			if got := len(channel.sent()); got != 0 {
				t.Fatalf("%d PDUs reached the modem", got)
			}
		})
	}
}
