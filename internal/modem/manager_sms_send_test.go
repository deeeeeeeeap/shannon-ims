package modem

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/1239t/vohive/pkg/smscodec"
)

// nextHighPriorityCommand takes the next command the manager queued for the
// modem, standing in for the serial loop.
func nextHighPriorityCommand(t *testing.T, m *Manager) commandRequest {
	t.Helper()
	select {
	case req := <-m.cmdChanHigh:
		return req
	case <-time.After(3 * time.Second):
		t.Fatal("the manager did not queue the next command")
		return commandRequest{}
	}
}

func waitForSendResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("sending did not finish")
		return nil
	}
}

func assertNoQueuedCommand(t *testing.T, m *Manager) {
	t.Helper()
	select {
	case req := <-m.cmdChanHigh:
		t.Fatalf("unexpected high priority command %q", req.cmd)
	case req := <-m.cmdChan:
		t.Fatalf("unexpected command %q", req.cmd)
	default:
	}
}

func TestManagerSendPreparedSMSWritesEveryPartThroughCMGS(t *testing.T) {
	m := newRunningTestManager(t)
	submission, err := smscodec.PrepareSubmission("+1234567", strings.Repeat("A", 200), smscodec.SubmitOptions{})
	if err != nil {
		t.Fatalf("PrepareSubmission: %v", err)
	}
	if submission.PartCount() != 2 {
		t.Fatalf("PartCount() = %d, want 2", submission.PartCount())
	}

	done := make(chan error, 1)
	go func() { done <- m.SendPreparedSMS(submission) }()

	setup := nextHighPriorityCommand(t, m)
	if setup.cmd != "AT+CMGF=0" {
		t.Fatalf("first command = %q, want the PDU mode switch", setup.cmd)
	}
	setup.respChan <- "OK"

	for i := 0; i < submission.PartCount(); i++ {
		req := nextHighPriorityCommand(t, m)
		tpduLen, pduHex := submission.ATPDU(i)
		if want := fmt.Sprintf("AT+CMGS=%d", tpduLen); req.cmd != want {
			t.Fatalf("part %d: command = %q, want %q", i, req.cmd, want)
		}
		if req.followUp != pduHex+"\x1A" {
			t.Fatalf("part %d: the PDU written after the prompt is not the prepared part", i)
		}
		if !req.interactive || !req.waitPrompt || !req.highPriority {
			t.Fatalf("part %d: request is not an interactive high priority command: %+v", i, req)
		}
		if !bytes.Equal(req.cancelSequence, []byte{0x1B}) {
			t.Fatalf("part %d: cancel sequence = %x, want ESC", i, req.cancelSequence)
		}
		req.respChan <- fmt.Sprintf("+CMGS: %d\r\nOK", i+1)
	}

	if err := waitForSendResult(t, done); err != nil {
		t.Fatalf("SendPreparedSMS: %v", err)
	}
	assertNoQueuedCommand(t, m)
}

func TestManagerSendSMSStopsAtTheFirstFailedPart(t *testing.T) {
	m := newRunningTestManager(t)

	done := make(chan error, 1)
	go func() { done <- m.SendSMS("+1234567", strings.Repeat("A", 400)) }()

	nextHighPriorityCommand(t, m).respChan <- "OK"
	nextHighPriorityCommand(t, m).respChan <- "+CMGS: 1\r\nOK"
	nextHighPriorityCommand(t, m).errChan <- errors.New("+CMS ERROR: 500")

	err := waitForSendResult(t, done)
	if err == nil {
		t.Fatal("SendSMS() error = nil although the modem refused the second part")
	}
	if !strings.Contains(err.Error(), "分片 2") {
		t.Fatalf("error does not name the failed part: %v", err)
	}
	assertNoQueuedCommand(t, m)
}

func TestManagerSendSMSAcceptsNumberAsWritten(t *testing.T) {
	m := newRunningTestManager(t)

	done := make(chan error, 1)
	go func() {
		done <- m.SendSMSWithOptions(" +1 (202) 555-0123 ", "synthetic", smscodec.SubmitOptions{})
	}()

	nextHighPriorityCommand(t, m).respChan <- "OK"
	req := nextHighPriorityCommand(t, m)
	req.respChan <- "+CMGS: 1\r\nOK"
	if err := waitForSendResult(t, done); err != nil {
		t.Fatalf("SendSMSWithOptions: %v", err)
	}

	pdu, err := hex.DecodeString(strings.TrimSuffix(req.followUp, "\x1A"))
	if err != nil {
		t.Fatalf("the PDU written to the modem is not hexadecimal: %v", err)
	}
	// Service centre length, first octet, TP-MR, then the destination: eleven
	// digits, international numbering, swapped semi-octets.
	wantDestination := []byte{0x0b, 0x91, 0x21, 0x20, 0x55, 0x05, 0x21, 0xf3}
	if len(pdu) < 3+len(wantDestination) || pdu[0] != 0x00 {
		t.Fatalf("unexpected PDU %x", pdu)
	}
	if got := pdu[3 : 3+len(wantDestination)]; !bytes.Equal(got, wantDestination) {
		t.Fatalf("destination on the wire = %x, want %x", got, wantDestination)
	}
}

func TestManagerSendSMSRejectsUnusableInputBeforeTouchingTheModem(t *testing.T) {
	cases := []struct {
		name    string
		phone   string
		message string
		want    error
	}{
		{"no number", "   ", "synthetic", smscodec.ErrDestinationEmpty},
		{"not a number", "someone", "synthetic", smscodec.ErrDestinationInvalid},
		{"no text", "+1234567", "", smscodec.ErrMessageEmpty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newRunningTestManager(t)
			err := m.SendSMS(tc.phone, tc.message)
			if !errors.Is(err, tc.want) {
				t.Fatalf("SendSMS() error = %v, want %v", err, tc.want)
			}
			assertNoQueuedCommand(t, m)
		})
	}

	m := newRunningTestManager(t)
	if err := m.SendPreparedSMS(nil); err == nil {
		t.Fatal("SendPreparedSMS(nil) error = nil")
	}
	assertNoQueuedCommand(t, m)
}
