package cscall

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeATModem struct {
	ring      func()
	clip      func(string)
	hangup    func()
	qpcmv     chan int
	dialed    string
	answered  int
	hangups   int
	hangupErr error
	silentCmd []string
	clcc      string
}

func (m *fakeATModem) SetRingCallback(f func())       { m.ring = f }
func (m *fakeATModem) SetClipCallback(f func(string)) { m.clip = f }
func (m *fakeATModem) SetHangupCallback(f func())     { m.hangup = f }
func (m *fakeATModem) GetQPCMVChan() <-chan int       { return m.qpcmv }
func (m *fakeATModem) DialCall(number string) error   { m.dialed = number; return nil }
func (m *fakeATModem) AnswerCall() error              { m.answered++; return nil }
func (m *fakeATModem) HangupCall() error              { m.hangups++; return m.hangupErr }
func (m *fakeATModem) ExecuteATSilent(cmd string, timeout time.Duration) (string, error) {
	m.silentCmd = append(m.silentCmd, cmd)
	if cmd == "AT+CLCC" {
		return m.clcc, nil
	}
	return "OK", nil
}

func TestATControllerMapsCallbacksAndCommands(t *testing.T) {
	fake := &fakeATModem{qpcmv: make(chan int, 1)}
	ctrl := NewATController(fake)
	if err := ctrl.Start(context.Background()); err != nil {
		t.Fatalf("Start() error=%v", err)
	}
	defer ctrl.Stop()

	fake.ring()
	got := <-ctrl.Events()
	if got.Type != EventIncoming || got.Number != "Unknown" {
		t.Fatalf("ring event=%+v want incoming Unknown", got)
	}

	fake.clip("+123")
	got = <-ctrl.Events()
	if got.Type != EventIncoming || got.Number != "+123" {
		t.Fatalf("clip event=%+v want incoming +123", got)
	}

	if _, err := ctrl.Dial(context.Background(), "10086"); err != nil {
		t.Fatalf("Dial() error=%v", err)
	}
	if fake.dialed != "10086" {
		t.Fatalf("dialed=%q want 10086", fake.dialed)
	}

	if err := ctrl.Answer(context.Background(), "at"); err != nil {
		t.Fatalf("Answer() error=%v", err)
	}
	if fake.answered != 1 {
		t.Fatalf("answered=%d want 1", fake.answered)
	}

	if err := ctrl.Hangup(context.Background(), "at", HangupOptions{SendModemSignal: true}); err != nil {
		t.Fatalf("Hangup() error=%v", err)
	}
	if fake.hangups != 1 {
		t.Fatalf("hangups=%d want 1", fake.hangups)
	}
	if len(fake.silentCmd) == 0 || fake.silentCmd[len(fake.silentCmd)-1] != "AT+QPCMV=0" {
		t.Fatalf("silentCmd=%v want QPCMV cleanup", fake.silentCmd)
	}

	fake.hangup()
	got = <-ctrl.Events()
	if got.Type != EventHangup {
		t.Fatalf("hangup event=%+v want EventHangup", got)
	}

	fake.qpcmv <- 1
	if ready := <-ctrl.PCMReady(); !ready {
		t.Fatal("PCMReady=false want true")
	}
	fake.qpcmv <- 0
	if ready := <-ctrl.PCMReady(); ready {
		t.Fatal("PCMReady=true want false")
	}
}

func TestATControllerHangupAlwaysCleansQPCMV(t *testing.T) {
	hangupErr := errors.New("ath failed")
	fake := &fakeATModem{qpcmv: make(chan int, 1), hangupErr: hangupErr}
	ctrl := NewATController(fake)

	if err := ctrl.Hangup(context.Background(), "at", HangupOptions{SendModemSignal: true}); !errors.Is(err, hangupErr) {
		t.Fatalf("Hangup() error=%v want %v", err, hangupErr)
	}
	if fake.hangups != 1 {
		t.Fatalf("hangups=%d want 1", fake.hangups)
	}
	if len(fake.silentCmd) != 1 || fake.silentCmd[0] != "AT+QPCMV=0" {
		t.Fatalf("silentCmd=%v want QPCMV cleanup after hangup error", fake.silentCmd)
	}

	fake.silentCmd = nil
	if err := ctrl.Hangup(context.Background(), "at", HangupOptions{SendModemSignal: false}); err != nil {
		t.Fatalf("Hangup(SendModemSignal=false) error=%v", err)
	}
	if fake.hangups != 1 {
		t.Fatalf("hangups=%d want unchanged", fake.hangups)
	}
	if len(fake.silentCmd) != 1 || fake.silentCmd[0] != "AT+QPCMV=0" {
		t.Fatalf("silentCmd=%v want QPCMV cleanup without modem hangup", fake.silentCmd)
	}
}

func TestATControllerGetCallsParsesCLCCActive(t *testing.T) {
	fake := &fakeATModem{qpcmv: make(chan int, 1), clcc: `+CLCC: 1,0,0,0,0,"10086",129`}
	ctrl := NewATController(fake)
	calls, err := ctrl.GetCalls(context.Background())
	if err != nil {
		t.Fatalf("GetCalls() error=%v", err)
	}
	if len(calls) != 1 || calls[0].State != CallStateConnected {
		t.Fatalf("calls=%+v want one connected call", calls)
	}
}
