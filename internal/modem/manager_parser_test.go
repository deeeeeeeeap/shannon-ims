package modem

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
	"go.bug.st/serial"
)

func TestManagerReadLoopQuarantinesOversizedLine(t *testing.T) {
	manager, err := New(config.DeviceConfig{ID: "synthetic-at", ATPort: "/dev/synthetic", DeviceBackend: "at"})
	if err != nil {
		t.Fatalf("New() error=%v", err)
	}
	port := &scriptedReadSerialPort{data: bytes.Repeat([]byte{'X'}, defaultATMaxLineBytes+1)}
	manager.port = port
	manager.running = true
	manager.healthy = true

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		manager.readLoop()
	}()

	request := commandRequest{
		cmd:      "AT+SYNTHETIC",
		timeout:  time.Second,
		respChan: make(chan string, 1),
		errChan:  make(chan error, 1),
	}
	manager.handleCommand(request)

	select {
	case commandErr := <-request.errChan:
		if !errors.Is(commandErr, ErrATLineTooLong) {
			t.Fatalf("command error=%v, want ErrATLineTooLong", commandErr)
		}
	default:
		t.Fatal("oversized line produced no command error")
	}
	if !manager.isATResponseStreamQuarantined() {
		t.Fatal("response stream not quarantined after oversized line")
	}
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("readLoop did not stop after parser overflow")
	}

	next := commandRequest{
		cmd:      "AT+NEXT",
		timeout:  time.Second,
		respChan: make(chan string, 1),
		errChan:  make(chan error, 1),
	}
	manager.handleCommand(next)
	if nextErr := <-next.errChan; nextErr == nil || !strings.Contains(nextErr.Error(), "隔离") {
		t.Fatalf("next command error=%v, want quarantined fail-closed error", nextErr)
	}
	if got := port.writes.Load(); got != 1 {
		t.Fatalf("serial writes=%d, want 1 so next command cannot consume polluted data", got)
	}
}

func TestManagerQuarantinesOversizedCumulativeResponse(t *testing.T) {
	manager, err := New(config.DeviceConfig{ID: "synthetic-at", ATPort: "/dev/synthetic", DeviceBackend: "at"})
	if err != nil {
		t.Fatalf("New() error=%v", err)
	}
	port := &timeoutSerialPort{}
	manager.port = port
	manager.running = true
	manager.healthy = true

	request := commandRequest{
		cmd:      "AT+SYNTHETIC",
		timeout:  time.Second,
		respChan: make(chan string, 1),
		errChan:  make(chan error, 1),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.handleCommand(request)
	}()

	deadline := time.Now().Add(time.Second)
	for port.writes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if port.writes.Load() != 1 {
		t.Fatal("command was not written to synthetic port")
	}
	line := strings.Repeat("R", defaultATMaxLineBytes)
	for i := 0; i <= defaultATMaxResponseBytes/defaultATMaxLineBytes; i++ {
		manager.rxChan <- rxMsg{Data: line}
	}

	select {
	case commandErr := <-request.errChan:
		if !errors.Is(commandErr, ErrATResponseTooLarge) {
			t.Fatalf("command error=%v, want ErrATResponseTooLarge", commandErr)
		}
	case <-time.After(time.Second):
		t.Fatal("oversized cumulative response produced no command error")
	}
	if !manager.isATResponseStreamQuarantined() {
		t.Fatal("response stream not quarantined after cumulative overflow")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleCommand did not stop after cumulative overflow")
	}
}

type scriptedReadSerialPort struct {
	mu     sync.Mutex
	data   []byte
	offset int
	writes atomic.Int32
}

func (p *scriptedReadSerialPort) SetMode(*serial.Mode) error { return nil }
func (p *scriptedReadSerialPort) Read(dst []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.offset >= len(p.data) {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(dst, p.data[p.offset:])
	p.offset += n
	return n, nil
}
func (p *scriptedReadSerialPort) Write(src []byte) (int, error) {
	p.writes.Add(1)
	return len(src), nil
}
func (p *scriptedReadSerialPort) Drain() error                       { return nil }
func (p *scriptedReadSerialPort) ResetInputBuffer() error            { return nil }
func (p *scriptedReadSerialPort) ResetOutputBuffer() error           { return nil }
func (p *scriptedReadSerialPort) SetDTR(bool) error                  { return nil }
func (p *scriptedReadSerialPort) SetRTS(bool) error                  { return nil }
func (p *scriptedReadSerialPort) SetReadTimeout(time.Duration) error { return nil }
func (p *scriptedReadSerialPort) Close() error                       { return nil }
func (p *scriptedReadSerialPort) Break(time.Duration) error          { return nil }
func (p *scriptedReadSerialPort) GetModemStatusBits() (*serial.ModemStatusBits, error) {
	return nil, nil
}
