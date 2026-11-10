package modem

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"

	"go.bug.st/serial"
)

// replyingSerialPort is a serial port with a modem behind it that answers each
// command line with what reply returns. Like the serial library it reports a
// read timeout as (0, nil) and fails reads and writes once it has been closed.
type replyingSerialPort struct {
	rx        chan []byte
	failRead  chan error
	closed    chan struct{}
	closeOnce sync.Once
	lineSeen  chan string

	reply     func(line string) string
	failWrite func(data []byte) error

	mu      sync.Mutex
	timeout time.Duration
	pending []byte
	partial []byte
	lines   []string
}

func newReplyingSerialPort(reply func(line string) string) *replyingSerialPort {
	if reply == nil {
		reply = func(string) string { return "\r\nOK\r\n" }
	}
	return &replyingSerialPort{
		rx:       make(chan []byte, 256),
		failRead: make(chan error, 1),
		closed:   make(chan struct{}),
		lineSeen: make(chan string, 256),
		reply:    reply,
		timeout:  time.Second,
	}
}

func (p *replyingSerialPort) Read(dst []byte) (int, error) {
	p.mu.Lock()
	if len(p.pending) > 0 {
		n := copy(dst, p.pending)
		p.pending = p.pending[n:]
		p.mu.Unlock()
		return n, nil
	}
	timeout := p.timeout
	p.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-p.closed:
		return 0, errors.New("Port has been closed")
	case err := <-p.failRead:
		return 0, err
	case chunk := <-p.rx:
		n := copy(dst, chunk)
		if n < len(chunk) {
			p.mu.Lock()
			p.pending = chunk[n:]
			p.mu.Unlock()
		}
		return n, nil
	case <-timer.C:
		return 0, nil
	}
}

func (p *replyingSerialPort) Write(src []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, errors.New("Port has been closed")
	default:
	}
	if p.failWrite != nil {
		if err := p.failWrite(src); err != nil {
			return 0, err
		}
	}

	p.mu.Lock()
	p.partial = append(p.partial, src...)
	var lines []string
	for {
		end := bytes.IndexByte(p.partial, '\n')
		if end < 0 {
			break
		}
		lines = append(lines, strings.TrimRight(string(p.partial[:end]), "\r"))
		p.partial = p.partial[end+1:]
	}
	p.lines = append(p.lines, lines...)
	p.mu.Unlock()

	for _, line := range lines {
		select {
		case p.lineSeen <- line:
		default:
		}
		if answer := p.reply(line); answer != "" {
			select {
			case p.rx <- []byte(answer):
			case <-p.closed:
			}
		}
	}
	return len(src), nil
}

func (p *replyingSerialPort) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *replyingSerialPort) SetReadTimeout(timeout time.Duration) error {
	p.mu.Lock()
	p.timeout = timeout
	p.mu.Unlock()
	return nil
}

func (p *replyingSerialPort) SetMode(*serial.Mode) error { return nil }
func (p *replyingSerialPort) Drain() error               { return nil }
func (p *replyingSerialPort) ResetInputBuffer() error    { return nil }
func (p *replyingSerialPort) ResetOutputBuffer() error   { return nil }
func (p *replyingSerialPort) SetDTR(bool) error          { return nil }
func (p *replyingSerialPort) SetRTS(bool) error          { return nil }
func (p *replyingSerialPort) Break(time.Duration) error  { return nil }
func (p *replyingSerialPort) GetModemStatusBits() (*serial.ModemStatusBits, error) {
	return &serial.ModemStatusBits{}, nil
}

func (p *replyingSerialPort) isClosed() bool {
	select {
	case <-p.closed:
		return true
	default:
		return false
	}
}

func (p *replyingSerialPort) received(line string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, got := range p.lines {
		if got == line {
			return true
		}
	}
	return false
}

// waitForLine returns once the modem side has been sent the command line.
func (p *replyingSerialPort) waitForLine(t *testing.T, line string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-p.lineSeen:
			if got == line {
				return
			}
		case <-deadline:
			t.Fatalf("the port was never sent %q", line)
		}
	}
}

var virtualPortTestSeq atomic.Int64

func virtualPortTestName() string {
	return fmt.Sprintf("sim://modem-test-%d", virtualPortTestSeq.Add(1))
}

// startManagerOnPort starts a manager whose AT port is the given port and
// waits until it has sent its setup commands.
func startManagerOnPort(t *testing.T, port serial.Port) *Manager {
	t.Helper()
	name := virtualPortTestName()
	t.Cleanup(RegisterVirtualSerialPort(name, func(string, *serial.Mode) (serial.Port, error) {
		return port, nil
	}))

	m, err := New(config.DeviceConfig{ID: "dev-sim", DeviceBackend: "at", ATPort: name})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { m.StopAndWait(2 * time.Second) })
	if !m.WaitReady(5 * time.Second) {
		t.Fatal("the manager did not finish its setup commands")
	}
	return m
}

// silentOn answers every command except the given one, which gets no answer.
func silentOn(command string) func(string) string {
	return func(line string) string {
		if line == command {
			return ""
		}
		return "\r\nOK\r\n"
	}
}

func TestNewTakesTheSerialModeFromTheDeviceEntry(t *testing.T) {
	unset, err := New(config.DeviceConfig{ID: "d", DeviceBackend: "at", ATPort: "/dev/ttyUSB2"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	want := serial.Mode{BaudRate: 115200, DataBits: 8, Parity: serial.NoParity, StopBits: serial.OneStopBit}
	if *unset.portMode != want {
		t.Fatalf("mode of an entry without serial settings = %+v, want %+v", *unset.portMode, want)
	}

	set, err := New(config.DeviceConfig{
		ID: "d", DeviceBackend: "at", ATPort: "/dev/ttyS1",
		BaudRate: 9600, DataBits: 7, StopBits: 2, Parity: "o",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	want = serial.Mode{BaudRate: 9600, DataBits: 7, Parity: serial.OddParity, StopBits: serial.TwoStopBits}
	if *set.portMode != want {
		t.Fatalf("mode of an entry with serial settings = %+v, want %+v", *set.portMode, want)
	}
}

func TestStartOpensTheATPortThroughTheRegisteredOpenerWithTheConfiguredMode(t *testing.T) {
	name := virtualPortTestName()
	port := newReplyingSerialPort(func(line string) string {
		if line == "AT+CSQ" {
			return "\r\n+CSQ: 20,99\r\n\r\nOK\r\n"
		}
		return "\r\nOK\r\n"
	})
	var gotName string
	var gotMode serial.Mode
	defer RegisterVirtualSerialPort(name, func(n string, mode *serial.Mode) (serial.Port, error) {
		gotName, gotMode = n, *mode
		return port, nil
	})()

	m, err := New(config.DeviceConfig{
		ID: "dev-sim", DeviceBackend: "at", ATPort: name,
		BaudRate: 9600, DataBits: 7, StopBits: 2, Parity: "E",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer m.StopAndWait(2 * time.Second)

	wantMode := serial.Mode{BaudRate: 9600, DataBits: 7, Parity: serial.EvenParity, StopBits: serial.TwoStopBits}
	if gotName != name || gotMode != wantMode {
		t.Fatalf("opened %q with %+v, want %q with %+v", gotName, gotMode, name, wantMode)
	}
	if !m.WaitReady(5 * time.Second) {
		t.Fatal("the manager did not finish its setup commands")
	}
	for _, command := range []string{"AT", "ATE0", "AT+CMGF=0", "AT+CNMI=2,1,0,0,0"} {
		if !port.received(command) {
			t.Errorf("setup did not send %q", command)
		}
	}

	resp, err := m.ExecuteAT("AT+CSQ", 5*time.Second)
	if err != nil || resp != "+CSQ: 20,99" {
		t.Fatalf("ExecuteAT() = %q, %v; want the answer of the port", resp, err)
	}

	if !m.StopAndWait(2 * time.Second) {
		t.Fatal("the loops were still running two seconds after Stop")
	}
	if !port.isClosed() {
		t.Fatal("Stop left the port open")
	}
}

func TestStartRetriesAPortThatIsBusy(t *testing.T) {
	name := virtualPortTestName()
	port := newReplyingSerialPort(nil)
	attempts := 0
	defer RegisterVirtualSerialPort(name, func(string, *serial.Mode) (serial.Port, error) {
		attempts++
		if attempts < 3 {
			// The text the serial library gives for EBUSY.
			return nil, errors.New("Serial port busy")
		}
		return port, nil
	})()

	m, err := New(config.DeviceConfig{ID: "dev-sim", DeviceBackend: "at", ATPort: name})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start() error = %v after %d attempts", err, attempts)
	}
	defer m.StopAndWait(2 * time.Second)
	if attempts != 3 {
		t.Fatalf("the port was opened %d times, want 3", attempts)
	}
}

func TestCommandFailsAtOnceAndRecoveryStartsWhenTheLinkBreaksMidCommand(t *testing.T) {
	for _, tc := range []struct {
		name       string
		readErr    string
		wantReason string
	}{
		// What the serial library reports when the device goes away during a read.
		{name: "device removed", readErr: "Port has been closed", wantReason: "serial_read_error"},
		{name: "input output error", readErr: "input/output error", wantReason: "serial_runtime_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := newReplyingSerialPort(silentOn("AT+SLOW"))
			m := startManagerOnPort(t, port)
			reasons := make(chan string, 4)
			m.SetOnDisconnectWithReason(func(reason string) { reasons <- reason })

			result := make(chan error, 1)
			go func() {
				_, err := m.ExecuteATHigh("AT+SLOW", 30*time.Second)
				result <- err
			}()
			port.waitForLine(t, "AT+SLOW")
			port.failRead <- errors.New(tc.readErr)

			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), tc.readErr) {
					t.Fatalf("command error = %v, want the read error", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the command was still waiting five seconds after the link broke")
			}
			select {
			case reason := <-reasons:
				if reason != tc.wantReason {
					t.Fatalf("disconnect reason = %q, want %q", reason, tc.wantReason)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the broken link was not reported, so nothing would reconnect the modem")
			}
			if m.CanExecuteAT() {
				t.Fatal("CanExecuteAT() = true on a port nobody reads any more")
			}
			if !port.isClosed() {
				t.Fatal("the port was left open")
			}
			if !m.StopAndWait(2 * time.Second) {
				t.Fatal("the loops were still running")
			}
		})
	}
}

func TestStopReleasesACommandThatIsWaitingForItsAnswer(t *testing.T) {
	port := newReplyingSerialPort(silentOn("AT+SLOW"))
	m := startManagerOnPort(t, port)
	reasons := make(chan string, 4)
	m.SetOnDisconnectWithReason(func(reason string) { reasons <- reason })

	result := make(chan error, 1)
	go func() {
		_, err := m.ExecuteATHigh("AT+SLOW", 30*time.Second)
		result <- err
	}()
	port.waitForLine(t, "AT+SLOW")

	if !m.StopAndWait(2 * time.Second) {
		t.Fatal("the main loop kept waiting for the answer after Stop")
	}
	select {
	case err := <-result:
		if err == nil || err.Error() != "manager stopped" {
			t.Fatalf("command error = %v, want manager stopped", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the caller was not released")
	}
	select {
	case reason := <-reasons:
		t.Fatalf("an intended stop was reported as a disconnect (%s)", reason)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestStoppingAnIdleManagerIsNotReportedAsADisconnect(t *testing.T) {
	port := newReplyingSerialPort(nil)
	m := startManagerOnPort(t, port)
	reasons := make(chan string, 4)
	m.SetOnDisconnectWithReason(func(reason string) { reasons <- reason })

	if !m.StopAndWait(2 * time.Second) {
		t.Fatal("the loops were still running two seconds after Stop")
	}
	select {
	case reason := <-reasons:
		t.Fatalf("an intended stop was reported as a disconnect (%s)", reason)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestInteractiveCommandFailsAtOnceWhenTheFollowUpCannotBeWritten(t *testing.T) {
	m, err := New(config.DeviceConfig{ID: "dev-at", ATPort: "/dev/ttyUSB6", DeviceBackend: "at"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	port := newReplyingSerialPort(func(string) string { return "" })
	var refused [][]byte
	port.failWrite = func(data []byte) error {
		if strings.HasPrefix(string(data), "AT+CMGS") {
			return nil
		}
		refused = append(refused, append([]byte(nil), data...))
		return errors.New("write refused")
	}
	m.port = port
	m.running = true
	m.healthy = true

	const followUp = "0011000B818100000000F00000AA0141\x1a"
	req := commandRequest{
		cmd:            "AT+CMGS=15",
		timeout:        30 * time.Second,
		respChan:       make(chan string, 1),
		errChan:        make(chan error, 1),
		interactive:    true,
		waitPrompt:     true,
		followUp:       followUp,
		cancelSequence: []byte{0x1b},
	}
	done := make(chan struct{})
	go func() {
		m.handleCommand(req)
		close(done)
	}()
	m.rxChan <- rxMsg{Data: "> "}

	select {
	case err := <-req.errChan:
		if err == nil || !strings.Contains(err.Error(), "write refused") {
			t.Fatalf("command error = %v, want the write error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the command went on waiting for an answer to a message it never sent")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleCommand did not return")
	}

	if !m.isATResponseStreamQuarantined() {
		t.Fatal("the response stream was not quarantined although the modem may still wait for input")
	}
	if len(refused) != 2 || string(refused[0]) != followUp || !bytes.Equal(refused[1], []byte{0x1b}) {
		t.Fatalf("writes after the prompt = %q, want the message and then the cancel sequence", refused)
	}
}

func TestSerialATReturnsTheAnswerOfACommandTheModemRefuses(t *testing.T) {
	for _, answer := range []string{
		"\r\n+CME ERROR: 10\r\n",
		"\r\n+CMS ERROR: 304\r\n",
		"\r\nERROR\r\n",
		"\r\nNO CARRIER\r\n",
		"\r\n+CPIN: READY\r\n\r\nOK\r\n",
	} {
		t.Run(strings.TrimSpace(answer), func(t *testing.T) {
			port := newReplyingSerialPort(func(string) string { return answer })
			session := &SerialAT{port: port}

			started := time.Now()
			resp, err := session.Execute("AT+CPIN?", 20*time.Second)
			if err != nil || resp != answer {
				t.Fatalf("Execute() = %q, %v; want the answer of the modem", resp, err)
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("Execute() took %s for an answer that was there at once", elapsed)
			}
			if !port.received("AT+CPIN?") {
				t.Fatal("the command was not written as one line")
			}
		})
	}
}

func TestSerialATStopsReadingWhenThePortFails(t *testing.T) {
	port := newReplyingSerialPort(nil)
	port.reply = func(string) string {
		port.failRead <- errors.New("Port has been closed")
		return ""
	}
	session := &SerialAT{port: port}

	started := time.Now()
	_, err := session.Execute("AT", 20*time.Second)
	if err == nil || !strings.Contains(err.Error(), "Port has been closed") {
		t.Fatalf("Execute() error = %v, want the read error", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("Execute() kept reading a dead port for %s", elapsed)
	}
}

func TestSerialATTimesOutWhenTheModemStaysSilent(t *testing.T) {
	port := newReplyingSerialPort(func(string) string { return "\r\n+CSQ: 20,99\r\n" })
	session := &SerialAT{port: port}

	resp, err := session.Execute("AT+CSQ", 400*time.Millisecond)
	if err == nil || err.Error() != "timeout" {
		t.Fatalf("Execute() error = %v, want timeout", err)
	}
	if resp != "\r\n+CSQ: 20,99\r\n" {
		t.Fatalf("Execute() = %q, want what had arrived before the timeout", resp)
	}
}

func TestOpenSerialATUsesTheGivenSettings(t *testing.T) {
	name := virtualPortTestName()
	port := newReplyingSerialPort(nil)
	var gotMode serial.Mode
	defer RegisterVirtualSerialPort(name, func(_ string, mode *serial.Mode) (serial.Port, error) {
		gotMode = *mode
		return port, nil
	})()

	session, err := OpenSerialAT(name, config.SerialSettings{BaudRate: 19200, DataBits: 8, StopBits: 1, Parity: "O"})
	if err != nil {
		t.Fatalf("OpenSerialAT() error = %v", err)
	}
	want := serial.Mode{BaudRate: 19200, DataBits: 8, Parity: serial.OddParity, StopBits: serial.OneStopBit}
	if gotMode != want {
		t.Fatalf("opened with %+v, want %+v", gotMode, want)
	}
	if resp, err := session.Execute("AT", 2*time.Second); err != nil || resp != "\r\nOK\r\n" {
		t.Fatalf("Execute() = %q, %v", resp, err)
	}
	if err := session.Close(); err != nil || !port.isClosed() {
		t.Fatalf("Close() error = %v, port closed = %v", err, port.isClosed())
	}
}

func TestATResponseCompleteLooksForAFinalResultOnItsOwnLine(t *testing.T) {
	for resp, want := range map[string]bool{
		"":                                   false,
		"\r\nOK\r\n":                         true,
		"\r\n+CSQ: 20,99\r\n\r\nOK\r\n":      true,
		"\r\nERROR\r\n":                      true,
		"\r\n+CME ERROR: 10\r\n":             true,
		"\r\n+CMS ERROR: 304\r\n":            true,
		"\r\nNO CARRIER\r\n":                 true,
		"\r\nOK":                             false, // the line may not be complete yet
		"\r\n+CSQ: 20,99\r\n":                false,
		"\r\n+COPS: 0,0,\"OK MOBILE\",7\r\n": false,
		"\r\n+CUSD: 0,\"NO ERROR\",15\r\n":   false,
	} {
		if got := atResponseComplete(resp); got != want {
			t.Errorf("atResponseComplete(%q) = %v, want %v", resp, got, want)
		}
	}
}

func TestProbeIMEIReadsTheAnswerThroughTheRegisteredOpener(t *testing.T) {
	const identity = "860000000000019"
	name := virtualPortTestName()
	port := newReplyingSerialPort(func(line string) string {
		if line == "AT+CGSN" {
			return "\r\n" + identity + "\r\n\r\nOK\r\n"
		}
		return "\r\nOK\r\n"
	})
	var gotMode serial.Mode
	defer RegisterVirtualSerialPort(name, func(_ string, mode *serial.Mode) (serial.Port, error) {
		gotMode = *mode
		return port, nil
	})()

	got, err := ProbeIMEI(name, 5*time.Second)
	if err != nil || got != identity {
		t.Fatalf("ProbeIMEI() = %q, %v", got, err)
	}
	want := serial.Mode{BaudRate: 115200, DataBits: 8, Parity: serial.NoParity, StopBits: serial.OneStopBit}
	if gotMode != want {
		t.Fatalf("opened with %+v, want %+v", gotMode, want)
	}
	if !port.isClosed() {
		t.Fatal("the probe left the port open")
	}
}

func TestProbeIMEIGivesUpAtOnceWhenThePortFails(t *testing.T) {
	name := virtualPortTestName()
	port := newReplyingSerialPort(func(string) string { return "" })
	port.failRead <- errors.New("Port has been closed")
	defer RegisterVirtualSerialPort(name, func(string, *serial.Mode) (serial.Port, error) {
		return port, nil
	})()

	started := time.Now()
	_, err := ProbeIMEI(name, 20*time.Second)
	if err == nil || !strings.Contains(err.Error(), "Port has been closed") {
		t.Fatalf("ProbeIMEI() error = %v, want the read error", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("ProbeIMEI() kept reading a dead port for %s", elapsed)
	}
}

func TestRegisterVirtualSerialPortReplacesAndRemovesOnlyItsOwnOpener(t *testing.T) {
	name := virtualPortTestName()
	first, second := newReplyingSerialPort(nil), newReplyingSerialPort(nil)
	openerOf := func(port serial.Port) SerialPortOpener {
		return func(string, *serial.Mode) (serial.Port, error) { return port, nil }
	}

	removeFirst := RegisterVirtualSerialPort(name, openerOf(first))
	removeSecond := RegisterVirtualSerialPort(" "+name+" ", openerOf(second))
	if got, err := openSerialPort(name, defaultSerialMode()); err != nil || got != serial.Port(second) {
		t.Fatalf("open after a second registration = %v, %v; want the second port", got, err)
	}

	removeFirst()
	if got, err := openSerialPort(name, defaultSerialMode()); err != nil || got != serial.Port(second) {
		t.Fatalf("open after removing the replaced registration = %v, %v; want the second port", got, err)
	}

	removeSecond()
	if _, err := openSerialPort(name, defaultSerialMode()); err == nil {
		t.Fatal("a name that is no longer registered was not opened as a device")
	}

	RegisterVirtualSerialPort(name, nil)()
	RegisterVirtualSerialPort("  ", openerOf(first))()
	if _, err := openSerialPort(name, defaultSerialMode()); err == nil {
		t.Fatal("a registration without an opener took effect")
	}
}
