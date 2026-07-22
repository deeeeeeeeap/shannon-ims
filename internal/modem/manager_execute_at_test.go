package modem

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
	"go.bug.st/serial"
)

func TestManagerExecuteATFailsFastWithoutATPort(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-qmi",
		DeviceBackend: "qmi",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if m.HasATPort() {
		t.Fatal("HasATPort() = true, want false")
	}
	if m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = true, want false")
	}

	if _, err := m.ExecuteAT("AT", 100*time.Millisecond); err == nil || err.Error() != "当前设备没有可用 AT 端口" {
		t.Fatalf("ExecuteAT() error = %v, want 当前设备没有可用 AT 端口", err)
	}
}

func TestManagerNewAllowsResolvedQMIWithoutATPort(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-qmi-resolved",
		ControlDevice: "/dev/cdc-wdm0",
	})
	if err != nil {
		t.Fatalf("New() error = %v, want nil for resolved QMI backend without AT port", err)
	}
	if m.HasATPort() {
		t.Fatal("HasATPort() = true, want false")
	}
	if m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = true, want false")
	}
}

func TestManagerExecuteATFailsFastWhenNotRunning(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-qmi",
		DeviceBackend: "qmi",
		ATPort:        "/dev/ttyUSB6",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !m.HasATPort() {
		t.Fatal("HasATPort() = false, want true")
	}
	if m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = true, want false")
	}

	if _, err := m.ExecuteAT("AT", 100*time.Millisecond); err == nil || err.Error() != "AT 管理器未启动或不可用" {
		t.Fatalf("ExecuteAT() error = %v, want AT 管理器未启动或不可用", err)
	}
}

func TestManagerStartSkipsATManagerForPureQMIBackend(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-qmi",
		DeviceBackend: "qmi",
		ATPort:        "/dev/vohive-test-at-port-that-must-not-open",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !m.HasATPort() {
		t.Fatal("HasATPort() = false, want true so the manual AT terminal can still see the configured port")
	}

	if err := m.Start(); err != nil {
		t.Fatalf("Start() error = %v, want nil without opening the AT port", err)
	}
	if !m.WaitReady(20 * time.Millisecond) {
		t.Fatal("WaitReady() = false, want true after pure QMI start skips AT manager")
	}
	if m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = true, want false because pure QMI must not expose the automatic AT manager")
	}
}

func TestManagerStartSkipsATManagerForResolvedQMIBackend(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-qmi-resolved",
		ControlDevice: "/dev/cdc-wdm0",
		ATPort:        "/dev/vohive-test-at-port-that-must-not-open",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := m.Start(); err != nil {
		t.Fatalf("Start() error = %v, want nil without opening the AT port", err)
	}
	if !m.WaitReady(20 * time.Millisecond) {
		t.Fatal("WaitReady() = false, want true after resolved QMI start skips AT manager")
	}
	if m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = true, want false because resolved QMI must not expose the automatic AT manager")
	}
}

func TestManagerCanExecuteATWhenRunning(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-at",
		DeviceBackend: "at",
		ATPort:        "/dev/ttyUSB6",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	m.running = true
	m.healthy = true

	if !m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = false, want true")
	}
}

func TestManagerStopAndWaitWaitsForBackgroundLoops(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-qmi",
		DeviceBackend: "qmi",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	release := make(chan struct{})
	m.loopWG.Add(1)
	go func() {
		defer m.loopWG.Done()
		<-release
	}()

	if m.StopAndWait(20 * time.Millisecond) {
		t.Fatal("StopAndWait() = true while background loop is still running, want false")
	}

	close(release)
	if !m.StopAndWait(time.Second) {
		t.Fatal("StopAndWait() = false after background loop exited, want true")
	}
}

func TestManagerClassifiesFatalSerialRuntimeErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "input output", err: errors.New("input/output error"), want: true},
		{name: "no such device", err: errors.New("open /dev/ttyUSB2: no such device"), want: true},
		{name: "bad file descriptor", err: errors.New("bad file descriptor"), want: true},
		{name: "timeout", err: errors.New("timeout"), want: false},
		{name: "command error", err: errors.New("设备返回错误: ERROR"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFatalSerialRuntimeErr(tt.err); got != tt.want {
				t.Fatalf("isFatalSerialRuntimeErr(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

type failingSerialPort struct {
	writeErr error
	closed   atomic.Bool
}

func (p *failingSerialPort) SetMode(*serial.Mode) error { return nil }
func (p *failingSerialPort) Read([]byte) (int, error)   { return 0, io.EOF }
func (p *failingSerialPort) Write([]byte) (int, error)  { return 0, p.writeErr }
func (p *failingSerialPort) Drain() error               { return nil }
func (p *failingSerialPort) ResetInputBuffer() error    { return nil }
func (p *failingSerialPort) ResetOutputBuffer() error   { return nil }
func (p *failingSerialPort) SetDTR(bool) error          { return nil }
func (p *failingSerialPort) SetRTS(bool) error          { return nil }
func (p *failingSerialPort) GetModemStatusBits() (*serial.ModemStatusBits, error) {
	return nil, nil
}
func (p *failingSerialPort) SetReadTimeout(time.Duration) error { return nil }
func (p *failingSerialPort) Close() error {
	p.closed.Store(true)
	return nil
}
func (p *failingSerialPort) Break(time.Duration) error { return nil }

type timeoutSerialPort struct {
	closed atomic.Bool
	writes atomic.Int32
}

func (p *timeoutSerialPort) SetMode(*serial.Mode) error { return nil }
func (p *timeoutSerialPort) Read([]byte) (int, error)   { return 0, io.EOF }
func (p *timeoutSerialPort) Write(b []byte) (int, error) {
	p.writes.Add(1)
	return len(b), nil
}
func (p *timeoutSerialPort) Drain() error             { return nil }
func (p *timeoutSerialPort) ResetInputBuffer() error  { return nil }
func (p *timeoutSerialPort) ResetOutputBuffer() error { return nil }
func (p *timeoutSerialPort) SetDTR(bool) error        { return nil }
func (p *timeoutSerialPort) SetRTS(bool) error        { return nil }
func (p *timeoutSerialPort) GetModemStatusBits() (*serial.ModemStatusBits, error) {
	return nil, nil
}
func (p *timeoutSerialPort) SetReadTimeout(time.Duration) error { return nil }
func (p *timeoutSerialPort) Close() error {
	p.closed.Store(true)
	return nil
}
func (p *timeoutSerialPort) Break(time.Duration) error { return nil }

type recordingTimeoutSerialPort struct {
	timeoutSerialPort
	payloads chan []byte
}

func (p *recordingTimeoutSerialPort) Write(b []byte) (int, error) {
	p.timeoutSerialPort.writes.Add(1)
	payload := append([]byte(nil), b...)
	p.payloads <- payload
	return len(b), nil
}

func TestHandleCommandNotifiesDisconnectOnFatalWriteError(t *testing.T) {
	m, err := New(config.DeviceConfig{ID: "dev-at", ATPort: "/dev/ttyUSB6", DeviceBackend: "at"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	port := &failingSerialPort{writeErr: errors.New("input/output error")}
	m.port = port
	m.running = true
	m.healthy = true
	disconnected := make(chan struct{}, 1)
	m.SetOnDisconnect(func() { disconnected <- struct{}{} })

	req := commandRequest{
		cmd:      "AT+CPIN?",
		timeout:  time.Second,
		respChan: make(chan string, 1),
		errChan:  make(chan error, 1),
	}
	m.handleCommand(req)

	if err := <-req.errChan; err == nil || !strings.Contains(err.Error(), "input/output error") {
		t.Fatalf("command error = %v, want input/output error", err)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("disconnect callback was not called")
	}
	if m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = true after fatal serial error, want false")
	}
	if !port.closed.Load() {
		t.Fatal("serial port was not closed")
	}
}

func TestHandleCommandTriggersWatchdogAfterConsecutiveNormalTimeouts(t *testing.T) {
	m, err := New(config.DeviceConfig{ID: "dev-at", ATPort: "/dev/ttyUSB6", DeviceBackend: "at"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	port := &timeoutSerialPort{}
	m.port = port
	m.running = true
	m.healthy = true
	disconnected := make(chan string, 1)
	m.SetOnDisconnectWithReason(func(reason string) { disconnected <- reason })

	for i := 1; i <= atTimeoutWatchdogThreshold; i++ {
		req := commandRequest{
			cmd:      "AT+PING",
			timeout:  time.Millisecond,
			respChan: make(chan string, 1),
			errChan:  make(chan error, 1),
		}
		m.handleCommand(req)
		if err := <-req.errChan; err == nil || err.Error() != "命令执行超时" {
			t.Fatalf("timeout %d error=%v want 命令执行超时", i, err)
		}
		if i < atTimeoutWatchdogThreshold {
			select {
			case reason := <-disconnected:
				t.Fatalf("disconnect reason=%q before threshold %d", reason, i)
			default:
			}
			// 只有成功重开串口后，下一条命令才可继续用于累计 watchdog。
			m.markATResponseStreamReady()
		}
	}

	select {
	case reason := <-disconnected:
		if reason != "at_timeout_threshold" {
			t.Fatalf("reason=%q want at_timeout_threshold", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("disconnect callback was not called after AT timeout threshold")
	}
	if m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = true after timeout threshold, want false")
	}
	if !port.closed.Load() {
		t.Fatal("serial port was not closed after timeout threshold")
	}
}

func TestHandleCommandNormalTimeoutDoesNotWriteCancelSequence(t *testing.T) {
	m, err := New(config.DeviceConfig{ID: "dev-at", ATPort: "/dev/ttyUSB6", DeviceBackend: "at"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	port := &timeoutSerialPort{}
	m.port = port
	m.running = true
	m.healthy = true

	req := commandRequest{
		cmd:      "AT+PING",
		timeout:  time.Millisecond,
		respChan: make(chan string, 1),
		errChan:  make(chan error, 1),
	}
	m.handleCommand(req)
	if err := <-req.errChan; err == nil || err.Error() != "命令执行超时" {
		t.Fatalf("handleCommand() error = %v, want 命令执行超时", err)
	}
	if got := port.writes.Load(); got != 1 {
		t.Fatalf("serial writes after normal timeout = %d, want only the command write", got)
	}
	if m.IsHealthy() {
		t.Fatal("IsHealthy() = true after the first timeout, want Pool health check to observe fail-closed state")
	}
	if m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = true after the first timeout, want response stream quarantined")
	}
	m.atTimeoutMu.Lock()
	timeoutStreak := m.atTimeoutStreak
	m.atTimeoutMu.Unlock()
	if timeoutStreak != 1 {
		t.Fatalf("AT timeout streak=%d after first timeout, want 1 (below direct disconnect threshold)", timeoutStreak)
	}
}

func TestHandleCommandInteractiveTimeoutWritesDeclaredCancelSequence(t *testing.T) {
	m, err := New(config.DeviceConfig{ID: "dev-at", ATPort: "/dev/ttyUSB6", DeviceBackend: "at"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	port := &recordingTimeoutSerialPort{payloads: make(chan []byte, 2)}
	m.port = port
	m.running = true
	m.healthy = true

	req := commandRequest{
		cmd:            "AT+CMGS=1",
		timeout:        time.Millisecond,
		respChan:       make(chan string, 1),
		errChan:        make(chan error, 1),
		interactive:    true,
		cancelSequence: []byte{0x1B},
	}
	m.handleCommand(req)
	if err := <-req.errChan; err == nil || err.Error() != "命令执行超时" {
		t.Fatalf("handleCommand() error = %v, want 命令执行超时", err)
	}

	commandWrite := <-port.payloads
	if string(commandWrite) != "AT+CMGS=1\r\n" {
		t.Fatalf("first serial write = %q, want AT+CMGS=1\\r\\n", commandWrite)
	}
	select {
	case cancelWrite := <-port.payloads:
		if !bytes.Equal(cancelWrite, []byte{0x1B}) {
			t.Fatalf("cancel sequence = %x, want ESC", cancelWrite)
		}
	case <-time.After(time.Second):
		t.Fatal("declared cancel sequence was not written")
	}
}

func TestHandleCommandIgnoresHighPriorityTimeoutsForWatchdog(t *testing.T) {
	m, err := New(config.DeviceConfig{ID: "dev-at", ATPort: "/dev/ttyUSB6", DeviceBackend: "at"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	m.port = &timeoutSerialPort{}
	m.running = true
	m.healthy = true
	disconnected := make(chan string, 1)
	m.SetOnDisconnectWithReason(func(reason string) { disconnected <- reason })

	for i := 0; i < atTimeoutWatchdogThreshold+1; i++ {
		req := commandRequest{
			cmd:          "AT+HIGH",
			timeout:      time.Millisecond,
			respChan:     make(chan string, 1),
			errChan:      make(chan error, 1),
			highPriority: true,
		}
		m.handleCommand(req)
		if err := <-req.errChan; err == nil || err.Error() != "命令执行超时" {
			t.Fatalf("timeout %d error=%v want 命令执行超时", i, err)
		}
		// 高优先级 timeout 不计入 watchdog，但仍须经串口重开解除响应隔离。
		m.markATResponseStreamReady()
	}

	select {
	case reason := <-disconnected:
		t.Fatalf("disconnect reason=%q for high-priority timeouts, want none", reason)
	default:
	}
	if !m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = false after high-priority timeouts, want true")
	}
}

func TestHandleCommandResetsTimeoutWatchdogOnDeviceError(t *testing.T) {
	m, err := New(config.DeviceConfig{ID: "dev-at", ATPort: "/dev/ttyUSB6", DeviceBackend: "at"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	m.port = &timeoutSerialPort{}
	m.running = true
	m.healthy = true
	disconnected := make(chan string, 1)
	m.SetOnDisconnectWithReason(func(reason string) { disconnected <- reason })

	for i := 0; i < atTimeoutWatchdogThreshold-1; i++ {
		req := commandRequest{
			cmd:      "AT+PING",
			timeout:  time.Millisecond,
			respChan: make(chan string, 1),
			errChan:  make(chan error, 1),
		}
		m.handleCommand(req)
		<-req.errChan
		m.markATResponseStreamReady()
	}

	req := commandRequest{
		cmd:      "AT+ERROR",
		timeout:  time.Second,
		respChan: make(chan string, 1),
		errChan:  make(chan error, 1),
	}
	go func() {
		time.Sleep(time.Millisecond)
		m.rxChan <- rxMsg{Data: "ERROR"}
	}()
	m.handleCommand(req)
	if err := <-req.errChan; err == nil || !strings.Contains(err.Error(), "设备返回错误") {
		t.Fatalf("device error=%v want 设备返回错误", err)
	}

	for i := 0; i < atTimeoutWatchdogThreshold-1; i++ {
		req := commandRequest{
			cmd:      "AT+PING",
			timeout:  time.Millisecond,
			respChan: make(chan string, 1),
			errChan:  make(chan error, 1),
		}
		m.handleCommand(req)
		<-req.errChan
		m.markATResponseStreamReady()
	}

	select {
	case reason := <-disconnected:
		t.Fatalf("disconnect reason=%q after reset by device error, want none", reason)
	default:
	}
	if !m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = false after reset by device error, want true")
	}
}

func TestExecuteATReturnsFatalSerialErrorBeforeManagerStopped(t *testing.T) {
	m, err := New(config.DeviceConfig{ID: "dev-at", ATPort: "/dev/ttyUSB6", DeviceBackend: "at"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	m.port = &failingSerialPort{writeErr: errors.New("input/output error")}
	m.running = true
	m.healthy = true
	disconnected := make(chan struct{}, 1)
	m.SetOnDisconnect(func() { disconnected <- struct{}{} })

	go func() {
		req := <-m.cmdChan
		m.handleCommand(req)
	}()

	_, err = m.ExecuteAT("AT+CPIN?", time.Second)
	if err == nil || !strings.Contains(err.Error(), "input/output error") {
		t.Fatalf("ExecuteAT() error = %v, want input/output error", err)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("disconnect callback was not called")
	}
}

func TestManagerIsURCTreatsCGLAAsSynchronousResponse(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-qmi",
		DeviceBackend: "qmi",
		ATPort:        "/dev/ttyUSB6",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if m.isURC(`+CGLA: 16,"BF41038101059000"`) {
		t.Fatal("isURC(+CGLA) = true, want false so APDU responses stay with the active command")
	}
}

func TestManagerExecuteATReturnsResponseWhenRunning(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-at",
		DeviceBackend: "at",
		ATPort:        "/dev/ttyUSB6",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	m.running = true
	m.healthy = true

	go func() {
		req := <-m.cmdChan
		req.respChan <- "OK"
	}()

	resp, err := m.ExecuteAT("AT", time.Second)
	if err != nil {
		t.Fatalf("ExecuteAT() error = %v", err)
	}
	if resp != "OK" {
		t.Fatalf("ExecuteAT() resp = %q, want %q", resp, "OK")
	}
}

func TestManagerExecuteATLateResultCannotCompleteNextRequest(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)

	m, err := New(config.DeviceConfig{
		ID:            "dev-at",
		DeviceBackend: "at",
		ATPort:        "/dev/ttyUSB6",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	m.running = true
	m.healthy = true

	type executeResult struct {
		response string
		err      error
	}

	firstDone := make(chan executeResult, 1)
	go func() {
		response, executeErr := m.ExecuteAT("AT+FIRST", time.Second)
		firstDone <- executeResult{response: response, err: executeErr}
	}()
	firstRequest := <-m.cmdChan
	firstRequest.errChan <- errors.New("synthetic request A timeout")

	select {
	case result := <-firstDone:
		if result.err == nil || result.err.Error() != "synthetic request A timeout" {
			t.Fatalf("first ExecuteAT() error = %v, want synthetic request A timeout", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("first ExecuteAT() did not finish")
	}

	secondDone := make(chan executeResult, 1)
	go func() {
		response, executeErr := m.ExecuteAT("AT+SECOND", time.Second)
		secondDone <- executeResult{response: response, err: executeErr}
	}()
	secondRequest := <-m.cmdChan

	firstRequest.respChan <- "late response from request A"
	select {
	case result := <-secondDone:
		t.Fatalf("second ExecuteAT() completed from request A late result: response=%q err=%v", result.response, result.err)
	case <-time.After(20 * time.Millisecond):
	}

	secondRequest.respChan <- "response from request B"
	select {
	case result := <-secondDone:
		if result.err != nil {
			t.Fatalf("second ExecuteAT() error = %v", result.err)
		}
		if result.response != "response from request B" {
			t.Fatalf("second ExecuteAT() response = %q, want response from request B", result.response)
		}
	case <-time.After(time.Second):
		t.Fatal("second ExecuteAT() did not finish with its own response")
	}
}

func TestManagerExecuteATLatePhysicalResponseCannotCompleteNextRequest(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-at",
		DeviceBackend: "at",
		ATPort:        "/dev/ttyUSB6",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	port := &recordingTimeoutSerialPort{payloads: make(chan []byte, 4)}
	m.port = port
	m.running = true
	m.healthy = true
	t.Cleanup(m.Stop)

	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for i := 0; i < 2; i++ {
			req := <-m.cmdChan
			m.handleCommand(req)
		}
	}()

	type executeResult struct {
		response string
		err      error
	}
	firstDone := make(chan executeResult, 1)
	go func() {
		response, executeErr := m.ExecuteAT("AT+FIRST", 30*time.Millisecond)
		firstDone <- executeResult{response: response, err: executeErr}
	}()
	select {
	case payload := <-port.payloads:
		if string(payload) != "AT+FIRST\r\n" {
			t.Fatalf("first serial write = %q, want AT+FIRST\\r\\n", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("first command was not written")
	}

	secondDone := make(chan executeResult, 1)
	go func() {
		response, executeErr := m.ExecuteAT("AT+SECOND", 500*time.Millisecond)
		secondDone <- executeResult{response: response, err: executeErr}
	}()
	queueDeadline := time.Now().Add(time.Second)
	for len(m.cmdChan) != 1 {
		if time.Now().After(queueDeadline) {
			t.Fatal("second command was not queued behind the first command")
		}
		runtime.Gosched()
	}

	select {
	case result := <-firstDone:
		if result.err == nil || result.err.Error() != "命令执行超时" {
			t.Fatalf("first ExecuteAT() error = %v, want 命令执行超时", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("first ExecuteAT() did not time out")
	}

	m.rxChan <- rxMsg{Data: "OK"}
	select {
	case result := <-secondDone:
		if result.err == nil {
			t.Fatalf("second ExecuteAT() completed from the first command's late physical response: %q", result.response)
		}
	case <-time.After(time.Second):
		t.Fatal("second ExecuteAT() did not fail closed after response desynchronization")
	}
	select {
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("command worker did not stop")
	}
	if got := port.writes.Load(); got != 1 {
		t.Fatalf("serial writes after response desynchronization = %d, want only the first command", got)
	}
}

func TestManagerExecuteATAssignsMonotonicRequestIDs(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-at",
		DeviceBackend: "at",
		ATPort:        "/dev/ttyUSB6",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	m.running = true
	m.healthy = true

	execute := func(cmd string) commandRequest {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			_, executeErr := m.ExecuteAT(cmd, time.Second)
			done <- executeErr
		}()
		req := <-m.cmdChan
		req.respChan <- "OK"
		select {
		case executeErr := <-done:
			if executeErr != nil {
				t.Fatalf("ExecuteAT(%q) error = %v", cmd, executeErr)
			}
		case <-time.After(time.Second):
			t.Fatalf("ExecuteAT(%q) did not finish", cmd)
		}
		return req
	}

	firstRequest := execute("AT+FIRST")
	secondRequest := execute("AT+SECOND")
	if firstRequest.requestID == 0 {
		t.Fatal("first request ID = 0, want a non-zero generation")
	}
	if secondRequest.requestID <= firstRequest.requestID {
		t.Fatalf("request IDs are not monotonic: first=%d second=%d", firstRequest.requestID, secondRequest.requestID)
	}
}

func TestManagerSendSMSAssignsRequestIDToInteractiveCommand(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-at",
		DeviceBackend: "at",
		ATPort:        "/dev/ttyUSB6",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	m.running = true
	m.healthy = true

	done := make(chan error, 1)
	go func() {
		done <- m.SendSMS("1234", "synthetic")
	}()

	setupRequest := <-m.cmdChanHigh
	setupRequest.respChan <- "OK"
	interactiveRequest := <-m.cmdChanHigh
	interactiveRequest.respChan <- "+CMGS: 1\r\nOK"
	select {
	case sendErr := <-done:
		if sendErr != nil {
			t.Fatalf("SendSMS() error = %v", sendErr)
		}
	case <-time.After(time.Second):
		t.Fatal("SendSMS() did not finish")
	}
	if interactiveRequest.requestID == 0 {
		t.Fatal("interactive SMS request ID = 0, want a non-zero generation")
	}
	if interactiveRequest.requestID <= setupRequest.requestID {
		t.Fatalf("interactive SMS request ID=%d, want greater than setup request ID=%d", interactiveRequest.requestID, setupRequest.requestID)
	}
}

func TestManagerHealthStateConcurrentFatalTransition(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-at",
		DeviceBackend: "at",
		ATPort:        "/dev/ttyUSB6",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	m.running = true
	m.healthy = true

	started := make(chan struct{})
	stopReads := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		close(started)
		for {
			select {
			case <-stopReads:
				return
			default:
				_ = m.IsHealthy()
				_ = m.CanExecuteAT()
			}
		}
	}()
	<-started

	m.handleFatalSerialRuntimeErr(errors.New("input/output error"), "read", "AT+PING")
	close(stopReads)
	select {
	case <-readerDone:
	case <-time.After(time.Second):
		t.Fatal("health-state reader did not stop")
	}

	if m.IsHealthy() {
		t.Fatal("IsHealthy() = true after fatal transition, want false")
	}
	if m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = true after fatal transition, want false")
	}
}
