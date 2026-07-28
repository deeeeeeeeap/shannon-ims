package device

import (
	"context"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/pkg/smscodec"
	"github.com/1239t/vowifi-go/runtimehost"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

type poolSMSMessagingAdapter struct {
	sendCalls       atomic.Int32
	closeCalls      atomic.Int32
	sending         atomic.Bool
	closedWhileSend atomic.Bool
	sendStarted     chan struct{}
	releaseSend     chan struct{}
}

type poolSMSBarrierSMSCBackend struct {
	workerStatusBackendStub
	entered chan struct{}
	release chan struct{}
}

func (b *poolSMSBarrierSMSCBackend) GetSMSC(ctx context.Context) (string, error) {
	close(b.entered)
	select {
	case <-b.release:
		return "+55500", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (a *poolSMSMessagingAdapter) SendSMS(context.Context, string, string, []messaging.SMSPart) (messaging.SendOutcome, error) {
	a.sendCalls.Add(1)
	a.sending.Store(true)
	defer a.sending.Store(false)
	if a.sendStarted != nil {
		close(a.sendStarted)
	}
	if a.releaseSend != nil {
		<-a.releaseSend
	}
	return messaging.SendOutcome{MessageID: "synthetic"}, nil
}

func (*poolSMSMessagingAdapter) SendUSSD(context.Context, string) (*messaging.USSDResult, error) {
	return nil, nil
}

func (*poolSMSMessagingAdapter) ContinueUSSD(context.Context, string, string) (*messaging.USSDResult, error) {
	return nil, nil
}

func (*poolSMSMessagingAdapter) CancelUSSD(context.Context, string) error { return nil }

func (a *poolSMSMessagingAdapter) Close(context.Context) error {
	a.closeCalls.Add(1)
	if a.sending.Load() {
		a.closedWhileSend.Store(true)
	}
	return nil
}

func runtimeInstanceFieldForPoolSMSTest(t *testing.T, inst *runtimehost.Instance, name string) reflect.Value {
	t.Helper()
	field := reflect.ValueOf(inst).Elem().FieldByName(name)
	if !field.IsValid() {
		t.Fatalf("runtime instance field %q not found", name)
	}
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
}

func setRuntimeInstanceFieldForPoolSMSTest(t *testing.T, inst *runtimehost.Instance, name string, value any) {
	t.Helper()
	runtimeInstanceFieldForPoolSMSTest(t, inst, name).Set(reflect.ValueOf(value))
}

func runtimeInstanceStopStateForPoolSMSTest(t *testing.T, inst *runtimehost.Instance) (bool, bool) {
	t.Helper()
	mutexValue := runtimeInstanceFieldForPoolSMSTest(t, inst, "mu")
	mutex, ok := mutexValue.Addr().Interface().(*sync.Mutex)
	if !ok {
		t.Fatal("runtime instance mutex has unexpected type")
	}
	mutex.Lock()
	defer mutex.Unlock()
	stopped := runtimeInstanceFieldForPoolSMSTest(t, inst, "stopped").Bool()
	cleanupInstalled := !runtimeInstanceFieldForPoolSMSTest(t, inst, "stopCleanupDone").IsNil()
	return stopped, cleanupInstalled
}

func newPoolSMSCallChain(t *testing.T, state runtimehost.State, adapter messaging.Service) (*Pool, string) {
	t.Helper()
	const deviceID = "sms-seam-device"
	pool := NewPool(&config.Config{})
	pool.workers[deviceID] = &Worker{
		ID: deviceID,
		Backend: &workerSMSCBackendStub{
			workerStatusBackendStub: workerStatusBackendStub{mode: backend.BackendAT},
			seq:                     []smscResult{{value: "+55500"}},
		},
	}
	inst := &runtimehost.Instance{}
	setRuntimeInstanceFieldForPoolSMSTest(t, inst, "state", state)
	setRuntimeInstanceFieldForPoolSMSTest(t, inst, "svc", adapter)
	pool.voWiFiRuntimeStore().SetInstance(deviceID, inst)
	return pool, deviceID
}

func TestPoolSendVoWiFiSMSRejectsBeforeSMSReady(t *testing.T) {
	adapter := &poolSMSMessagingAdapter{}
	pool, deviceID := newPoolSMSCallChain(t, runtimehost.State{SMSReady: false}, adapter)

	_, err := pool.SendVoWiFiSMSWithOptions(
		context.Background(),
		deviceID,
		"55501",
		"synthetic",
		smscodec.SubmitOptions{},
	)
	if err == nil {
		t.Fatal("SendVoWiFiSMSWithOptions() error=nil before SMSReady")
	}
	if got := adapter.sendCalls.Load(); got != 0 {
		t.Fatalf("messaging adapter calls=%d before SMSReady, want 0", got)
	}
}

func TestPoolSendVoWiFiSMSRejectsStoppedOldInstance(t *testing.T) {
	adapter := &poolSMSMessagingAdapter{}
	pool, deviceID := newPoolSMSCallChain(t, runtimehost.State{SMSReady: true}, adapter)
	barrier := &poolSMSBarrierSMSCBackend{
		workerStatusBackendStub: workerStatusBackendStub{mode: backend.BackendAT},
		entered:                 make(chan struct{}),
		release:                 make(chan struct{}),
	}
	pool.workers[deviceID].Backend = barrier
	oldInstance := pool.voWiFiRuntimeStore().Instance(deviceID)

	sendDone := make(chan error, 1)
	go func() {
		_, err := pool.SendVoWiFiSMSWithOptions(
			context.Background(),
			deviceID,
			"55501",
			"synthetic",
			smscodec.SubmitOptions{},
		)
		sendDone <- err
	}()

	select {
	case <-barrier.entered:
	case <-time.After(time.Second):
		t.Fatal("SendVoWiFiSMSWithOptions() did not reach the SMSC barrier")
	}
	if err := oldInstance.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error=%v", err)
	}
	pool.voWiFiRuntimeStore().SetInstance(deviceID, &runtimehost.Instance{})
	close(barrier.release)

	select {
	case err := <-sendDone:
		if err == nil {
			t.Fatal("SendVoWiFiSMSWithOptions() error=nil for stopped old instance")
		}
	case <-time.After(time.Second):
		t.Fatal("SendVoWiFiSMSWithOptions() did not return after the SMSC barrier")
	}
	if got := adapter.sendCalls.Load(); got != 0 {
		t.Fatalf("messaging adapter calls=%d for stopped old instance, want 0", got)
	}
}

func TestPoolSendVoWiFiSMSStopWaitsForInFlightSend(t *testing.T) {
	adapter := &poolSMSMessagingAdapter{
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}
	pool, deviceID := newPoolSMSCallChain(t, runtimehost.State{SMSReady: true}, adapter)
	inst := pool.voWiFiRuntimeStore().Instance(deviceID)

	sendDone := make(chan error, 1)
	go func() {
		_, err := pool.SendVoWiFiSMSWithOptions(
			context.Background(),
			deviceID,
			"55501",
			"synthetic",
			smscodec.SubmitOptions{},
		)
		sendDone <- err
	}()
	select {
	case <-adapter.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("SendVoWiFiSMSWithOptions() did not enter the messaging adapter")
	}
	if got := runtimeInstanceFieldForPoolSMSTest(t, inst, "serviceUsers").Int(); got != 1 {
		t.Fatalf("runtime service users=%d during Pool send, want 1", got)
	}
	cleanupGate := make(chan struct{})
	setRuntimeInstanceFieldForPoolSMSTest(t, inst, "watchDone", cleanupGate)

	stopDone := make(chan error, 1)
	go func() {
		stopDone <- inst.Stop(context.Background())
	}()
	stoppedDeadline := time.NewTimer(time.Second)
	defer stoppedDeadline.Stop()
	for {
		stopped, cleanupInstalled := runtimeInstanceStopStateForPoolSMSTest(t, inst)
		if stopped && cleanupInstalled {
			break
		}
		select {
		case err := <-stopDone:
			t.Fatalf("Stop() returned before the instance exposed stopped state: %v", err)
		case <-stoppedDeadline.C:
			t.Fatal("Stop() did not mark the instance stopped")
		default:
			runtime.Gosched()
		}
	}
	select {
	case cleanupGate <- struct{}{}:
	case err := <-stopDone:
		t.Fatalf("Stop() returned before cleanup entered: %v", err)
	case <-time.After(time.Second):
		t.Fatal("Stop() cleanup did not enter its deterministic gate")
	}
	select {
	case err := <-stopDone:
		t.Fatalf("Stop() returned while Pool SendVoWiFiSMSWithOptions was in flight: %v", err)
	default:
	}
	if adapter.closeCalls.Load() != 0 || adapter.closedWhileSend.Load() {
		t.Fatalf(
			"messaging adapter closed during send: close_calls=%d closed_while_send=%v",
			adapter.closeCalls.Load(),
			adapter.closedWhileSend.Load(),
		)
	}

	close(adapter.releaseSend)
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("SendVoWiFiSMSWithOptions() error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SendVoWiFiSMSWithOptions() did not finish")
	}
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop() error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop() did not finish after messaging send")
	}
	if adapter.closeCalls.Load() != 1 || adapter.closedWhileSend.Load() {
		t.Fatalf(
			"messaging adapter close lifecycle invalid: close_calls=%d closed_while_send=%v",
			adapter.closeCalls.Load(),
			adapter.closedWhileSend.Load(),
		)
	}
}

func TestPoolSendVoWiFiSMSSuccessDispatchesExactlyOnce(t *testing.T) {
	adapter := &poolSMSMessagingAdapter{}
	pool, deviceID := newPoolSMSCallChain(t, runtimehost.State{SMSReady: true}, adapter)

	outcome, err := pool.SendVoWiFiSMSWithOptions(
		context.Background(),
		deviceID,
		"55501",
		"synthetic",
		smscodec.SubmitOptions{},
	)
	if err != nil {
		t.Fatalf("SendVoWiFiSMSWithOptions() error=%v", err)
	}
	if outcome.MessageID != "synthetic" {
		t.Fatalf("SendVoWiFiSMSWithOptions() message ID=%q, want synthetic", outcome.MessageID)
	}
	if got := adapter.sendCalls.Load(); got != 1 {
		t.Fatalf("messaging adapter calls=%d for successful send, want 1", got)
	}
}
