package device

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/1239t/vowifi-go/runtimehost"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

var errSyntheticUSSDUnsupported = errors.New("synthetic USSD unsupported")

type poolUSSDMessagingAdapter struct {
	calls atomic.Int32
}

type poolUSSDOperation struct {
	name string
	call func(*Pool, string) error
}

func poolUSSDOperations() []poolUSSDOperation {
	return []poolUSSDOperation{
		{
			name: "send",
			call: func(pool *Pool, deviceID string) error {
				_, err := pool.SendVoWiFiUSSD(context.Background(), deviceID, "synthetic")
				return err
			},
		},
		{
			name: "continue",
			call: func(pool *Pool, deviceID string) error {
				_, err := pool.ContinueVoWiFiUSSD(context.Background(), deviceID, "synthetic-session", "synthetic")
				return err
			},
		},
		{
			name: "cancel",
			call: func(pool *Pool, deviceID string) error {
				return pool.CancelVoWiFiUSSD(context.Background(), deviceID, "synthetic-session")
			},
		},
	}
}

func (*poolUSSDMessagingAdapter) SendSMS(context.Context, string, string, []messaging.SMSPart) (messaging.SendOutcome, error) {
	return messaging.SendOutcome{}, nil
}

func (a *poolUSSDMessagingAdapter) SendUSSD(context.Context, string) (*messaging.USSDResult, error) {
	a.calls.Add(1)
	return nil, errSyntheticUSSDUnsupported
}

func (a *poolUSSDMessagingAdapter) ContinueUSSD(context.Context, string, string) (*messaging.USSDResult, error) {
	a.calls.Add(1)
	return nil, errSyntheticUSSDUnsupported
}

func (a *poolUSSDMessagingAdapter) CancelUSSD(context.Context, string) error {
	a.calls.Add(1)
	return errSyntheticUSSDUnsupported
}

func newPoolUSSDCallChain(t *testing.T, state runtimehost.State, adapter messaging.Service) (*Pool, string) {
	t.Helper()
	const deviceID = "ussd-seam-device"
	pool := NewPool(nil)
	inst := &runtimehost.Instance{}
	setRuntimeInstanceFieldForPoolSMSTest(t, inst, "state", state)
	setRuntimeInstanceFieldForPoolSMSTest(t, inst, "svc", adapter)
	pool.voWiFiRuntimeStore().SetInstance(deviceID, inst)
	return pool, deviceID
}

func TestPoolVoWiFiUSSDRejectsBeforeIMSReady(t *testing.T) {
	for _, operation := range poolUSSDOperations() {
		t.Run(operation.name, func(t *testing.T) {
			adapter := &poolUSSDMessagingAdapter{}
			pool, deviceID := newPoolUSSDCallChain(t, runtimehost.State{
				IMSReady: false,
				SMSReady: true,
			}, adapter)

			if err := operation.call(pool, deviceID); err == nil {
				t.Fatal("USSD call succeeded before IMSReady")
			}
			if got := adapter.calls.Load(); got != 0 {
				t.Fatalf("USSD adapter calls before IMSReady=%d, want 0", got)
			}
		})
	}
}

func TestPoolVoWiFiUSSDRejectsStoppedInstance(t *testing.T) {
	for _, operation := range poolUSSDOperations() {
		t.Run(operation.name, func(t *testing.T) {
			adapter := &poolUSSDMessagingAdapter{}
			pool, deviceID := newPoolUSSDCallChain(t, runtimehost.State{IMSReady: true}, adapter)
			instance := pool.voWiFiRuntimeStore().Instance(deviceID)
			if err := instance.Stop(context.Background()); err != nil {
				t.Fatalf("Stop() error=%v", err)
			}

			if err := operation.call(pool, deviceID); err == nil {
				t.Fatal("USSD call succeeded after Stop")
			}
			if got := adapter.calls.Load(); got != 0 {
				t.Fatalf("USSD adapter calls after Stop=%d, want 0", got)
			}
		})
	}
}

func TestPoolVoWiFiUSSDDispatchesOnceAndPreservesUnsupportedError(t *testing.T) {
	for _, operation := range poolUSSDOperations() {
		t.Run(operation.name, func(t *testing.T) {
			adapter := &poolUSSDMessagingAdapter{}
			pool, deviceID := newPoolUSSDCallChain(t, runtimehost.State{
				IMSReady: true,
				SMSReady: false,
			}, adapter)

			if err := operation.call(pool, deviceID); !errors.Is(err, errSyntheticUSSDUnsupported) {
				t.Fatalf("USSD error=%v, want unsupported error preserved", err)
			}
			if got := adapter.calls.Load(); got != 1 {
				t.Fatalf("USSD adapter calls=%d, want exactly 1", got)
			}
		})
	}
}
