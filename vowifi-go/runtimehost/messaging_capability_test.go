package runtimehost

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

var errSyntheticRuntimeUSSDUnsupported = errors.New("synthetic runtime USSD unsupported")

type blockingUSSDService struct {
	calls           atomic.Int32
	closeCalls      atomic.Int32
	active          atomic.Bool
	closedWhileCall atomic.Bool
	started         chan struct{}
	release         chan struct{}
}

func (*blockingUSSDService) SendSMS(context.Context, string, string, []messaging.SMSPart) (messaging.SendOutcome, error) {
	return messaging.SendOutcome{}, nil
}

func (s *blockingUSSDService) run() (*messaging.USSDResult, error) {
	s.calls.Add(1)
	s.active.Store(true)
	defer s.active.Store(false)
	close(s.started)
	<-s.release
	return nil, errSyntheticRuntimeUSSDUnsupported
}

func (s *blockingUSSDService) SendUSSD(context.Context, string) (*messaging.USSDResult, error) {
	return s.run()
}

func (s *blockingUSSDService) ContinueUSSD(context.Context, string, string) (*messaging.USSDResult, error) {
	return s.run()
}

func (s *blockingUSSDService) CancelUSSD(context.Context, string) error {
	_, err := s.run()
	return err
}

func (s *blockingUSSDService) Close(context.Context) error {
	s.closeCalls.Add(1)
	if s.active.Load() {
		s.closedWhileCall.Store(true)
	}
	return nil
}

func waitForUSSDStopAdmission(t *testing.T, instance *Instance, stopDone <-chan error) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		instance.mu.Lock()
		admitted := instance.stopped && instance.stopCleanupDone != nil
		instance.mu.Unlock()
		if admitted {
			return
		}
		select {
		case err := <-stopDone:
			t.Fatalf("Stop() returned before publishing cleanup state: %v", err)
		case <-deadline.C:
			t.Fatal("Stop() did not publish cleanup state")
		default:
			runtime.Gosched()
		}
	}
}

func TestInstanceStopJoinsEveryInFlightUSSDOperation(t *testing.T) {
	operations := []struct {
		name string
		call func(*Instance) error
	}{
		{
			name: "send",
			call: func(instance *Instance) error {
				_, err := instance.SendUSSD(context.Background(), "synthetic")
				return err
			},
		},
		{
			name: "continue",
			call: func(instance *Instance) error {
				_, err := instance.ContinueUSSD(context.Background(), "synthetic-session", "synthetic")
				return err
			},
		},
		{
			name: "cancel",
			call: func(instance *Instance) error {
				return instance.CancelUSSD(context.Background(), "synthetic-session")
			},
		},
	}

	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			service := &blockingUSSDService{
				started: make(chan struct{}),
				release: make(chan struct{}),
			}
			cleanupGate := make(chan struct{})
			instance := &Instance{
				svc:       service,
				state:     State{IMSReady: true},
				watchDone: cleanupGate,
			}

			callDone := make(chan error, 1)
			go func() {
				callDone <- operation.call(instance)
			}()
			select {
			case <-service.started:
			case <-time.After(time.Second):
				t.Fatal("USSD operation did not enter the Adapter")
			}

			instance.mu.Lock()
			users := instance.serviceUsers
			instance.mu.Unlock()
			if users != 1 {
				t.Fatalf("service users during USSD operation=%d, want 1", users)
			}

			stopDone := make(chan error, 1)
			go func() {
				stopDone <- instance.Stop(context.Background())
			}()
			waitForUSSDStopAdmission(t, instance, stopDone)
			select {
			case cleanupGate <- struct{}{}:
			case err := <-stopDone:
				t.Fatalf("Stop() returned before cleanup entered: %v", err)
			case <-time.After(time.Second):
				t.Fatal("Stop() cleanup did not enter its deterministic gate")
			}
			select {
			case err := <-stopDone:
				t.Fatalf("Stop() returned while USSD was in flight: %v", err)
			default:
			}
			if service.closeCalls.Load() != 0 || service.closedWhileCall.Load() {
				t.Fatal("messaging Adapter closed while USSD was in flight")
			}

			close(service.release)
			select {
			case err := <-callDone:
				if !errors.Is(err, errSyntheticRuntimeUSSDUnsupported) {
					t.Fatalf("USSD error=%v, want unsupported error preserved", err)
				}
			case <-time.After(time.Second):
				t.Fatal("USSD operation did not finish")
			}
			select {
			case err := <-stopDone:
				if err != nil {
					t.Fatalf("Stop() error=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Stop() did not finish after USSD")
			}
			if service.closeCalls.Load() != 1 || service.closedWhileCall.Load() {
				t.Fatalf(
					"messaging Adapter close lifecycle invalid: close_calls=%d closed_while_call=%v",
					service.closeCalls.Load(),
					service.closedWhileCall.Load(),
				)
			}
		})
	}
}
