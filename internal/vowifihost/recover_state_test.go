package vowifihost

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

func TestManagerDesiredRecoverBackoffLifecycle(t *testing.T) {
	manager := NewManager()
	deviceID := "dev-recover"
	now := time.Now()
	runs := make(chan struct{}, 2)
	results := make(chan error, 2)
	manager.SetLifecycleRunForTest(func(ctx context.Context, _ LifecycleCommand) error {
		runs <- struct{}{}
		select {
		case err := <-results:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	if !manager.ScheduleDesiredRecover(context.Background(), DesiredRecoverRequest{DeviceID: deviceID, Now: now}) {
		t.Fatal("first ScheduleDesiredRecover() = false, want true")
	}
	<-runs
	if manager.ScheduleDesiredRecover(context.Background(), DesiredRecoverRequest{DeviceID: deviceID, Now: now}) {
		t.Fatal("ScheduleDesiredRecover() while in-flight = true, want false")
	}
	results <- errors.New("synthetic failure")

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		snapshot, ok := manager.DesiredRecoverState(deviceID)
		if ok && !snapshot.InFlight && snapshot.Attempt == 1 && snapshot.Delay == 30*time.Second {
			break
		}
		runtime.Gosched()
	}
	snapshot, ok := manager.DesiredRecoverState(deviceID)
	if !ok || snapshot.InFlight || snapshot.Attempt != 1 || snapshot.Delay != 30*time.Second {
		t.Fatalf("failed recover state = %+v, %v", snapshot, ok)
	}
	if manager.ScheduleDesiredRecover(context.Background(), DesiredRecoverRequest{DeviceID: deviceID, Now: now.Add(29 * time.Second)}) {
		t.Fatal("ScheduleDesiredRecover() before nextAt = true, want false")
	}
	if !manager.ScheduleDesiredRecover(context.Background(), DesiredRecoverRequest{DeviceID: deviceID, Now: now.Add(31 * time.Second)}) {
		t.Fatal("ScheduleDesiredRecover() after nextAt = false, want true")
	}
	<-runs

	manager.ForgetDesiredRecover(deviceID)
	if manager.HasDesiredRecoverState(deviceID) {
		t.Fatal("recover state should be forgotten")
	}
}
