package vowifihost

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestLifecycleControllerEnableKeepsRunContextAliveAfterSubmitReturns(t *testing.T) {
	c := NewLifecycleController()

	var enableCtx context.Context
	c.TestRun = func(ctx context.Context, cmd LifecycleCommand) error {
		if cmd.Kind != LifecycleCommandEnable {
			t.Fatalf("command kind = %s, want enable", cmd.Kind.String())
		}
		enableCtx = ctx
		return nil
	}

	if err := c.Submit(context.Background(), LifecycleCommand{DeviceID: "dev-1", Kind: LifecycleCommandEnable}); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if enableCtx == nil {
		t.Fatal("enable context was not captured")
	}
	select {
	case <-enableCtx.Done():
		t.Fatalf("enable context was canceled after successful Submit: %v", enableCtx.Err())
	default:
	}
}

func TestLifecycleControllerSerializesCommandsPerDevice(t *testing.T) {
	c := NewLifecycleController()
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	done := make(chan error, 2)
	var mu sync.Mutex
	var order []LifecycleCommandKind

	c.TestRun = func(_ context.Context, cmd LifecycleCommand) error {
		mu.Lock()
		order = append(order, cmd.Kind)
		mu.Unlock()
		if cmd.Kind == LifecycleCommandEnable {
			close(firstStarted)
			<-releaseFirst
		}
		return nil
	}

	go func() {
		done <- c.Submit(context.Background(), LifecycleCommand{DeviceID: "dev-1", Kind: LifecycleCommandEnable})
	}()
	<-firstStarted
	go func() {
		done <- c.Submit(context.Background(), LifecycleCommand{DeviceID: "dev-1", Kind: LifecycleCommandRestart})
	}()
	close(releaseFirst)

	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Submit() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for serialized commands")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != LifecycleCommandEnable || order[1] != LifecycleCommandRestart {
		t.Fatalf("command order = %v, want [enable restart]", order)
	}
}

func TestLifecycleControllerAllowsDifferentDevicesToRunIndependently(t *testing.T) {
	c := NewLifecycleController()
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{})
	done := make(chan error, 2)

	c.TestRun = func(_ context.Context, cmd LifecycleCommand) error {
		if cmd.DeviceID == "dev-a" {
			close(firstStarted)
			<-releaseFirst
		} else {
			close(secondStarted)
		}
		return nil
	}
	go func() {
		done <- c.Submit(context.Background(), LifecycleCommand{DeviceID: "dev-a", Kind: LifecycleCommandEnable})
	}()
	<-firstStarted
	go func() {
		done <- c.Submit(context.Background(), LifecycleCommand{DeviceID: "dev-b", Kind: LifecycleCommandEnable})
	}()

	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("second device did not run independently")
	}
	close(releaseFirst)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("Submit() error = %v", err)
		}
	}
}
