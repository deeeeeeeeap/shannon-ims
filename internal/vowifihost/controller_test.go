package vowifihost

import (
	"context"
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

func TestLifecycleControllerSwitchBeginPreemptsInFlightEnable(t *testing.T) {
	c := NewLifecycleController()

	enableRelease := make(chan struct{})
	started := make(chan LifecycleCommand, 2)
	done := make(chan error, 2)

	c.TestRun = func(ctx context.Context, cmd LifecycleCommand) error {
		started <- cmd
		if cmd.Kind == LifecycleCommandEnable {
			<-enableRelease
		}
		return nil
	}

	go func() {
		done <- c.Submit(context.Background(), LifecycleCommand{DeviceID: "dev-1", Kind: LifecycleCommandEnable})
	}()

	var enableCmd LifecycleCommand
	select {
	case enableCmd = <-started:
		if enableCmd.Kind != LifecycleCommandEnable {
			t.Fatalf("first command = %s, want enable", enableCmd.Kind.String())
		}
	case <-time.After(time.Second):
		t.Fatal("enable command did not start")
	}

	go func() {
		done <- c.Submit(context.Background(), LifecycleCommand{DeviceID: "dev-1", Kind: LifecycleCommandSwitchBegin})
	}()

	var switchCmd LifecycleCommand
	select {
	case switchCmd = <-started:
		if switchCmd.Kind != LifecycleCommandSwitchBegin {
			t.Fatalf("preempting command = %s, want switch_begin", switchCmd.Kind.String())
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("switch_begin did not preempt in-flight enable")
	}

	if switchCmd.Generation <= enableCmd.Generation {
		t.Fatalf("switch_begin generation = %d, want > in-flight enable generation %d", switchCmd.Generation, enableCmd.Generation)
	}

	close(enableRelease)
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("submit returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for submit to finish")
		}
	}
}

func TestLifecycleControllerRestartPreemptsInFlightEnable(t *testing.T) {
	c := NewLifecycleController()

	started := make(chan LifecycleCommand, 2)
	done := make(chan error, 2)

	c.TestRun = func(ctx context.Context, cmd LifecycleCommand) error {
		started <- cmd
		if cmd.Kind == LifecycleCommandEnable {
			<-ctx.Done()
		}
		return nil
	}

	go func() {
		done <- c.Submit(context.Background(), LifecycleCommand{DeviceID: "dev-1", Kind: LifecycleCommandEnable})
	}()

	var enableCmd LifecycleCommand
	select {
	case enableCmd = <-started:
		if enableCmd.Kind != LifecycleCommandEnable {
			t.Fatalf("first command = %s, want enable", enableCmd.Kind.String())
		}
	case <-time.After(time.Second):
		t.Fatal("enable command did not start")
	}

	go func() {
		done <- c.Submit(context.Background(), LifecycleCommand{DeviceID: "dev-1", Kind: LifecycleCommandRestart})
	}()

	var restartCmd LifecycleCommand
	select {
	case restartCmd = <-started:
		if restartCmd.Kind != LifecycleCommandRestart {
			t.Fatalf("preempting command = %s, want restart", restartCmd.Kind.String())
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("restart did not preempt in-flight enable")
	}

	if restartCmd.Generation <= enableCmd.Generation {
		t.Fatalf("restart generation = %d, want > in-flight enable generation %d", restartCmd.Generation, enableCmd.Generation)
	}

	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("submit returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for submit to finish")
		}
	}
}
