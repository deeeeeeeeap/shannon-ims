package vowifihost

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost"
	"github.com/1239t/vowifi-go/runtimehost/carrier"
)

func TestManagerDesiredRecoverableIsFalseWhenRuntimeActiveOrStarting(t *testing.T) {
	manager := NewManager()
	manager.RuntimeStore().SetInstance("active", &runtimehost.Instance{})
	manager.RuntimeStore().BeginStart("starting")

	if manager.DesiredRecoverable("active") {
		t.Fatal("DesiredRecoverable() = true for active runtime, want false")
	}
	if manager.DesiredRecoverable("starting") {
		t.Fatal("DesiredRecoverable() = true for starting runtime, want false")
	}
	if !manager.DesiredRecoverable("idle") {
		t.Fatal("DesiredRecoverable() = false for idle device, want true")
	}
}

func TestManagerScheduleDesiredRecoverOwnsFailureBackoff(t *testing.T) {
	manager := NewManager()
	deviceID := "dev-owned-result"
	now := time.Now()
	run := make(chan struct{})
	manager.SetLifecycleRunForTest(func(context.Context, LifecycleCommand) error {
		close(run)
		return errors.New("synthetic recover failure")
	})

	if !manager.ScheduleDesiredRecover(context.Background(), DesiredRecoverRequest{
		DeviceID: deviceID,
		Now:      now,
	}) {
		t.Fatal("ScheduleDesiredRecover() = false, want true")
	}
	<-run

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		state, ok := manager.DesiredRecoverState(deviceID)
		if ok && !state.InFlight && state.Attempt == 1 && state.Delay == 30*time.Second {
			return
		}
		runtime.Gosched()
	}
	state, _ := manager.DesiredRecoverState(deviceID)
	t.Fatalf("desired recover state = %+v, want owned failure backoff", state)
}

func TestManagerScheduleDesiredRecoverRunsRecoverAndOwnsSuccess(t *testing.T) {
	manager := NewManager()
	commands := make(chan LifecycleCommand, 1)
	release := make(chan struct{})
	manager.SetLifecycleRunForTest(func(ctx context.Context, cmd LifecycleCommand) error {
		commands <- cmd
		<-release
		return nil
	})

	if !manager.ScheduleDesiredRecover(context.Background(), DesiredRecoverRequest{
		DeviceID: "dev-1",
		Reason:   "desired_reconcile",
		Now:      time.Now(),
	}) {
		t.Fatal("ScheduleDesiredRecover() = false, want true")
	}

	select {
	case cmd := <-commands:
		if cmd.Kind != LifecycleCommandRecover {
			t.Fatalf("command kind = %s, want recover", cmd.Kind.String())
		}
		if cmd.DeviceID != "dev-1" {
			t.Fatalf("command deviceID = %q, want dev-1", cmd.DeviceID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for recover command")
	}
	if state, ok := manager.DesiredRecoverState("dev-1"); !ok || !state.InFlight {
		t.Fatalf("desired recover state = %+v, %v, want in-flight", state, ok)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for manager.HasDesiredRecoverState("dev-1") && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if manager.HasDesiredRecoverState("dev-1") {
		t.Fatal("successful recover state was not cleared by host owner")
	}
}

func TestManagerScheduleDesiredRecoverSkipsRuntimeActivity(t *testing.T) {
	manager := NewManager()
	manager.RuntimeStore().SetInstance("dev-1", &runtimehost.Instance{})
	manager.SetLifecycleRunForTest(func(ctx context.Context, cmd LifecycleCommand) error {
		t.Fatalf("recover should not run for active runtime: %+v", cmd)
		return nil
	})

	if manager.ScheduleDesiredRecover(context.Background(), DesiredRecoverRequest{
		DeviceID: "dev-1",
		Now:      time.Now(),
	}) {
		t.Fatal("ScheduleDesiredRecover() = true for active runtime, want false")
	}
}

func TestManagerScheduleDesiredRecoverOwnsPolicyBlockedResult(t *testing.T) {
	manager := NewManager()
	run := make(chan struct{})
	manager.SetLifecycleRunForTest(func(context.Context, LifecycleCommand) error {
		close(run)
		return carrier.NewVoWiFiBlockedMCCError("001")
	})
	if !manager.ScheduleDesiredRecover(context.Background(), DesiredRecoverRequest{DeviceID: "dev-policy"}) {
		t.Fatal("ScheduleDesiredRecover() = false, want true")
	}
	<-run
	deadline := time.Now().Add(time.Second)
	for manager.HasDesiredRecoverState("dev-policy") && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if manager.HasDesiredRecoverState("dev-policy") {
		t.Fatal("policy-blocked result retained desired recover state")
	}
}

func TestDesiredRecoverLateResultCannotRecreateForgottenState(t *testing.T) {
	store := NewRuntimeStore()
	deviceID := "dev-stale-recover-result"
	generation, accepted := store.beginDesiredRecover(deviceID, time.Now())
	if !accepted {
		t.Fatal("beginDesiredRecover() = false, want true")
	}
	store.forgetDesiredRecover(deviceID)
	if _, current := store.finishDesiredRecover(deviceID, generation, time.Now(), desiredRecoverFailed); current {
		t.Fatal("late desired recover result was accepted after forget")
	}
	if _, ok := store.desiredRecoverState(deviceID); ok {
		t.Fatal("late desired recover result recreated forgotten state")
	}
}

func TestForgottenDesiredRecoverCannotEnterLifecycleRun(t *testing.T) {
	manager := NewManager()
	deviceID := "dev-forgotten-before-run"
	recoverGeneration, accepted := manager.RuntimeStore().beginDesiredRecover(deviceID, time.Now())
	if !accepted {
		t.Fatal("beginDesiredRecover() = false, want true")
	}
	lifecycleGeneration, accepted := manager.RuntimeStore().admitLifecycle(deviceID, LifecycleCommandRecover)
	if !accepted {
		t.Fatal("admitLifecycle() = false, want true")
	}
	manager.ForgetDesiredRecover(deviceID)
	ran := false
	manager.SetLifecycleRunForTest(func(context.Context, LifecycleCommand) error {
		ran = true
		return nil
	})

	err := manager.runAdmittedLifecycleCommand(context.Background(), LifecycleCommand{
		DeviceID:                 deviceID,
		Kind:                     LifecycleCommandRecover,
		Generation:               lifecycleGeneration,
		desiredRecoverGeneration: recoverGeneration,
	})
	if err != nil {
		t.Fatalf("runAdmittedLifecycleCommand() error = %v", err)
	}
	if ran {
		t.Fatal("forgotten desired recover entered lifecycle run")
	}
}

func TestForgetDesiredRecoverCancelsCurrentLifecycleRun(t *testing.T) {
	manager := NewManager()
	deviceID := "dev-cancel-recover"
	started := make(chan struct{})
	canceled := make(chan struct{})
	manager.SetLifecycleRunForTest(func(ctx context.Context, _ LifecycleCommand) error {
		close(started)
		<-ctx.Done()
		close(canceled)
		return ctx.Err()
	})
	if !manager.ScheduleDesiredRecover(context.Background(), DesiredRecoverRequest{DeviceID: deviceID}) {
		t.Fatal("ScheduleDesiredRecover() = false, want true")
	}
	<-started
	manager.ForgetDesiredRecover(deviceID)
	<-canceled
	if manager.HasDesiredRecoverState(deviceID) {
		t.Fatal("forgotten desired recover state remained visible")
	}
}
