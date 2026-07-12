package vowifihost

import (
	"context"
	"testing"
)

func TestManagerOwnsLifecycleController(t *testing.T) {
	manager := NewManager()
	var got LifecycleCommand
	manager.ConfigureLifecycle(LifecycleControllerOptions{
		Run: func(ctx context.Context, cmd LifecycleCommand) error {
			got = cmd
			return nil
		},
	})

	if err := manager.SubmitLifecycle(context.Background(), LifecycleCommand{
		DeviceID: "dev-1",
		Kind:     LifecycleCommandRestart,
		Reason:   "test",
	}); err != nil {
		t.Fatalf("SubmitLifecycle() error = %v", err)
	}

	if got.DeviceID != "dev-1" || got.Kind != LifecycleCommandRestart || got.Generation == 0 {
		t.Fatalf("submitted command = %+v, want device/kind with non-zero generation", got)
	}
	if current := manager.CurrentLifecycleGeneration("dev-1"); current != got.Generation {
		t.Fatalf("current generation = %d, want %d", current, got.Generation)
	}
}

func TestManagerLifecycleRunForTestOverridesConfiguredRun(t *testing.T) {
	manager := NewManager()
	var configuredRan bool
	manager.ConfigureLifecycle(LifecycleControllerOptions{
		Run: func(ctx context.Context, cmd LifecycleCommand) error {
			configuredRan = true
			return nil
		},
	})

	var testRan bool
	manager.SetLifecycleRunForTest(func(ctx context.Context, cmd LifecycleCommand) error {
		testRan = true
		return nil
	})

	if err := manager.SubmitLifecycle(context.Background(), LifecycleCommand{
		DeviceID: "dev-test",
		Kind:     LifecycleCommandEnable,
	}); err != nil {
		t.Fatalf("SubmitLifecycle() error = %v", err)
	}
	if !testRan {
		t.Fatal("test lifecycle run hook was not called")
	}
	if configuredRan {
		t.Fatal("configured lifecycle run should be bypassed by test hook")
	}
}

func TestManagerLifecycleConvenienceMethodsSubmitExpectedCommands(t *testing.T) {
	manager := NewManager()
	var got []LifecycleCommand
	manager.SetLifecycleRunForTest(func(ctx context.Context, cmd LifecycleCommand) error {
		got = append(got, cmd)
		return nil
	})

	if err := manager.Enable(context.Background(), "dev-1"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}
	if err := manager.Disable(context.Background(), "dev-1", "disable", false); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	if err := manager.Restart(context.Background(), "dev-1"); err != nil {
		t.Fatalf("Restart() error = %v", err)
	}
	currentGeneration := manager.CurrentLifecycleGeneration("dev-1")
	if err := manager.Recover(context.Background(), LifecycleRecoverRequest{
		DeviceID:     "dev-1",
		Reason:       "apdu_busy",
		OverrideEPDG: "epdg.example",
		Generation:   currentGeneration,
	}); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if err := manager.SwitchBegin(context.Background(), "dev-1"); err != nil {
		t.Fatalf("SwitchBegin() error = %v", err)
	}
	if err := manager.SwitchEnd(context.Background(), "dev-1", true); err != nil {
		t.Fatalf("SwitchEnd() error = %v", err)
	}

	wantKinds := []LifecycleCommandKind{
		LifecycleCommandEnable,
		LifecycleCommandDisable,
		LifecycleCommandRestart,
		LifecycleCommandRecover,
		LifecycleCommandSwitchBegin,
		LifecycleCommandSwitchEnd,
	}
	if len(got) != len(wantKinds) {
		t.Fatalf("submitted %d commands, want %d", len(got), len(wantKinds))
	}
	for i, want := range wantKinds {
		if got[i].Kind != want {
			t.Fatalf("command[%d].Kind = %s, want %s", i, got[i].Kind.String(), want.String())
		}
	}
	if got[3].Reason != "apdu_busy" || got[3].OverrideEPDG != "epdg.example" || got[3].Generation != currentGeneration {
		t.Fatalf("recover command = %+v, want reason/override/generation preserved", got[3])
	}
	if !got[5].RestoreRadio {
		t.Fatalf("switch end command = %+v, want RestoreRadio", got[5])
	}
}

func TestManagerRestartInvalidatesStaleStartupBeforeLifecycleRun(t *testing.T) {
	manager := NewManager()
	deviceID := "dev-restart-stale-start"
	claim := manager.BeginStart(deviceID)
	if !claim.Accepted {
		t.Fatalf("BeginStart() = %+v, want accepted", claim)
	}
	before := manager.CurrentEpoch(deviceID)
	var epochDuringRun uint64
	var startingDuringRun bool
	manager.SetLifecycleRunForTest(func(ctx context.Context, cmd LifecycleCommand) error {
		if cmd.Kind != LifecycleCommandRestart {
			t.Fatalf("kind = %s, want restart", cmd.Kind.String())
		}
		epochDuringRun = manager.CurrentEpoch(deviceID)
		startingDuringRun = manager.Starting(deviceID)
		return nil
	})

	if err := manager.Restart(context.Background(), deviceID); err != nil {
		t.Fatalf("Restart() error = %v", err)
	}

	if epochDuringRun <= before {
		t.Fatalf("epoch during restart = %d, want > %d", epochDuringRun, before)
	}
	if startingDuringRun {
		t.Fatal("runtime starting flag was still true during restart lifecycle run")
	}
}
