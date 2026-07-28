package vowifihost

import (
	"context"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost"
)

type runtimeAttemptControlAdapter struct{}

func (runtimeAttemptControlAdapter) Context() context.Context                     { return context.Background() }
func (runtimeAttemptControlAdapter) IsSwitching(string) bool                      { return false }
func (runtimeAttemptControlAdapter) WorkerExists(string) bool                     { return true }
func (runtimeAttemptControlAdapter) WaitQMICoreReady(string, time.Duration) error { return nil }
func (runtimeAttemptControlAdapter) WaitWorkerReady(string, time.Duration) error  { return nil }
func (runtimeAttemptControlAdapter) PrepareStart(string, string, string) (PreparedStart, error) {
	return PreparedStart{}, nil
}
func (runtimeAttemptControlAdapter) BeforeStart(string, runtimehost.Modem, *runtimehost.ProxyConfig) func(context.Context, runtimehost.SessionConfig) error {
	return nil
}
func (runtimeAttemptControlAdapter) HandleStartupError(StartupErrorRequest) error { return nil }
func (runtimeAttemptControlAdapter) MarkRuntimeStarted(RuntimeStartedRequest)     {}
func (runtimeAttemptControlAdapter) RestoreSMSMode(string)                        {}
func (runtimeAttemptControlAdapter) RestoreRadioAfterVoWiFi(string) error         { return nil }

func TestDisableInvalidatesRuntimeAttemptExactlyOnce(t *testing.T) {
	manager := NewManager()
	manager.ConfigureAdapter(runtimeAttemptControlAdapter{})
	deviceID := "dev-disable-once"
	before := manager.CurrentEpoch(deviceID)

	if err := manager.Disable(context.Background(), deviceID, "test", false); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	if got := manager.CurrentEpoch(deviceID); got != before+1 {
		t.Fatalf("runtime epoch after Disable() = %d, want exactly %d", got, before+1)
	}
}

func TestRestartInvalidatesRuntimeAttemptExactlyOnce(t *testing.T) {
	manager := NewManager()
	manager.ConfigureAdapter(runtimeAttemptControlAdapter{})
	deviceID := "dev-restart-once"
	before := manager.CurrentEpoch(deviceID)

	if err := manager.Restart(context.Background(), deviceID); err == nil {
		t.Fatal("Restart() error = nil with synthetic incomplete start")
	}
	if got := manager.CurrentEpoch(deviceID); got != before+1 {
		t.Fatalf("runtime epoch after Restart() = %d, want exactly %d", got, before+1)
	}
}

func TestRuntimeAttemptStoreOwnsLifecycleAdmission(t *testing.T) {
	manager := NewManager()
	deviceID := "dev-attempt-owner"
	var admitted LifecycleCommand
	manager.SetLifecycleRunForTest(func(_ context.Context, cmd LifecycleCommand) error {
		admitted = cmd
		return nil
	})

	if err := manager.Enable(context.Background(), deviceID); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}
	if admitted.Generation == 0 {
		t.Fatal("lifecycle command has no RuntimeAttempt generation")
	}
	if got := manager.RuntimeStore().currentLifecycleGeneration(deviceID); got != admitted.Generation {
		t.Fatalf("RuntimeAttempt generation = %d, want admitted %d", got, admitted.Generation)
	}
}

func TestRuntimeAttemptPreemptionCancelsAndJoinsBeforeRestart(t *testing.T) {
	manager := NewManager()
	deviceID := "dev-preempt-join"
	enableStarted := make(chan struct{})
	events := make(chan string, 2)
	done := make(chan error, 2)
	manager.SetLifecycleRunForTest(func(ctx context.Context, cmd LifecycleCommand) error {
		switch cmd.Kind {
		case LifecycleCommandEnable:
			close(enableStarted)
			<-ctx.Done()
			events <- "enable_exit"
		case LifecycleCommandRestart:
			events <- "restart_start"
		}
		return nil
	})

	go func() { done <- manager.Enable(context.Background(), deviceID) }()
	<-enableStarted
	go func() { done <- manager.Restart(context.Background(), deviceID) }()

	if first := <-events; first != "enable_exit" {
		t.Fatalf("first lifecycle event = %q, want enable_exit", first)
	}
	if second := <-events; second != "restart_start" {
		t.Fatalf("second lifecycle event = %q, want restart_start", second)
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("lifecycle command error = %v", err)
		}
	}
}

func TestRecoverDoesNotInvalidateRuntimeEpochDuringOwnedCleanup(t *testing.T) {
	manager := NewManager()
	manager.ConfigureAdapter(runtimeAttemptControlAdapter{})
	deviceID := "dev-recover-owned-cleanup"
	before := manager.CurrentEpoch(deviceID)

	if err := manager.Recover(context.Background(), LifecycleRecoverRequest{DeviceID: deviceID, Reason: "test"}); err == nil {
		t.Fatal("Recover() error = nil with synthetic incomplete start")
	}
	if got := manager.CurrentEpoch(deviceID); got != before {
		t.Fatalf("runtime epoch after Recover() = %d, want unchanged %d", got, before)
	}
}
