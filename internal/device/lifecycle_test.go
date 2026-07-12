package device

import (
	"strings"
	"testing"
	"time"
)

func TestLifecycleCoordinatorRecoveryWindowBlocksEviction(t *testing.T) {
	lc := newLifecycleCoordinator()
	now := time.Date(2026, 5, 4, 23, 0, 0, 0, time.UTC)

	lc.BeginRecoveryAt("dev1", LifecyclePhaseRecovering, "qmi_reset", now, 3*time.Minute)

	canEvict, reason := lc.CanEvict("dev1", now.Add(2*time.Minute))
	if canEvict {
		t.Fatalf("CanEvict() = true, want false")
	}
	if !strings.Contains(reason, "recovering") {
		t.Fatalf("reason=%q want contains recovering", reason)
	}
}

func TestLifecycleCoordinatorAllowsEvictionAfterDeadline(t *testing.T) {
	lc := newLifecycleCoordinator()
	now := time.Date(2026, 5, 4, 23, 0, 0, 0, time.UTC)

	lc.BeginRecoveryAt("dev1", LifecyclePhaseRecovering, "qmi_reset", now, time.Minute)

	canEvict, reason := lc.CanEvict("dev1", now.Add(time.Minute+time.Second))
	if !canEvict {
		t.Fatalf("CanEvict() = false, want true reason=%q", reason)
	}
}

func TestLifecycleCoordinatorFinishOnlineClearsRecovery(t *testing.T) {
	lc := newLifecycleCoordinator()
	now := time.Date(2026, 5, 4, 23, 0, 0, 0, time.UTC)
	lc.BeginRecoveryAt("dev1", LifecyclePhaseQMIStarting, "worker_start", now, 3*time.Minute)

	lc.FinishOnline("dev1")

	snap := lc.GetSnapshot("dev1")
	if snap.Phase != LifecyclePhaseOnline {
		t.Fatalf("phase=%q want %q", snap.Phase, LifecyclePhaseOnline)
	}
	if snap.Recovering {
		t.Fatal("Recovering=true, want false")
	}
	if !snap.Deadline.IsZero() {
		t.Fatalf("Deadline=%v want zero", snap.Deadline)
	}
}

func TestLifecycleCoordinatorMissingDeviceDefaultsOffline(t *testing.T) {
	lc := newLifecycleCoordinator()

	snap := lc.GetSnapshot("missing")
	if snap.Phase != LifecyclePhaseOffline {
		t.Fatalf("phase=%q want %q", snap.Phase, LifecyclePhaseOffline)
	}
	if snap.Recovering {
		t.Fatal("Recovering=true, want false")
	}
}
