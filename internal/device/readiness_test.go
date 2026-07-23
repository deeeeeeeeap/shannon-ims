package device

import (
	"testing"

	"github.com/1239t/vohive/internal/config"
)

func TestPoolReadinessFailsBeforeInitializationCompletes(t *testing.T) {
	pool := NewPool(&config.Config{})
	snapshot := pool.ReadinessSnapshot()

	if snapshot.Ready {
		t.Fatal("Ready=true before initial worker bootstrap completed")
	}
	if snapshot.Initialized {
		t.Fatal("Initialized=true before StartAll initial bootstrap completed")
	}
	if snapshot.Reason != "initializing" {
		t.Fatalf("Reason=%q, want initializing", snapshot.Reason)
	}
	if snapshot.TotalWorkers != 0 || snapshot.AvailableWorkers != 0 {
		t.Fatalf("unexpected worker counts before initialization: %+v", snapshot)
	}
}

func TestPoolInitializationCompletesOnlyAfterAllBootstrapAttemptsFinish(t *testing.T) {
	pool := NewPool(&config.Config{})
	pool.beginInitialization(2)
	pool.finishInitializationAttempt()
	if got := pool.ReadinessSnapshot(); got.Initialized || got.Reason != "initializing" {
		t.Fatalf("readiness after first of two attempts=%+v, want initializing", got)
	}

	pool.finishInitializationAttempt()
	if got := pool.ReadinessSnapshot(); !got.Initialized {
		t.Fatalf("Initialized=false after all bootstrap attempts: %+v", got)
	}
}

func TestPoolReadinessFailsWithNoWorkersAfterInitialization(t *testing.T) {
	pool := NewPool(&config.Config{})
	pool.beginInitialization(0)
	snapshot := pool.ReadinessSnapshot()

	if snapshot.Ready {
		t.Fatal("Ready=true with zero workers")
	}
	if !snapshot.Initialized {
		t.Fatal("Initialized=false after zero bootstrap attempts completed")
	}
	if snapshot.Reason != "no_workers" {
		t.Fatalf("Reason=%q, want no_workers", snapshot.Reason)
	}
}

func TestPoolReadinessSucceedsWithHealthyWorker(t *testing.T) {
	pool := NewPool(&config.Config{})
	worker := &Worker{}
	worker.state.Runtime.Ready = true
	worker.state.Meta.Healthy = true
	pool.workers["synthetic-worker"] = worker
	pool.beginInitialization(0)

	snapshot := pool.ReadinessSnapshot()

	if !snapshot.Ready {
		t.Fatalf("Ready=false with one healthy worker: %+v", snapshot)
	}
	if !snapshot.Initialized || snapshot.Degraded {
		t.Fatalf("unexpected readiness flags: %+v", snapshot)
	}
	if snapshot.Reason != "ready" {
		t.Fatalf("Reason=%q, want ready", snapshot.Reason)
	}
	if snapshot.TotalWorkers != 1 || snapshot.AvailableWorkers != 1 {
		t.Fatalf("unexpected worker counts: %+v", snapshot)
	}
}

func TestPoolReadinessFailsWhenCriticalControlPlaneIsDegraded(t *testing.T) {
	pool := NewPool(&config.Config{})
	healthy := &Worker{}
	healthy.state.Runtime.Ready = true
	healthy.state.Meta.Healthy = true
	failed := &Worker{}
	failed.state.Runtime.Ready = true
	failed.RecordWatchdogEvent(WatchdogEvent{
		Layer:     HealthLayerQMI,
		State:     HealthStateInvalid,
		EventType: "synthetic_control_failure",
	})
	pool.workers["healthy-worker"] = healthy
	pool.workers["failed-worker"] = failed
	pool.beginInitialization(0)

	snapshot := pool.ReadinessSnapshot()

	if snapshot.Ready {
		t.Fatalf("Ready=true with invalid control plane: %+v", snapshot)
	}
	if !snapshot.Degraded || !snapshot.Initialized {
		t.Fatalf("unexpected readiness flags: %+v", snapshot)
	}
	if snapshot.Reason != "control_degraded" {
		t.Fatalf("Reason=%q, want control_degraded", snapshot.Reason)
	}
	if snapshot.TotalWorkers != 2 || snapshot.AvailableWorkers != 1 {
		t.Fatalf("unexpected worker counts: %+v", snapshot)
	}
}
