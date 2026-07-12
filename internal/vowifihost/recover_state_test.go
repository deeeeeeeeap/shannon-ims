package vowifihost

import (
	"errors"
	"testing"
	"time"
)

func TestManagerDesiredRecoverBackoffLifecycle(t *testing.T) {
	manager := NewManager()
	deviceID := "dev-recover"
	now := time.Now()

	if !manager.BeginDesiredRecover(deviceID, now) {
		t.Fatal("first BeginDesiredRecover() = false, want true")
	}
	if manager.BeginDesiredRecover(deviceID, now) {
		t.Fatal("BeginDesiredRecover() while in-flight = true, want false")
	}

	snapshot := manager.MarkDesiredRecoverFailed(deviceID, now, errors.New("network down"))
	if snapshot.Attempt != 1 {
		t.Fatalf("attempt = %d, want 1", snapshot.Attempt)
	}
	if snapshot.Delay != 30*time.Second {
		t.Fatalf("delay = %s, want 30s", snapshot.Delay)
	}
	if manager.BeginDesiredRecover(deviceID, now.Add(29*time.Second)) {
		t.Fatal("BeginDesiredRecover() before nextAt = true, want false")
	}
	if !manager.BeginDesiredRecover(deviceID, now.Add(31*time.Second)) {
		t.Fatal("BeginDesiredRecover() after nextAt = false, want true")
	}

	manager.ClearDesiredRecoverState(deviceID)
	if manager.HasDesiredRecoverState(deviceID) {
		t.Fatal("recover state should be cleared")
	}
}
