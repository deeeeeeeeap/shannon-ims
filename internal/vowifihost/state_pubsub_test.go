package vowifihost

import (
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost"
)

func TestManagerStateSubscriptionBroadcastAndCleanup(t *testing.T) {
	manager := NewManager()

	ch, unsub := manager.SubscribeState("dev-1")
	if got := manager.SubscriberCount("dev-1"); got != 1 {
		t.Fatalf("SubscriberCount() = %d, want 1", got)
	}

	manager.BroadcastState("dev-1")
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("expected state broadcast")
	}

	unsub()
	if got := manager.SubscriberCount("dev-1"); got != 0 {
		t.Fatalf("SubscriberCount() after unsubscribe = %d, want 0", got)
	}

	manager.BroadcastState("dev-1")
	select {
	case <-ch:
		t.Fatal("unexpected broadcast after unsubscribe")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestManagerRecordStartupStateBroadcastsWhenAccepted(t *testing.T) {
	manager := NewManager()
	deviceID := "dev-starting"
	ch, unsub := manager.SubscribeState(deviceID)
	defer unsub()
	if claim := manager.BeginStart(deviceID); !claim.Accepted {
		t.Fatalf("BeginStart() = %+v, want accepted", claim)
	}

	accepted := manager.RecordStartupState(deviceID, runtimehost.State{
		DeviceID:   deviceID,
		Phase:      "radio_ready",
		UpdatedAt:  time.Now(),
		LastReason: "starting",
	})
	if !accepted {
		t.Fatal("expected startup state to be accepted")
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("expected broadcast for accepted startup state")
	}

	rejected := manager.RecordStartupState(deviceID, runtimehost.State{
		DeviceID:  deviceID,
		Phase:     "older",
		UpdatedAt: time.Now().Add(-time.Hour),
	})
	if rejected {
		t.Fatal("expected stale startup state to be rejected")
	}
	select {
	case <-ch:
		t.Fatal("unexpected broadcast for rejected startup state")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestManagerRejectsStartupStateAfterAttemptInvalidation(t *testing.T) {
	manager := NewManager()
	deviceID := "dev-invalidated-start"
	if claim := manager.BeginStart(deviceID); !claim.Accepted {
		t.Fatalf("BeginStart() = %+v, want accepted", claim)
	}
	updates, unsubscribe := manager.SubscribeState(deviceID)
	defer unsubscribe()
	manager.InvalidateRuntime(deviceID, "test")

	accepted := manager.RecordStartupState(deviceID, runtimehost.State{
		DeviceID:  deviceID,
		Phase:     "stale_callback",
		UpdatedAt: time.Now(),
	})
	if accepted {
		t.Fatal("RecordStartupState() accepted a callback after attempt invalidation")
	}
	select {
	case <-updates:
		t.Fatal("stale callback published after attempt invalidation")
	default:
	}
}

func TestStoreRejectsPreviousEpochStateDuringNewAttempt(t *testing.T) {
	store := NewRuntimeStore()
	deviceID := "dev-new-attempt"
	oldClaim := store.BeginStart(deviceID)
	store.Invalidate(deviceID)
	currentClaim := store.BeginStart(deviceID)
	instance := &runtimehost.Instance{}
	state := runtimehost.State{DeviceID: deviceID, Phase: "starting", UpdatedAt: time.Now()}

	if store.publishRuntimeState(deviceID, oldClaim.Epoch, instance, state) {
		t.Fatal("publishRuntimeState() accepted the previous attempt epoch")
	}
	if !store.publishRuntimeState(deviceID, currentClaim.Epoch, instance, state) {
		t.Fatal("publishRuntimeState() rejected the current attempt epoch")
	}
}

func TestManagerRejectsOldInstanceStateAfterReplacement(t *testing.T) {
	manager := NewManager()
	deviceID := "dev-replaced-instance"
	oldClaim := manager.BeginStart(deviceID)
	oldInstance := &runtimehost.Instance{}
	if !manager.ClaimStarted(deviceID, oldClaim.Epoch, oldInstance) {
		t.Fatal("ClaimStarted() rejected the original runtime")
	}
	if !manager.TeardownSession(nil, deviceID, TeardownOptions{Reason: "replacement"}) {
		t.Fatal("TeardownSession() did not remove the original runtime")
	}

	currentClaim := manager.BeginStart(deviceID)
	currentInstance := &runtimehost.Instance{}
	if !manager.ClaimStarted(deviceID, currentClaim.Epoch, currentInstance) {
		t.Fatal("ClaimStarted() rejected the replacement runtime")
	}

	updates, unsubscribe := manager.SubscribeState(deviceID)
	defer unsubscribe()
	state := runtimehost.State{DeviceID: deviceID, Phase: "ims_ready", UpdatedAt: time.Now()}
	if manager.publishRuntimeState(deviceID, oldClaim.Epoch, oldInstance, state) {
		t.Fatal("old runtime state was accepted after replacement")
	}
	select {
	case <-updates:
		t.Fatal("old runtime state published after replacement")
	default:
	}

	if !manager.publishRuntimeState(deviceID, currentClaim.Epoch, currentInstance, state) {
		t.Fatal("current runtime state was rejected")
	}
	select {
	case <-updates:
	default:
		t.Fatal("current runtime state was not published")
	}
}
