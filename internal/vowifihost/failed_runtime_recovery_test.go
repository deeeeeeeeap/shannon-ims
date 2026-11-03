package vowifihost

import (
	"context"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost"
)

func TestFailedAdmittedRuntimeCanRecover(t *testing.T) {
	m := NewManager()
	claim := m.BeginStart("fixture-device")
	inst := &runtimehost.Instance{}
	if !m.ClaimStarted("fixture-device", claim.Epoch, inst) {
		t.Fatal("claim failed")
	}
	if m.DesiredRecoverable("fixture-device") {
		t.Fatal("starting pipeline must not be replaced")
	}
	if !m.publishRuntimeState("fixture-device", claim.Epoch, inst, runtimehost.State{LastErrorClass: "ims", LastReason: "ims_channel_closed"}) {
		t.Fatal("failure publication rejected")
	}
	if !m.DesiredRecoverable("fixture-device") {
		t.Fatal("dead instance permanently blocks desired recovery")
	}
	if _, accepted := m.RuntimeStore().beginDesiredRecover("fixture-device", time.Now().Add(3*time.Minute)); !accepted {
		t.Fatal("failed instance was rejected at recovery admission")
	}
	if _, accepted := m.RuntimeStore().beginDesiredRecover("fixture-device", time.Now().Add(3*time.Minute)); accepted {
		t.Fatal("duplicate recovery was admitted")
	}
}

func TestAsyncRecoveryKeepsBackoffUntilIMSReady(t *testing.T) {
	m := NewManager()
	store := m.RuntimeStore()
	deviceID := "fixture-async"
	for attempt := 0; attempt < 2; attempt++ {
		generation, accepted := store.beginDesiredRecover(deviceID, time.Now().Add(3*time.Minute))
		if !accepted {
			t.Fatal("recovery not admitted")
		}
		lifecycle, accepted := store.admitLifecycle(deviceID, LifecycleCommandRecover)
		if !accepted {
			t.Fatal("lifecycle not admitted")
		}
		_, release, current := store.bindLifecycleRun(context.Background(), deviceID, lifecycle, LifecycleCommandRecover, generation)
		if !current {
			t.Fatal("lifecycle bind failed")
		}
		if previous := store.Instance(deviceID); previous != nil {
			store.DeleteInstance(deviceID, previous)
		}
		claim := m.BeginStart(deviceID)
		inst := &runtimehost.Instance{}
		if !m.ClaimStarted(deviceID, claim.Epoch, inst) {
			t.Fatal("claim failed")
		}
		release()
		if _, current := store.finishDesiredRecover(deviceID, generation, time.Now(), desiredRecoverSucceeded); !current {
			t.Fatal("claim erased in-flight recovery")
		}
		if !m.publishRuntimeState(deviceID, claim.Epoch, inst, runtimehost.State{LastErrorClass: "ims", LastReason: "synthetic_failure"}) {
			t.Fatal("failure rejected")
		}
		snapshot, _ := m.DesiredRecoverState(deviceID)
		if snapshot.Attempt != attempt+1 || snapshot.Delay != DesiredRecoverDelay(attempt) {
			t.Fatal("async failure reset backoff")
		}
	}
}
