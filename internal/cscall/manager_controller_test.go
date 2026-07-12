package cscall

import "testing"

func TestHasConnectedCallMatchesEmptyOrExactID(t *testing.T) {
	calls := []CallInfo{{ID: "7", State: CallStateConnected}}
	if !hasConnectedCall(calls, "7") {
		t.Fatal("hasConnectedCall() false for exact connected call")
	}
	if !hasConnectedCall(calls, "") {
		t.Fatal("hasConnectedCall() false for empty desired call")
	}
	if hasConnectedCall(calls, "8") {
		t.Fatal("hasConnectedCall() true for different call id")
	}
}

func TestManagerBeginIncomingCallSetsRingingState(t *testing.T) {
	mgr := &Manager{deviceID: "dev-1", state: CallStateIdle}
	sipCallID, shouldStart := mgr.beginIncomingCall("at", "+123")
	if !shouldStart {
		t.Fatal("shouldStart=false want true")
	}
	if sipCallID == "" {
		t.Fatal("sipCallID is empty")
	}
	if mgr.state != CallStateRinging {
		t.Fatalf("state=%v want ringing", mgr.state)
	}
	if mgr.callerID != "+123" {
		t.Fatalf("callerID=%q want +123", mgr.callerID)
	}
	if mgr.controllerCallID != "at" {
		t.Fatalf("controllerCallID=%q want at", mgr.controllerCallID)
	}
}
