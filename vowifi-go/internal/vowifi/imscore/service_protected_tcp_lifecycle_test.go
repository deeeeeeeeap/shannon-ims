package imscore

import (
	"context"
	"net"
	"testing"
)

func TestServiceAdoptsProtectedTCPRuntimeAndClosesIt(t *testing.T) {
	cfg, state, _, allocator := runtimeTestStateWithAllocator(t)
	dialer := &countingCarrierDialer{}
	runtime, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	runtime.BindPortRelease(allocator, state.generation)

	owned, ok := runtime.TakeOwnership()
	if !ok || owned == nil {
		t.Fatal("register result could not take runtime ownership")
	}
	clientConn, peerConn := net.Pipe()
	defer peerConn.Close()
	result := &registerResult{
		protectedTCP:        owned,
		protectedClientConn: clientConn,
		ipsecPolicy:         state.ipsecPolicy,
		transport:           state.transport,
	}
	service := &Service{cfg: cfg, protectedRuntimes: newProtectedRuntimeHolder()}

	if err := service.adoptProtectedTCPResult(result); err != nil {
		t.Fatalf("adoptProtectedTCPResult: %v", err)
	}
	if result.protectedTCP != nil {
		t.Fatal("register result retained runtime after Service adoption")
	}
	if current := service.protectedRuntimes.current(); current != runtime {
		t.Fatal("Service did not retain the adopted runtime")
	}
	if runtime.Closed() {
		t.Fatal("Service adoption closed the live runtime")
	}
	if shouldStartLegacyTransportRuntime(result) {
		t.Fatal("legacy transport would start alongside protected TCP")
	}
	if err := service.attachMessaging(context.Background(), "", result); err != nil {
		t.Fatalf("protected TCP registration should remain usable without messaging: %v", err)
	}
	if !service.MessagingReady() {
		t.Fatal("protected TCP service did not attach messaging to the transferred client flow")
	}

	if err := service.Close(context.Background()); err != nil {
		t.Fatalf("Service.Close: %v", err)
	}
	if !runtime.Closed() || !runtime.Joined() {
		t.Fatal("Service.Close did not close and join the protected runtime")
	}
	if allocator.isActive(state.generation) {
		t.Fatal("Service.Close did not release the protected port generation")
	}
}
