package imscore

import (
	"context"
	"net"
	"testing"
)

func TestTransferProtectedTCPMessagingOwnershipMovesRuntimeAndClientFlowOnce(t *testing.T) {
	cfg, state, _, allocator := runtimeTestStateWithAllocator(t)
	runtime, err := startProtectedTCPRuntime(context.Background(), cfg, &countingCarrierDialer{}, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	runtime.BindPortRelease(allocator, state.generation)

	client, peer := net.Pipe()
	defer peer.Close()
	transport, err := newStreamRegisterTransport(client)
	if err != nil {
		t.Fatalf("newStreamRegisterTransport: %v", err)
	}
	result := &registerResult{}

	if err := transferProtectedTCPMessagingOwnership(result, runtime, transport); err != nil {
		t.Fatalf("transferProtectedTCPMessagingOwnership: %v", err)
	}
	if result.protectedTCP != runtime || result.protectedClientConn != client {
		t.Fatal("runtime and client flow were not transferred together")
	}
	if again := transport.ReleaseConn(); again != nil {
		t.Fatal("client flow could be transferred twice")
	}
	runtime.CloseUnlessTransferred()
	if runtime.Closed() {
		t.Fatal("register cleanup closed the transferred runtime")
	}

	_ = result.protectedClientConn.Close()
	runtime.Close()
	if !runtime.Closed() || !runtime.Joined() || allocator.isActive(state.generation) {
		t.Fatal("transferred runtime did not close, join and release its generation")
	}
}
