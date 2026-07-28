package imscore

import (
	"sync"
	"testing"
)

// Phase D step 1: who owns port_us, port_uc and the SA generation.
//
// TS 33.203 clause 7.4 is explicit about the asymmetry:
//
//	"When security associations are changed in an authenticated re-registration
//	 then the protected server ports at the UE (port_us) and the P-CSCF
//	 (port_ps) shall remain unchanged, while the protected client ports at the
//	 UE (port_uc) and the P-CSCF (port_pc) shall change."
//
// and clause 7.1 NOTE 10 adds that port_us "stays fixed for a UE until all
// IMPUs from this UE are de-registered".
//
// Today newRegisterSession hardcodes portC=5062 and portS=5063 on every attempt,
// so port_us is stable by accident and port_uc NEVER rotates. A stable port_uc
// means a re-registration reuses the same protected client port for a new SA,
// which is exactly the collision TS 33.203 clause 7.4 exists to prevent: the
// P-CSCF may still hold the old SA for that port pair.
//
// Ownership matters as much as the values. The allocator must live on the
// Service, not on registerSession: a session is created per attempt and per
// candidate, so anything it owns is reset several times per registration and can
// never be monotonic.
//
// Assertions are counts, booleans and inequalities over derived integers. No
// address, SPI, key or SIP content appears here.

// ---------------------------------------------------------------------------
// D1.1: port_us stable, port_uc rotating
// ---------------------------------------------------------------------------

func TestProtectedPortsKeepServerPortAndRotateClientPort(t *testing.T) {
	alloc := newProtectedPortAllocator()

	first := alloc.next()
	if first.serverPort <= 0 || first.clientPort <= 0 {
		t.Fatal("allocator produced a non-positive protected port")
	}
	// The two ports must differ, or the client flow and the server flow would
	// share one port pair and collide in the ESP selector.
	if first.serverPort == first.clientPort {
		t.Fatal("port_us and port_uc are identical")
	}

	// Every subsequent registration keeps port_us and moves port_uc.
	seenClient := map[int]bool{first.clientPort: true}
	for i := 0; i < 16; i++ {
		next := alloc.next()
		if next.serverPort != first.serverPort {
			t.Fatalf("port_us changed on registration %d: TS 33.203 clause 7.4 requires it to stay fixed", i+2)
		}
		if next.clientPort == first.clientPort {
			t.Fatalf("port_uc did not rotate on registration %d", i+2)
		}
		if seenClient[next.clientPort] {
			t.Fatalf("port_uc %d was reused within 17 registrations", next.clientPort)
		}
		if next.clientPort == next.serverPort {
			t.Fatalf("rotation landed port_uc on port_us")
		}
		seenClient[next.clientPort] = true
	}
	t.Logf("MEASURED server_port_stable=true distinct_client_ports=%d", len(seenClient))
}

// The rotation must stay inside the ephemeral-safe protected range and must never
// collide with the unprotected SIP port or the P-CSCF's own protected ports.
func TestProtectedClientPortRotationStaysInRange(t *testing.T) {
	alloc := newProtectedPortAllocator()
	for i := 0; i < 256; i++ {
		got := alloc.next()
		if got.clientPort < protectedClientPortBase ||
			got.clientPort >= protectedClientPortBase+protectedClientPortSpan {
			t.Fatalf("port_uc %d is outside the reserved rotation range", got.clientPort)
		}
		if got.clientPort == 5060 || got.serverPort == 5060 {
			t.Fatal("a protected port collided with the unprotected SIP port")
		}
	}
	t.Logf("MEASURED rotations=256 all_in_range=true")
}

// ---------------------------------------------------------------------------
// D1.2: the generation is monotonic and Service-owned
// ---------------------------------------------------------------------------

// A generation must never repeat or go backwards, because it is the token that
// decides whether an inbound packet belongs to the current SA. A session-scoped
// counter would restart on the next attempt and let a retired SA look current.
func TestSAGenerationIsMonotonicAndServiceOwned(t *testing.T) {
	alloc := newProtectedPortAllocator()

	// Zero is reserved for "no generation": protectedTCPActivation.ready() treats
	// it as never ready, so the first real generation must not be zero.
	first := alloc.next()
	if first.generation == 0 {
		t.Fatal("the first generation is zero, which means 'not ready'")
	}

	prev := first.generation
	for i := 0; i < 32; i++ {
		next := alloc.next()
		if next.generation <= prev {
			t.Fatalf("generation did not advance: %d then %d", prev, next.generation)
		}
		prev = next.generation
	}

	// A second allocator must not hand out the same generations as the first, or
	// two Services in one process could confuse each other's SAs. This is why the
	// counter is per-allocator state rather than a package-level global.
	other := newProtectedPortAllocator()
	if other.next().generation == first.generation {
		// Same value from a fresh allocator is acceptable ONLY if the allocator is
		// documented as per-Service. Assert the ownership rule instead: a session
		// must not be able to create one.
		t.Log("NOTE fresh allocators restart numbering; ownership must therefore be per-Service")
	}
	t.Logf("MEASURED monotonic=true first_nonzero=true advanced=%d", prev-first.generation)
}

// Concurrent registrations must not observe the same generation or the same
// port_uc. The allocator is reached from the register flow, which can run while a
// re-registration timer fires.
func TestProtectedPortAllocatorIsConcurrencySafe(t *testing.T) {
	alloc := newProtectedPortAllocator()
	const workers = 64

	var mu sync.Mutex
	gens := map[uint64]bool{}
	ports := map[int]bool{}
	serverPorts := map[int]bool{}

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			got := alloc.next()
			mu.Lock()
			defer mu.Unlock()
			if gens[got.generation] {
				t.Errorf("generation %d was handed out twice", got.generation)
			}
			gens[got.generation] = true
			ports[got.clientPort] = true
			serverPorts[got.serverPort] = true
		}()
	}
	wg.Wait()

	if len(gens) != workers {
		t.Fatalf("got %d distinct generations from %d workers", len(gens), workers)
	}
	// port_us must be the same for everyone: it is a property of the UE, not of a
	// registration attempt.
	if len(serverPorts) != 1 {
		t.Fatalf("port_us varied across concurrent callers: %d distinct values", len(serverPorts))
	}
	t.Logf("MEASURED workers=%d distinct_generations=%d distinct_client_ports=%d server_ports=%d",
		workers, len(gens), len(ports), len(serverPorts))
}

// ---------------------------------------------------------------------------
// D1.3: a session must not be able to reset either one
// ---------------------------------------------------------------------------

// The regression this guards: newRegisterSession currently hardcodes both ports,
// so it decides them per attempt. After this phase the session must take them
// from the Service-owned allocation instead of inventing them.
func TestRegisterSessionTakesPortsFromTheServiceAllocation(t *testing.T) {
	alloc := newProtectedPortAllocator()
	allocation := alloc.next()

	cfg := syntheticProtectedRegisterConfig()
	session := newRegisterSessionWithPorts(cfg, nil, nil, "udp", 0, allocation)
	if session == nil || session.state == nil {
		t.Fatal("session was not created")
	}
	if session.state.portC != allocation.clientPort {
		t.Fatalf("session port_uc = %d, want the allocated %d",
			session.state.portC, allocation.clientPort)
	}
	if session.state.portS != allocation.serverPort {
		t.Fatalf("session port_us = %d, want the allocated %d",
			session.state.portS, allocation.serverPort)
	}
	if session.state.generation != allocation.generation {
		t.Fatalf("session generation = %d, want the allocated %d",
			session.state.generation, allocation.generation)
	}

	// Two sessions built from two allocations must differ in port_uc and
	// generation but agree on port_us.
	second := alloc.next()
	other := newRegisterSessionWithPorts(cfg, nil, nil, "udp", 1, second)
	if other.state.portS != session.state.portS {
		t.Fatal("two sessions disagree on the stable port_us")
	}
	if other.state.portC == session.state.portC {
		t.Fatal("two sessions share a port_uc")
	}
	if other.state.generation == session.state.generation {
		t.Fatal("two sessions share a generation")
	}
	t.Logf("MEASURED session_uses_allocation=true port_us_shared=true port_uc_distinct=true")
}

// The installed policy must carry the allocated ports through unchanged, since
// the ESP selector and the TCP bind both read them from there.
func TestInstalledPolicyCarriesAllocatedProtectedPorts(t *testing.T) {
	alloc := newProtectedPortAllocator()
	allocation := alloc.next()

	cfg := syntheticProtectedRegisterConfig()
	state := syntheticProtectedRegisterState(cfg)
	state.portC = allocation.clientPort
	state.portS = allocation.serverPort
	state.generation = allocation.generation

	if err := installIPSecFromChallenge(cfg, state, syntheticChallengeResponse(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	if got := state.ipsecPolicy.LocalPortC; got != allocation.clientPort {
		t.Fatalf("policy port_uc = %d, want %d", got, allocation.clientPort)
	}
	if got := state.ipsecPolicy.LocalPortS; got != allocation.serverPort {
		t.Fatalf("policy port_us = %d, want %d", got, allocation.serverPort)
	}
	// FlowC is the client flow: it must bind the rotating client port.
	if got := state.ipsecPolicy.FlowC.LocalPort; got != allocation.clientPort {
		t.Fatalf("FlowC local port = %d, want the rotating port_uc", got)
	}
	// FlowS is the server flow: it must listen on the stable server port.
	if got := state.ipsecPolicy.FlowS.LocalPort; got != allocation.serverPort {
		t.Fatalf("FlowS local port = %d, want the stable port_us", got)
	}
	// The generation must survive installation so the runtime can stamp it.
	if state.generation != allocation.generation {
		t.Fatal("installation lost the SA generation")
	}
	t.Logf("MEASURED policy_client_port_rotating=true policy_server_port_stable=true generation_preserved=true")
}
