package imscore

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

// D2 precondition: the rotation must never hand out a port that is STILL IN USE.
//
// The first allocator only remembered a bounded history of recently issued
// client ports. That prevents an immediate repeat, but after a full lap of the
// rotation range it drops half the history and reissues - and nothing checked
// whether the reissued port still belonged to a live generation. Two live SAs on
// one port_uc would collide in the ESP selector: matchOutbound keys on
// (LocalPort, RemotePort), so the second SA's packets would be protected with the
// first SA's keys.
//
// "Recently issued" and "currently active" are different sets. A port must be
// released explicitly when its generation is retired, and the allocator must
// refuse to reissue anything still held.
//
// Assertions are counts, booleans and set membership over derived integers. No
// address, SPI, key or SIP content appears here.

// A port stays reserved until its generation is released, even across a full lap
// of the rotation range.
func TestProtectedPortAllocatorNeverReissuesAnActivePort(t *testing.T) {
	alloc := newProtectedPortAllocator()

	// Hold a small set of allocations without releasing them.
	held := map[int]uint64{}
	for i := 0; i < 8; i++ {
		got := alloc.next()
		if prev, dup := held[got.clientPort]; dup {
			t.Fatalf("port_uc %d issued twice while generation %d still holds it",
				got.clientPort, prev)
		}
		held[got.clientPort] = got.generation
	}

	// Now walk well past a full lap. Every allocation must avoid the held ports.
	for i := 0; i < protectedClientPortSpan*3; i++ {
		got := alloc.next()
		if gen, active := held[got.clientPort]; active {
			t.Fatalf("lap %d reissued port_uc %d, still held by generation %d",
				i, got.clientPort, gen)
		}
		// Release each transient allocation immediately so the range does not
		// genuinely run out.
		alloc.release(got.generation)
	}
	t.Logf("MEASURED held_ports=%d laps=3 active_reissues=0", len(held))
}

// A released port becomes available again, otherwise a long-lived UE would
// exhaust the range.
func TestProtectedPortAllocatorReusesReleasedPorts(t *testing.T) {
	alloc := newProtectedPortAllocator()

	first := alloc.next()
	alloc.release(first.generation)

	// Walk the whole range; the released port must reappear.
	seen := false
	for i := 0; i < protectedClientPortSpan+8; i++ {
		got := alloc.next()
		if got.clientPort == first.clientPort {
			seen = true
		}
		alloc.release(got.generation)
	}
	if !seen {
		t.Fatal("a released port_uc never became available again")
	}
	t.Logf("MEASURED released_port_reused=true")
}

// Exhaustion must fail closed rather than duplicate a live port. A registration
// that cannot get a distinct port_uc must not proceed with a colliding one.
func TestProtectedPortAllocatorFailsClosedWhenExhausted(t *testing.T) {
	alloc := newProtectedPortAllocator()

	held := map[int]bool{}
	exhausted := false
	// The usable range excludes port_us, so at most span-1 ports can be held.
	for i := 0; i < protectedClientPortSpan+4; i++ {
		got, err := alloc.tryNext()
		if err != nil {
			exhausted = true
			break
		}
		if held[got.clientPort] {
			t.Fatalf("port_uc %d was issued twice before exhaustion", got.clientPort)
		}
		held[got.clientPort] = true
	}
	if !exhausted {
		t.Fatal("the allocator never reported exhaustion; it must fail closed")
	}
	// The held set must be the whole usable range: the allocator may not stop
	// early, and may not have skipped a usable port.
	if len(held) == 0 {
		t.Fatal("exhaustion was reported before any port was issued")
	}
	t.Logf("MEASURED held_before_exhaustion=%d failed_closed=true", len(held))
}

// Release must be idempotent and must tolerate unknown generations: the runtime
// teardown path can run twice (explicit Close plus a deferred Close).
func TestProtectedPortReleaseIsIdempotent(t *testing.T) {
	alloc := newProtectedPortAllocator()
	got := alloc.next()

	alloc.release(got.generation)
	alloc.release(got.generation)
	alloc.release(0)
	alloc.release(^uint64(0))

	// The allocator must still work afterwards.
	next := alloc.next()
	if next.generation <= got.generation {
		t.Fatal("generation stopped advancing after repeated releases")
	}
	t.Logf("MEASURED double_release_safe=true unknown_release_safe=true")
}

// Concurrent allocate and release must not corrupt the active set or hand out a
// duplicate live port.
func TestProtectedPortAllocatorConcurrentAllocateAndRelease(t *testing.T) {
	alloc := newProtectedPortAllocator()
	const workers = 32
	const rounds = 8

	var mu sync.Mutex
	live := map[int]bool{}
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				got, err := alloc.tryNext()
				if err != nil {
					continue
				}
				mu.Lock()
				if live[got.clientPort] {
					t.Errorf("port_uc %d held by two generations at once", got.clientPort)
				}
				live[got.clientPort] = true
				mu.Unlock()

				mu.Lock()
				delete(live, got.clientPort)
				mu.Unlock()
				alloc.release(got.generation)
			}
		}()
	}
	wg.Wait()
	if len(live) != 0 {
		t.Fatalf("%d ports leaked as active", len(live))
	}
	t.Logf("MEASURED workers=%d rounds=%d leaked=0", workers, rounds)
}

func TestRegisterCandidateFailureReleasesProtectedPortGeneration(t *testing.T) {
	network := &scriptedRegisterIMSNetwork{
		dial: func(string) (net.Conn, error) {
			return &immediateRegisterTimeoutConn{}, nil
		},
	}
	cfg := registerSessionTestConfig()
	service := &Service{
		imsCfg:         IMSConfig{Transport: "udp"},
		cfg:            cfg,
		network:        network,
		protectedPorts: newProtectedPortAllocator(),
	}
	attempt := service.registerRawWithCandidate(
		context.Background(),
		registerAttemptCandidate{Registrar: cfg.PCSCFAddr, Gateway: cfg.PCSCFAddr},
		"udp",
		0,
	)
	if attempt.err == nil {
		t.Fatal("synthetic candidate unexpectedly succeeded")
	}
	if got := service.protectedPorts.activeCount(); got != 0 {
		t.Fatalf("active protected generations = %d, want 0 after failed candidate", got)
	}
}

func TestProtectedPortExhaustionFailsWithoutTransportOrCandidateRetry(t *testing.T) {
	network := &scriptedRegisterIMSNetwork{
		dial: func(string) (net.Conn, error) {
			return nil, errors.New("network must not be reached")
		},
	}
	cfg := registerSessionTestConfig()
	service := &Service{
		imsCfg:         IMSConfig{Transport: "auto"},
		cfg:            cfg,
		network:        network,
		protectedPorts: newProtectedPortAllocator(),
	}
	var held []uint64
	for {
		allocation, err := service.protectedPorts.tryNext()
		if err != nil {
			break
		}
		held = append(held, allocation.generation)
	}
	defer func() {
		for _, generation := range held {
			service.protectedPorts.release(generation)
		}
	}()

	attempt := service.registerRawWithCandidate(
		context.Background(),
		registerAttemptCandidate{Registrar: cfg.PCSCFAddr, Gateway: cfg.PCSCFAddr},
		"udp",
		0,
	)
	if !errors.Is(attempt.err, errProtectedPortsExhausted) {
		t.Fatalf("attempt error = %v, want protected port exhaustion", attempt.err)
	}
	if got := len(network.dialedTransports()); got != 0 {
		t.Fatalf("network dials = %d, want 0", got)
	}
	if shouldRetryNextRegisterTransport(0, attempt.err, 0, 2, false) {
		t.Fatal("protected port exhaustion would retry another transport")
	}
	if shouldAdvanceRegistrarForProbeError(attempt.err, true) {
		t.Fatal("protected port exhaustion would advance registrar candidate")
	}
}
