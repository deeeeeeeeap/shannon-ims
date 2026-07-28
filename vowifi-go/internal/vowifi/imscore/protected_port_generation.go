package imscore

import (
	"crypto/rand"
	"errors"
	"math/big"
	"sync"
)

// Phase D step 1: ownership of port_us, port_uc and the SA generation.
//
// TS 33.203 clause 7.4 makes the two protected local ports behave differently
// across an authenticated re-registration:
//
//   - port_us (and the P-CSCF's port_ps) "shall remain unchanged"
//   - port_uc (and the P-CSCF's port_pc) "shall change"
//
// and clause 7.1 NOTE 10 pins port_us for the lifetime of the registration:
// it "stays fixed for a UE until all IMPUs from this UE are de-registered".
//
// The reason the asymmetry matters here rather than being cosmetic: port_us is
// the address the P-CSCF connects BACK to for every network-originated request
// (clause 7.1 Ports item 1), so moving it would break the terminating path.
// port_uc, by contrast, identifies one SA's client flow; reusing it for a new SA
// invites a collision with the old SA the P-CSCF may still hold for that pair.
//
// Both used to be hardcoded to 5062/5063 in newRegisterSession, which made
// port_us stable only by accident and left port_uc never rotating.
//
// The allocator lives on the Service, not on registerSession. A session exists
// per attempt and per candidate, so a session-scoped counter would restart
// several times inside one registration and could never be monotonic - and the
// generation's whole job is to tell a current SA from a retired one.

const (
	// protectedServerPort is the stable port_us. It is fixed rather than
	// allocated because clause 7.1 NOTE 10 requires it to survive every
	// re-registration, and because the P-CSCF learns it from the Contact and
	// Security-Client of the first REGISTER.
	protectedServerPort = 5063

	// protectedClientPortBase and protectedClientPortSpan bound the rotation
	// range for port_uc. The range deliberately excludes 5060 (unprotected SIP)
	// and protectedServerPort.
	protectedClientPortBase = 5064
	protectedClientPortSpan = 256

	// unprotectedSIPPort is excluded from the rotation range: TS 33.203
	// clause 7.1 Ports item 2 forbids unprotected traffic on port_uc/port_us, so
	// the two sets must never overlap.
	unprotectedSIPPort = 5060
)

// errProtectedClientPortsExhausted is returned when every usable port_uc is held
// by a live generation.
//
// Failing closed is the only safe option: reissuing a live port would give two
// SAs the same (LocalPort, RemotePort) selector, and matchOutbound would protect
// the new SA's packets with the old SA's keys.
var errProtectedClientPortsExhausted = errors.New("imscore: protected client ports exhausted")

// protectedPortsInitMu guards lazy creation of a Service's allocator.
//
// It is a package-level lock rather than a field because it protects the
// creation of the field itself. It is held only for the pointer swap, never
// across next(), so it cannot serialise allocation.
var protectedPortsInitMu sync.Mutex

// allocateProtectedPorts returns the next allocation for this Service, creating
// the allocator on first use.
//
// Lazy creation keeps every existing Service literal valid - including the ones
// in tests - while still guaranteeing that all allocations for one Service come
// from a single monotonic counter.
func (s *Service) allocateProtectedPorts() (protectedPortAllocation, error) {
	if s == nil {
		return protectedPortAllocation{}, errors.New("imscore: service is nil")
	}
	protectedPortsInitMu.Lock()
	if s.protectedPorts == nil {
		s.protectedPorts = newProtectedPortAllocator()
	}
	allocator := s.protectedPorts
	protectedPortsInitMu.Unlock()
	return allocator.tryNext()
}

// protectedPortAllocation is one registration's worth of protected identity: the
// stable server port, a freshly rotated client port, and the generation that
// stamps every packet belonging to the resulting SA.
type protectedPortAllocation struct {
	serverPort int
	clientPort int
	generation uint64
}

// protectedPortAllocator hands out allocations for one Service.
//
// It is safe for concurrent use: a re-registration timer can fire while an
// attempt is still running, and two callers must never receive the same
// generation or the same client port.
//
// The allocator tracks ACTIVE ports, not recently-issued ones. Those are
// different sets, and only the first is safe: the ESP selector keys on
// (LocalPort, RemotePort), so if a live SA still holds a port_uc, reissuing it
// would make a second SA's packets match the first SA's flow and be protected
// with the wrong keys. A port is therefore reserved from allocation until its
// generation is explicitly released, and exhaustion fails closed rather than
// duplicating a live port.
type protectedPortAllocator struct {
	mu         sync.Mutex
	generation uint64
	offset     int
	// active maps a live generation to the client port it holds.
	active map[uint64]int
	// activePorts is the reverse index, so a candidate port can be rejected
	// without scanning every generation.
	activePorts map[int]uint64
}

func newProtectedPortAllocator() *protectedPortAllocator {
	// The starting offset is random so two UEs on one operator do not walk the
	// same port sequence in lockstep. Failure to read randomness is not fatal:
	// the sequence only needs to be non-repeating, not unpredictable.
	start := 0
	if n, err := rand.Int(rand.Reader, big.NewInt(protectedClientPortSpan)); err == nil {
		start = int(n.Int64())
	}
	return &protectedPortAllocator{
		offset:      start,
		active:      make(map[uint64]int),
		activePorts: make(map[int]uint64),
	}
}

// errProtectedPortsExhausted is returned when every usable client port is held
// by a live generation.
//
// Failing is the only correct outcome here. Reissuing a live port would put two
// SAs on one (LocalPort, RemotePort) pair, and Transport.matchOutbound keys
// exactly on that pair - so the newer SA's packets would be protected with the
// older SA's keys. A registration that cannot get a distinct port_uc must not
// proceed.
var errProtectedPortsExhausted = errors.New("imscore: no protected client port is available")

// tryNext reserves the next identity, or fails if no client port is free.
//
// The reservation is held until release(generation) is called, which the runtime
// teardown path must do for every allocation it takes - success or failure.
func (a *protectedPortAllocator) tryNext() (protectedPortAllocation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	clientPort, ok := a.reserveClientPortLocked()
	if !ok {
		return protectedPortAllocation{}, errProtectedPortsExhausted
	}

	// Generation starts at 1: zero is reserved for "no current generation", and
	// protectedTCPActivation.ready() treats it as never ready. It is incremented
	// only after a port is secured, so a failed attempt does not burn a number.
	a.generation++
	a.active[a.generation] = clientPort
	a.activePorts[clientPort] = a.generation

	return protectedPortAllocation{
		serverPort: protectedServerPort,
		clientPort: clientPort,
		generation: a.generation,
	}, nil
}

// next reserves the next identity, falling back to the legacy fixed pair when the
// range is exhausted.
//
// The fallback carries generation 0, so it can drive protected UDP exactly as
// before but can never activate protected TCP - authorizeProtectedTCPActivation
// refuses a zero generation. Callers that must not silently degrade should use
// tryNext and handle the error.
func (a *protectedPortAllocator) next() protectedPortAllocation {
	got, err := a.tryNext()
	if err != nil {
		return legacyProtectedPortAllocation()
	}
	return got
}

// release retires a generation and frees its client port.
//
// It is idempotent and tolerates unknown generations: the teardown path can run
// twice (an explicit Close plus a deferred Close), and a failed registration may
// release an allocation it never successfully used.
func (a *protectedPortAllocator) release(generation uint64) {
	if generation == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	port, ok := a.active[generation]
	if !ok {
		return
	}
	delete(a.active, generation)
	// Only clear the port if it is still owned by THIS generation. A later
	// generation may already have taken it after an earlier release.
	if owner, held := a.activePorts[port]; held && owner == generation {
		delete(a.activePorts, port)
	}
}

// activeCount reports how many generations currently hold a port.
func (a *protectedPortAllocator) activeCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.active)
}

// isActive reports whether a generation still holds its client port.
//
// The teardown path must be able to prove a release happened exactly once, and
// that a repeated release did not free a port a LATER generation has since
// taken - which would put two live SAs on one port pair.
func (a *protectedPortAllocator) isActive(generation uint64) bool {
	if generation == 0 {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.active[generation]
	return ok
}

// reserveClientPortLocked walks the rotation range for a port no live generation
// holds. It never reuses an active port, and it never returns port_us or the
// unprotected SIP port.
func (a *protectedPortAllocator) reserveClientPortLocked() (int, bool) {
	for i := 0; i < protectedClientPortSpan; i++ {
		candidate := protectedClientPortBase + (a.offset+i)%protectedClientPortSpan
		if candidate == protectedServerPort || candidate == unprotectedSIPPort {
			continue
		}
		if _, live := a.activePorts[candidate]; live {
			continue
		}
		a.offset = (a.offset + i + 1) % protectedClientPortSpan
		return candidate, true
	}
	return 0, false
}

// legacyProtectedPortAllocation reproduces the pre-Phase-D fixed pair.
//
// It exists so callers that have no Service-owned allocator keep their current
// behaviour byte for byte instead of silently gaining a rotating client port.
// Generation is zero, which protectedTCPActivation.ready() treats as "never
// ready" - so a caller on this path can use protected UDP exactly as before but
// can never activate protected TCP. That is deliberate: without a Service-owned
// generation there is nothing to distinguish a current SA from a retired one.
func legacyProtectedPortAllocation() protectedPortAllocation {
	return protectedPortAllocation{
		serverPort: legacyProtectedClientPort + 1,
		clientPort: legacyProtectedClientPort,
		generation: 0,
	}
}

// legacyProtectedClientPort is the value newRegisterSession hardcoded before
// this phase. Kept as a named constant so the legacy path is greppable.
const legacyProtectedClientPort = 5062
