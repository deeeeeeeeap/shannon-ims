package imscore

import (
	"errors"
	"sync"
)

// protectedRuntimeHolder owns the ONE current protected TCP runtime and performs
// SA replacement.
//
// Why a holder rather than a plain field on Service: replacement has to be
// atomic with respect to readers. A field assignment would let a caller observe
// the new runtime while the old one is still pumping, or observe nil in between.
// The holder makes "which runtime is current" a single guarded value, and makes
// the switch and the teardown of the predecessor one operation.
//
// TS 33.203 clause 7.4 requires the old SA to stay usable until the new one is
// established, so the incumbent is never torn down speculatively:
//
//   - replace() adopts a candidate only if it is ready, then cancels and JOINS
//     the predecessor before returning;
//   - abandonReplacement() is the failure path: it discards the candidate and
//     leaves the incumbent serving.
//
// Joining before returning matters. If replace() returned while the old inbound
// pump was still draining, that pump could still deliver a packet decrypted with
// the retired transform, and its replay window no longer corresponds to anything
// the P-CSCF is using.
type protectedRuntimeHolder struct {
	mu      sync.Mutex
	runtime *protectedTCPRuntime
}

func newProtectedRuntimeHolder() *protectedRuntimeHolder {
	return &protectedRuntimeHolder{}
}

// errProtectedRuntimeNotReady is returned when a candidate cannot serve.
//
// Refusing is the only safe answer: adopting a runtime whose listener is down
// would leave the UE registered and unreachable, and TS 24.229 clause 3.1 NOTE 3
// gives terminating requests no alternative flow.
var errProtectedRuntimeNotReady = errors.New("imscore: protected TCP runtime is not ready to adopt")

// current returns the runtime in service, or nil.
func (h *protectedRuntimeHolder) current() *protectedTCPRuntime {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.runtime
}

// adopt installs the first runtime. It returns whatever it displaced, which must
// be nil on a first registration; a non-nil return means the caller adopted over
// a live runtime instead of calling replace.
func (h *protectedRuntimeHolder) adopt(rt *protectedTCPRuntime) *protectedTCPRuntime {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	previous := h.runtime
	h.runtime = rt
	h.mu.Unlock()
	return previous
}

// replace switches to a ready candidate and retires the predecessor.
//
// The candidate is validated BEFORE the incumbent is disturbed, so a refusal
// leaves the UE exactly as it was. The predecessor is closed and joined after
// the switch, never before: a packet in flight during the swap must find the old
// runtime still able to receive it.
func (h *protectedRuntimeHolder) replace(candidate *protectedTCPRuntime) error {
	if h == nil {
		return errors.New("imscore: protected runtime holder is nil")
	}
	if candidate == nil {
		return errProtectedRuntimeNotReady
	}
	if !candidate.Activation().ready() {
		return errProtectedRuntimeNotReady
	}

	h.mu.Lock()
	previous := h.runtime
	if previous == candidate {
		h.mu.Unlock()
		return nil
	}
	h.runtime = candidate
	h.mu.Unlock()

	// Outside the lock: Close waits for the pump, and holding the lock across a
	// join would block every reader for the duration.
	if previous != nil {
		previous.Close()
	}
	return nil
}

// abandonReplacement is the failure path. It tears the candidate down and leaves
// the incumbent in service.
//
// A failed re-registration must not cost the UE its working SA. TS 24.229
// clause 5.1.5.1 has the UE fall back to "the old set of security associations"
// when the new registration does not complete, which is only possible if the old
// runtime is still alive.
func (h *protectedRuntimeHolder) abandonReplacement(candidate *protectedTCPRuntime) {
	if candidate == nil {
		return
	}
	if h != nil {
		h.mu.Lock()
		isCurrent := h.runtime == candidate
		h.mu.Unlock()
		if isCurrent {
			// The candidate is already in service; abandoning it would leave the
			// holder empty. This is a caller error, so leave it alone rather than
			// tearing down the only runtime.
			return
		}
	}
	candidate.Close()
}

// closeCurrent retires whatever is in service and empties the holder.
func (h *protectedRuntimeHolder) closeCurrent() {
	if h == nil {
		return
	}
	h.mu.Lock()
	rt := h.runtime
	h.runtime = nil
	h.mu.Unlock()
	if rt != nil {
		rt.Close()
	}
}

// activeGeneration is the generation currently in service, or zero.
//
// Zero is the "nothing is current" sentinel that protectedTCPActivation.ready()
// already treats as never ready, so a caller cannot accidentally authorize a
// send against an empty holder.
func (h *protectedRuntimeHolder) activeGeneration() uint64 {
	rt := h.current()
	if rt == nil {
		return 0
	}
	return rt.Generation()
}
