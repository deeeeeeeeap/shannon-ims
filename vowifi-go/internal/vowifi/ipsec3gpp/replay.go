package ipsec3gpp

import (
	"sync"
)

const defaultReplayWindowSize uint32 = 64

// ReplayWindow implements a fixed-size anti-replay check for ESP sequence numbers.
type ReplayWindow struct {
	mu          sync.Mutex
	size        uint32
	initialized bool
	highest     uint32
	bitmap      uint64
	stats       ReplayStats
}

// NewReplayWindow creates a replay window. Zero size defaults to 64 packets.
func NewReplayWindow(size uint32) *ReplayWindow {
	if size == 0 {
		size = defaultReplayWindowSize
	}
	if size > 64 {
		size = 64
	}
	return &ReplayWindow{size: size}
}

// Accept returns true when seq is new and inside the replay window.
func (w *ReplayWindow) Accept(seq uint32) bool {
	if w == nil {
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.initialized {
		w.initialized = true
		w.highest = seq
		w.bitmap = 1
		w.stats.Accepted++
		return true
	}

	if seq == 0 {
		w.stats.TooOld++
		return false
	}

	if seq > w.highest {
		shift := seq - w.highest
		if shift >= w.size {
			w.bitmap = 1
		} else {
			w.bitmap <<= shift
			w.bitmap |= 1
		}
		w.highest = seq
		w.stats.Accepted++
		return true
	}

	delta := w.highest - seq
	if delta >= w.size {
		w.stats.TooOld++
		return false
	}
	mask := uint64(1) << delta
	if w.bitmap&mask != 0 {
		w.stats.Duplicate++
		return false
	}
	w.bitmap |= mask
	w.stats.Accepted++
	return true
}

// Snapshot returns a copy of replay statistics.
func (w *ReplayWindow) Snapshot() ReplayStats {
	if w == nil {
		return ReplayStats{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stats
}