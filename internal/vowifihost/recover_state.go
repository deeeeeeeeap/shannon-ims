package vowifihost

import (
	"strings"
	"time"
)

type DesiredRecoverSnapshot struct {
	Attempt  int
	NextAt   time.Time
	InFlight bool
	Delay    time.Duration
}

type desiredRecoverResult uint8

const (
	desiredRecoverSucceeded desiredRecoverResult = iota + 1
	desiredRecoverPolicyBlocked
	desiredRecoverFailed
)

func DesiredRecoverDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 30 * time.Second
	}
	if attempt == 1 {
		return time.Minute
	}
	return 2 * time.Minute
}

func (m *Manager) ForgetDesiredRecover(deviceID string) {
	if m != nil {
		m.RuntimeStore().forgetDesiredRecover(deviceID)
	}
}

func (m *Manager) HasDesiredRecoverState(deviceID string) bool {
	_, ok := m.DesiredRecoverState(deviceID)
	return ok
}

func (m *Manager) DesiredRecoverState(deviceID string) (DesiredRecoverSnapshot, bool) {
	if m == nil {
		return DesiredRecoverSnapshot{}, false
	}
	return m.RuntimeStore().desiredRecoverState(deviceID)
}

func (s *Store) beginDesiredRecover(deviceID string, now time.Time) (uint64, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return 0, false
	}
	if now.IsZero() {
		now = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.ensureSlotLocked(deviceID)
	if slot.instance != nil || slot.starting {
		return 0, false
	}
	if slot.recoverScheduleDone != nil || slot.recoverInFlight || now.Before(slot.recoverNextAt) {
		return 0, false
	}
	slot.recoverGeneration++
	slot.recoverInFlight = true
	slot.recoverPresent = true
	slot.recoverDelay = 0
	return slot.recoverGeneration, true
}

func (s *Store) finishDesiredRecover(deviceID string, generation uint64, now time.Time, result desiredRecoverResult) (DesiredRecoverSnapshot, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" || generation == 0 {
		return DesiredRecoverSnapshot{}, false
	}
	if now.IsZero() {
		now = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.slots[deviceID]
	if slot == nil || !slot.recoverInFlight || slot.recoverGeneration != generation {
		return DesiredRecoverSnapshot{}, false
	}
	switch result {
	case desiredRecoverSucceeded, desiredRecoverPolicyBlocked:
		resetDesiredRecoverLocked(slot)
		return DesiredRecoverSnapshot{}, true
	case desiredRecoverFailed:
		delay := DesiredRecoverDelay(slot.recoverAttempt)
		slot.recoverAttempt++
		slot.recoverNextAt = now.Add(delay)
		slot.recoverInFlight = false
		slot.recoverPresent = true
		slot.recoverDelay = delay
		return desiredRecoverSnapshot(slot), true
	default:
		return DesiredRecoverSnapshot{}, false
	}
}

func (s *Store) forgetDesiredRecover(deviceID string) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return
	}

	s.mu.Lock()
	slot := s.slots[deviceID]
	if slot == nil || (!slot.recoverPresent && !slot.recoverInFlight && slot.recoverScheduleDone == nil) {
		s.mu.Unlock()
		return
	}
	activeGeneration := slot.recoverGeneration
	slot.recoverGeneration++
	resetDesiredRecoverLocked(slot)
	scheduleCancel := slot.recoverScheduleCancel
	scheduleDone := slot.recoverScheduleDone
	slot.recoverScheduleCancel = nil
	slot.recoverScheduleDone = nil
	var cancel func()
	if slot.runKind == LifecycleCommandRecover && slot.runRecoverGeneration == activeGeneration {
		cancel = slot.runCancel
		slot.runCancel = nil
		slot.runKind = 0
		slot.runRecoverGeneration = 0
	}
	s.mu.Unlock()
	if scheduleCancel != nil {
		scheduleCancel()
	}
	if cancel != nil {
		cancel()
	}
	if scheduleDone != nil {
		<-scheduleDone
	}
}

func (s *Store) desiredRecoverCurrent(deviceID string, generation uint64) bool {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" || generation == 0 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	slot := s.slots[deviceID]
	return slot != nil && slot.recoverPresent && slot.recoverInFlight && slot.recoverGeneration == generation
}

func (s *Store) desiredRecoverState(deviceID string) (DesiredRecoverSnapshot, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return DesiredRecoverSnapshot{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	slot := s.slots[deviceID]
	if slot == nil || !slot.recoverPresent {
		return DesiredRecoverSnapshot{}, false
	}
	return desiredRecoverSnapshot(slot), true
}

func resetDesiredRecoverLocked(slot *runtimeSlot) {
	if slot == nil {
		return
	}
	slot.recoverAttempt = 0
	slot.recoverNextAt = time.Time{}
	slot.recoverInFlight = false
	slot.recoverDelay = 0
	slot.recoverPresent = false
}

func desiredRecoverSnapshot(slot *runtimeSlot) DesiredRecoverSnapshot {
	if slot == nil {
		return DesiredRecoverSnapshot{}
	}
	return DesiredRecoverSnapshot{
		Attempt:  slot.recoverAttempt,
		NextAt:   slot.recoverNextAt,
		InFlight: slot.recoverInFlight,
		Delay:    slot.recoverDelay,
	}
}
