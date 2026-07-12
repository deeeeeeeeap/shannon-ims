package vowifihost

import (
	"strings"
	"sync"
	"time"
)

type DesiredRecoverStore struct {
	mu     sync.Mutex
	states map[string]*desiredRecoverState
}

type desiredRecoverState struct {
	attempt  int
	nextAt   time.Time
	inFlight bool
	lastErr  string
}

type DesiredRecoverSnapshot struct {
	Attempt  int
	NextAt   time.Time
	InFlight bool
	LastErr  string
	Delay    time.Duration
}

func NewDesiredRecoverStore() *DesiredRecoverStore {
	return &DesiredRecoverStore{states: make(map[string]*desiredRecoverState)}
}

func DesiredRecoverDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 30 * time.Second
	}
	if attempt == 1 {
		return time.Minute
	}
	return 2 * time.Minute
}

func (m *Manager) BeginDesiredRecover(deviceID string, now time.Time) bool {
	return m.desiredRecoverStore().Begin(deviceID, now)
}

func (m *Manager) MarkDesiredRecoverFailed(deviceID string, now time.Time, err error) DesiredRecoverSnapshot {
	return m.desiredRecoverStore().MarkFailed(deviceID, now, err)
}

func (m *Manager) ClearDesiredRecoverState(deviceID string) {
	m.desiredRecoverStore().Clear(deviceID)
}

func (m *Manager) HasDesiredRecoverState(deviceID string) bool {
	_, ok := m.desiredRecoverStore().Snapshot(deviceID)
	return ok
}

func (m *Manager) DesiredRecoverState(deviceID string) (DesiredRecoverSnapshot, bool) {
	return m.desiredRecoverStore().Snapshot(deviceID)
}

func (s *DesiredRecoverStore) Begin(deviceID string, now time.Time) bool {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.ensureLocked(deviceID)
	if st.inFlight || now.Before(st.nextAt) {
		return false
	}
	st.inFlight = true
	return true
}

func (s *DesiredRecoverStore) MarkFailed(deviceID string, now time.Time, err error) DesiredRecoverSnapshot {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return DesiredRecoverSnapshot{}
	}
	if now.IsZero() {
		now = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.ensureLocked(deviceID)
	delay := DesiredRecoverDelay(st.attempt)
	st.attempt++
	st.nextAt = now.Add(delay)
	st.inFlight = false
	if err != nil {
		st.lastErr = err.Error()
	}
	return snapshotFromRecoverState(st, delay)
}

func (s *DesiredRecoverStore) Clear(deviceID string) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return
	}
	s.mu.Lock()
	delete(s.states, deviceID)
	s.mu.Unlock()
}

func (s *DesiredRecoverStore) Snapshot(deviceID string) (DesiredRecoverSnapshot, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return DesiredRecoverSnapshot{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.states[deviceID]
	if st == nil {
		return DesiredRecoverSnapshot{}, false
	}
	return snapshotFromRecoverState(st, 0), true
}

func (s *DesiredRecoverStore) ensureLocked(deviceID string) *desiredRecoverState {
	if s.states == nil {
		s.states = make(map[string]*desiredRecoverState)
	}
	st := s.states[deviceID]
	if st == nil {
		st = &desiredRecoverState{}
		s.states[deviceID] = st
	}
	return st
}

func snapshotFromRecoverState(st *desiredRecoverState, delay time.Duration) DesiredRecoverSnapshot {
	if st == nil {
		return DesiredRecoverSnapshot{}
	}
	return DesiredRecoverSnapshot{
		Attempt:  st.attempt,
		NextAt:   st.nextAt,
		InFlight: st.inFlight,
		LastErr:  st.lastErr,
		Delay:    delay,
	}
}
