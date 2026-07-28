package vowifihost

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/1239t/vowifi-go/runtimehost"
)

type Store struct {
	mu               sync.RWMutex
	slots            map[string]*runtimeSlot
	nextSubscriberID uint64
	subscribers      map[string]map[uint64]chan struct{}
}

type runtimeSlot struct {
	instance              *runtimehost.Instance
	starting              bool
	epoch                 uint64
	lifecycleGeneration   uint64
	runCancel             context.CancelFunc
	runCancelSequence     uint64
	runKind               LifecycleCommandKind
	runRecoverGeneration  uint64
	recoverGeneration     uint64
	recoverAttempt        int
	recoverNextAt         time.Time
	recoverInFlight       bool
	recoverDelay          time.Duration
	recoverPresent        bool
	recoverScheduleCancel context.CancelFunc
	recoverScheduleDone   chan struct{}
	state                 runtimehost.State
	updatedAt             time.Time
}

func (s *Store) admitLifecycle(deviceID string, kind LifecycleCommandKind) (uint64, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.ensureSlotLocked(deviceID)
	if kind == LifecycleCommandEnable && (slot.instance != nil || slot.starting) {
		return slot.lifecycleGeneration, false
	}
	slot.lifecycleGeneration++
	return slot.lifecycleGeneration, true
}

func (s *Store) preemptLifecycle(deviceID string) (uint64, context.CancelFunc) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return 0, nil
	}
	s.mu.Lock()
	slot := s.ensureSlotLocked(deviceID)
	slot.lifecycleGeneration++
	generation := slot.lifecycleGeneration
	cancel := slot.runCancel
	slot.runCancel = nil
	slot.runKind = 0
	slot.runRecoverGeneration = 0
	s.mu.Unlock()
	return generation, cancel
}

func (s *Store) currentLifecycleGeneration(deviceID string) uint64 {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if slot := s.slots[deviceID]; slot != nil {
		return slot.lifecycleGeneration
	}
	return 0
}

func (s *Store) bindLifecycleRun(ctx context.Context, deviceID string, generation uint64, kind LifecycleCommandKind, recoverGeneration uint64) (context.Context, func(), bool) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" || generation == 0 {
		return ctx, func() {}, false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)

	s.mu.Lock()
	slot := s.slots[deviceID]
	if slot == nil || slot.lifecycleGeneration != generation {
		s.mu.Unlock()
		cancel()
		return ctx, func() {}, false
	}
	slot.runCancelSequence++
	sequence := slot.runCancelSequence
	slot.runCancel = cancel
	slot.runKind = kind
	slot.runRecoverGeneration = recoverGeneration
	s.mu.Unlock()

	return runCtx, func() {
		s.mu.Lock()
		if slot := s.slots[deviceID]; slot != nil && slot.runCancelSequence == sequence {
			slot.runCancel = nil
			slot.runKind = 0
			slot.runRecoverGeneration = 0
		}
		s.mu.Unlock()
	}, true
}

type StartClaim struct {
	Epoch    uint64
	Accepted bool
	Active   bool
	Starting bool
}

func NewRuntimeStore() *Store {
	return &Store{
		slots:       make(map[string]*runtimeSlot),
		subscribers: make(map[string]map[uint64]chan struct{}),
	}
}

func (s *Store) Subscribe(deviceID string) (<-chan struct{}, func()) {
	deviceID = strings.TrimSpace(deviceID)
	updates := make(chan struct{}, 1)
	if s == nil || deviceID == "" {
		return updates, func() {}
	}

	s.mu.Lock()
	if s.subscribers == nil {
		s.subscribers = make(map[string]map[uint64]chan struct{})
	}
	s.nextSubscriberID++
	subscriberID := s.nextSubscriberID
	if s.subscribers[deviceID] == nil {
		s.subscribers[deviceID] = make(map[uint64]chan struct{})
	}
	s.subscribers[deviceID][subscriberID] = updates
	s.mu.Unlock()

	return updates, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if subscribers := s.subscribers[deviceID]; subscribers != nil {
			delete(subscribers, subscriberID)
			if len(subscribers) == 0 {
				delete(s.subscribers, deviceID)
			}
		}
	}
}

func (s *Store) SubscriberCount(deviceID string) int {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subscribers[deviceID])
}

func (s *Store) Broadcast(deviceID string) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifyLocked(deviceID)
}

func (s *Store) notifyLocked(deviceID string) {
	for _, updates := range s.subscribers[deviceID] {
		select {
		case updates <- struct{}{}:
		default:
		}
	}
}

func (s *Store) ensureSlotLocked(deviceID string) *runtimeSlot {
	if s.slots == nil {
		s.slots = make(map[string]*runtimeSlot)
	}
	slot := s.slots[deviceID]
	if slot == nil {
		slot = &runtimeSlot{}
		s.slots[deviceID] = slot
	}
	return slot
}

func (s *Store) BeginStart(deviceID string) StartClaim {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return StartClaim{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.ensureSlotLocked(deviceID)
	if slot.instance != nil {
		return StartClaim{Epoch: slot.epoch, Active: true}
	}
	if slot.starting {
		return StartClaim{Epoch: slot.epoch, Starting: true}
	}
	slot.starting = true
	slot.updatedAt = time.Now()
	return StartClaim{Epoch: slot.epoch, Accepted: true}
}

func (s *Store) ClaimStarted(deviceID string, epoch uint64, inst *runtimehost.Instance) bool {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" || inst == nil {
		return false
	}
	s.mu.Lock()
	slot := s.ensureSlotLocked(deviceID)
	if slot.epoch != epoch || !slot.starting {
		s.mu.Unlock()
		return false
	}
	if slot.instance != nil {
		s.mu.Unlock()
		return false
	}
	currentAPDUScheduleRun := slot.recoverScheduleDone != nil &&
		slot.runKind == LifecycleCommandRecover &&
		slot.runRecoverGeneration == slot.recoverGeneration
	var scheduleCancel context.CancelFunc
	slot.instance = inst
	slot.starting = false
	if (slot.recoverPresent || slot.recoverInFlight || slot.recoverScheduleDone != nil) && !currentAPDUScheduleRun {
		scheduleCancel = slot.recoverScheduleCancel
		slot.recoverGeneration++
		resetDesiredRecoverLocked(slot)
	}
	slot.state = runtimehost.State{}
	slot.updatedAt = time.Now()
	s.notifyLocked(deviceID)
	s.mu.Unlock()
	if scheduleCancel != nil {
		scheduleCancel()
	}
	return true
}

func (s *Store) FailStart(deviceID string, epoch uint64, state runtimehost.State, _ error) bool {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.ensureSlotLocked(deviceID)
	if slot.epoch != epoch || !slot.starting {
		return false
	}
	slot.starting = false
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now()
	}
	slot.state = state
	slot.updatedAt = time.Now()
	s.notifyLocked(deviceID)
	return true
}

func (s *Store) RecordStartupState(deviceID string, state runtimehost.State) bool {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return false
	}
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.ensureSlotLocked(deviceID)
	if slot.instance != nil || !slot.starting {
		return false
	}
	if !slot.state.UpdatedAt.IsZero() && state.UpdatedAt.Before(slot.state.UpdatedAt) {
		return false
	}
	slot.state = state
	slot.updatedAt = state.UpdatedAt
	s.notifyLocked(deviceID)
	return true
}

func (s *Store) publishRuntimeState(deviceID string, epoch uint64, inst *runtimehost.Instance, state runtimehost.State) bool {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" || inst == nil {
		return false
	}
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.slots[deviceID]
	if slot == nil || slot.epoch != epoch {
		return false
	}
	if slot.instance != nil {
		if slot.instance != inst {
			return false
		}
		s.notifyLocked(deviceID)
		return true
	}
	if !slot.starting {
		return false
	}
	if !slot.state.UpdatedAt.IsZero() && state.UpdatedAt.Before(slot.state.UpdatedAt) {
		return false
	}
	slot.state = state
	slot.updatedAt = state.UpdatedAt
	s.notifyLocked(deviceID)
	return true
}

func (s *Store) ClearStartupState(deviceID string) bool {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.slots[deviceID]
	if slot == nil || slot.state.UpdatedAt.IsZero() {
		return false
	}
	slot.starting = false
	slot.state = runtimehost.State{}
	slot.updatedAt = time.Now()
	s.notifyLocked(deviceID)
	if slot.instance == nil && !slot.starting && slot.recoverGeneration == 0 {
		delete(s.slots, deviceID)
	}
	return true
}

func (s *Store) Invalidate(deviceID string) (uint64, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return 0, false
	}
	s.mu.Lock()
	slot := s.ensureSlotLocked(deviceID)
	cancel := slot.runCancel
	slot.runCancel = nil
	slot.runKind = 0
	slot.runRecoverGeneration = 0
	slot.epoch++
	slot.starting = false
	hadState := !slot.state.UpdatedAt.IsZero()
	slot.state = runtimehost.State{}
	slot.updatedAt = time.Now()
	if hadState {
		s.notifyLocked(deviceID)
	}
	epoch := slot.epoch
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return epoch, hadState
}

func (s *Store) CurrentEpoch(deviceID string) uint64 {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if slot := s.slots[deviceID]; slot != nil {
		return slot.epoch
	}
	return 0
}

func (s *Store) Active(deviceID string) bool {
	return s.Instance(deviceID) != nil
}

func (s *Store) Starting(deviceID string) bool {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if slot := s.slots[deviceID]; slot != nil {
		return slot.starting
	}
	return false
}

func (s *Store) Instance(deviceID string) *runtimehost.Instance {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if slot := s.slots[deviceID]; slot != nil {
		return slot.instance
	}
	return nil
}

func (s *Store) SetInstance(deviceID string, inst *runtimehost.Instance) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.ensureSlotLocked(deviceID)
	slot.instance = inst
	slot.starting = false
	if slot.recoverPresent || slot.recoverInFlight {
		slot.recoverGeneration++
		resetDesiredRecoverLocked(slot)
	}
	slot.state = runtimehost.State{}
	slot.updatedAt = time.Now()
	s.notifyLocked(deviceID)
}

func (s *Store) DeleteInstance(deviceID string, inst *runtimehost.Instance) bool {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.slots[deviceID]
	if slot == nil || slot.instance == nil {
		return false
	}
	if inst != nil && slot.instance != inst {
		return false
	}
	slot.instance = nil
	slot.starting = false
	slot.state = runtimehost.State{}
	slot.updatedAt = time.Now()
	s.notifyLocked(deviceID)
	if slot.epoch == 0 && slot.recoverGeneration == 0 {
		delete(s.slots, deviceID)
	}
	return true
}

func (s *Store) State(deviceID string) (runtimehost.State, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" {
		return runtimehost.State{}, false
	}
	s.mu.RLock()
	slot := s.slots[deviceID]
	if slot == nil {
		s.mu.RUnlock()
		return runtimehost.State{}, false
	}
	inst := slot.instance
	state := slot.state
	hasState := !state.UpdatedAt.IsZero() || state.Phase != "" || slot.starting
	s.mu.RUnlock()
	if inst != nil {
		return inst.State(), true
	}
	if hasState {
		return state, true
	}
	return runtimehost.State{}, false
}

func (s *Store) Instances() map[string]*runtimehost.Instance {
	out := make(map[string]*runtimehost.Instance)
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for deviceID, slot := range s.slots {
		if slot != nil && slot.instance != nil {
			out[deviceID] = slot.instance
		}
	}
	return out
}

func (s *Store) InstanceIDs() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.slots))
	for deviceID, slot := range s.slots {
		if slot != nil && slot.instance != nil {
			ids = append(ids, deviceID)
		}
	}
	return ids
}
