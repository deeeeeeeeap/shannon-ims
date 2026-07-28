package vowifihost

import (
	"context"
	"strings"
	"time"

	"github.com/1239t/vohive/pkg/logger"
	"github.com/1239t/vowifi-go/runtimehost/carrier"
)

var apduBusyRecoverOpportunities = [...]time.Duration{
	3 * time.Second,
	5 * time.Second,
	10 * time.Second,
}

type desiredRecoverTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type desiredRecoverClock interface {
	Now() time.Time
	NewTimer(time.Duration) desiredRecoverTimer
}

type realDesiredRecoverClock struct{}

func (realDesiredRecoverClock) Now() time.Time {
	return time.Now()
}

func (realDesiredRecoverClock) NewTimer(delay time.Duration) desiredRecoverTimer {
	return realDesiredRecoverTimer{timer: time.NewTimer(delay)}
}

type realDesiredRecoverTimer struct {
	timer *time.Timer
}

func (t realDesiredRecoverTimer) C() <-chan time.Time {
	return t.timer.C
}

func (t realDesiredRecoverTimer) Stop() bool {
	return t.timer.Stop()
}

type APDUBusyRecoverRequest struct {
	DeviceID     string
	OverrideEPDG string
}

func (m *Manager) ScheduleAPDUBusyRecover(ctx context.Context, req APDUBusyRecoverRequest) bool {
	if m == nil {
		return false
	}
	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	clock := m.desiredRecoverClock()
	scheduledAt := clock.Now()
	scheduleCtx, generation, done, accepted := m.RuntimeStore().beginAPDUBusyRecoverSchedule(
		deviceID,
		ctx,
		scheduledAt,
		apduBusyRecoverOpportunities[0],
	)
	if !accepted {
		return false
	}

	go m.runAPDUBusyRecoverSchedule(scheduleCtx, APDUBusyRecoverRequest{
		DeviceID:     deviceID,
		OverrideEPDG: strings.TrimSpace(req.OverrideEPDG),
	}, generation, done, scheduledAt, clock)
	return true
}

func (m *Manager) desiredRecoverClock() desiredRecoverClock {
	if m == nil || m.recoverClock == nil {
		return realDesiredRecoverClock{}
	}
	return m.recoverClock
}

func (m *Manager) runAPDUBusyRecoverSchedule(
	ctx context.Context,
	req APDUBusyRecoverRequest,
	generation uint64,
	done chan struct{},
	scheduledAt time.Time,
	clock desiredRecoverClock,
) {
	completed := false
	defer func() {
		close(done)
		m.RuntimeStore().releaseAPDUBusyRecoverSchedule(req.DeviceID, generation, done, !completed)
	}()

	for opportunityIndex, opportunity := range apduBusyRecoverOpportunities {
		delay := scheduledAt.Add(opportunity).Sub(clock.Now())
		if delay < 0 {
			delay = 0
		}
		timer := clock.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C():
		}
		timer.Stop()
		if !m.RuntimeStore().beginAPDUBusyRecoverAttempt(req.DeviceID, generation) {
			return
		}

		logger.Warn("VoWiFi desired recover started", "event", "VOWIFI_DESIRED_RECOVER", "device", req.DeviceID, "reason", "apdu_busy")
		err := m.recoverDesired(ctx, LifecycleRecoverRequest{
			DeviceID:     req.DeviceID,
			Reason:       "apdu_busy",
			OverrideEPDG: req.OverrideEPDG,
		}, generation)
		if ctx.Err() != nil {
			return
		}
		result := desiredRecoverSucceeded
		if err != nil {
			result = desiredRecoverFailed
			if carrier.IsVoWiFiPolicyBlockedError(err) {
				result = desiredRecoverPolicyBlocked
			}
		}
		if result == desiredRecoverFailed && opportunityIndex+1 < len(apduBusyRecoverOpportunities) {
			nextAt := scheduledAt.Add(apduBusyRecoverOpportunities[opportunityIndex+1])
			if !m.RuntimeStore().deferAPDUBusyRecoverAttempt(req.DeviceID, generation, clock.Now(), nextAt) {
				return
			}
			continue
		}

		snapshot, current := m.RuntimeStore().finishDesiredRecover(req.DeviceID, generation, clock.Now(), result)
		if !current {
			return
		}
		completed = true
		switch result {
		case desiredRecoverSucceeded:
			logger.Info("VoWiFi desired recover succeeded", "event", "VOWIFI_DESIRED_RECOVER_SUCCESS", "device", req.DeviceID)
		case desiredRecoverPolicyBlocked:
			logger.Warn("VoWiFi desired recover stopped by policy", "event", "VOWIFI_DESIRED_RECOVER_SKIPPED_POLICY", "device", req.DeviceID)
		case desiredRecoverFailed:
			logger.Warn("VoWiFi desired recover backed off", "event", "VOWIFI_DESIRED_RETRY_DELAY", "device", req.DeviceID, "attempt", snapshot.Attempt, "delay", snapshot.Delay.String())
		}
		return
	}
}

func (s *Store) beginAPDUBusyRecoverSchedule(
	deviceID string,
	ctx context.Context,
	now time.Time,
	firstDelay time.Duration,
) (context.Context, uint64, chan struct{}, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" || firstDelay <= 0 {
		return ctx, 0, nil, false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if now.IsZero() {
		now = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.ensureSlotLocked(deviceID)
	if slot.instance != nil || slot.recoverPresent || slot.recoverInFlight || slot.recoverScheduleDone != nil {
		return ctx, 0, nil, false
	}
	scheduleCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	slot.recoverGeneration++
	slot.recoverAttempt = 0
	slot.recoverNextAt = now.Add(firstDelay)
	slot.recoverInFlight = false
	slot.recoverDelay = firstDelay
	slot.recoverPresent = true
	slot.recoverScheduleCancel = cancel
	slot.recoverScheduleDone = done
	return scheduleCtx, slot.recoverGeneration, done, true
}

func (s *Store) beginAPDUBusyRecoverAttempt(deviceID string, generation uint64) bool {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" || generation == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.slots[deviceID]
	if slot == nil || slot.instance != nil || !slot.recoverPresent || slot.recoverInFlight || slot.recoverGeneration != generation || slot.recoverScheduleDone == nil {
		return false
	}
	slot.recoverInFlight = true
	slot.recoverNextAt = time.Time{}
	slot.recoverDelay = 0
	return true
}

func (s *Store) deferAPDUBusyRecoverAttempt(deviceID string, generation uint64, now, nextAt time.Time) bool {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" || generation == 0 || nextAt.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.slots[deviceID]
	if slot == nil || !slot.recoverPresent || !slot.recoverInFlight || slot.recoverGeneration != generation || slot.recoverScheduleDone == nil {
		return false
	}
	delay := nextAt.Sub(now)
	if delay < 0 {
		delay = 0
	}
	slot.recoverInFlight = false
	slot.recoverNextAt = nextAt
	slot.recoverDelay = delay
	return true
}

func (s *Store) releaseAPDUBusyRecoverSchedule(deviceID string, generation uint64, done chan struct{}, clearState bool) {
	deviceID = strings.TrimSpace(deviceID)
	if s == nil || deviceID == "" || generation == 0 || done == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.slots[deviceID]
	if slot == nil || slot.recoverScheduleDone != done {
		return
	}
	slot.recoverScheduleCancel = nil
	slot.recoverScheduleDone = nil
	if clearState && slot.recoverGeneration == generation {
		slot.recoverGeneration++
		resetDesiredRecoverLocked(slot)
	}
}
