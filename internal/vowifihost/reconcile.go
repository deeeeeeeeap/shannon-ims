package vowifihost

import (
	"context"
	"strings"
	"time"

	"github.com/1239t/vohive/pkg/logger"
	"github.com/1239t/vowifi-go/runtimehost/carrier"
)

const defaultDesiredRecoverReason = "desired_reconcile"

type DesiredRecoverRequest struct {
	DeviceID     string
	Reason       string
	OverrideEPDG string
	Now          time.Time
}

func (m *Manager) DesiredRecoverable(deviceID string) bool {
	if m == nil {
		return false
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return false
	}
	store := m.RuntimeStore()
	return !store.Active(deviceID) && !store.Starting(deviceID)
}

func (m *Manager) ScheduleDesiredRecover(ctx context.Context, req DesiredRecoverRequest) bool {
	if m == nil {
		return false
	}
	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		return false
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = defaultDesiredRecoverReason
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	recoverGeneration, accepted := m.RuntimeStore().beginDesiredRecover(deviceID, now)
	if !accepted {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}

	logger.Warn("VoWiFi desired recover started", "event", "VOWIFI_DESIRED_RECOVER", "device", deviceID, "reason", reason)
	go func() {
		err := m.recoverDesired(ctx, LifecycleRecoverRequest{
			DeviceID:     deviceID,
			Reason:       reason,
			OverrideEPDG: req.OverrideEPDG,
		}, recoverGeneration)
		result := desiredRecoverSucceeded
		if err != nil {
			result = desiredRecoverFailed
			if carrier.IsVoWiFiPolicyBlockedError(err) {
				result = desiredRecoverPolicyBlocked
			}
		}
		snapshot, current := m.RuntimeStore().finishDesiredRecover(deviceID, recoverGeneration, time.Now(), result)
		if !current {
			return
		}
		switch result {
		case desiredRecoverSucceeded:
			logger.Info("VoWiFi desired recover succeeded", "event", "VOWIFI_DESIRED_RECOVER_SUCCESS", "device", deviceID)
		case desiredRecoverPolicyBlocked:
			logger.Warn("VoWiFi desired recover stopped by policy", "event", "VOWIFI_DESIRED_RECOVER_SKIPPED_POLICY", "device", deviceID)
		case desiredRecoverFailed:
			logger.Warn("VoWiFi desired recover backed off", "event", "VOWIFI_DESIRED_RETRY_DELAY", "device", deviceID, "attempt", snapshot.Attempt, "delay", snapshot.Delay.String())
		}
	}()
	return true
}
