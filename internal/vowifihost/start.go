package vowifihost

import (
	"strings"

	"github.com/1239t/vohive/pkg/logger"
	"github.com/1239t/vowifi-go/runtimehost"
)

func (m *Manager) BeginStart(deviceID string) StartClaim {
	if m == nil {
		return StartClaim{}
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return StartClaim{}
	}
	return m.RuntimeStore().BeginStart(deviceID)
}

func (m *Manager) FailStart(deviceID string, epoch uint64, state runtimehost.State, err error) {
	if m == nil {
		return
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return
	}
	m.RuntimeStore().FailStart(deviceID, epoch, state, err)
}

func (m *Manager) CurrentEpoch(deviceID string) uint64 {
	if m == nil {
		return 0
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return 0
	}
	return m.RuntimeStore().CurrentEpoch(deviceID)
}

func (m *Manager) ShouldRun(deviceID string, epoch uint64) bool {
	return m.CurrentEpoch(deviceID) == epoch
}

func (m *Manager) ClaimStarted(deviceID string, epoch uint64, inst *runtimehost.Instance) bool {
	if m == nil || inst == nil {
		return false
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return false
	}
	if !m.RuntimeStore().ClaimStarted(deviceID, epoch, inst) {
		logger.Info("discard stale VoWiFi runtime start result",
			"device", deviceID,
			"startup_epoch", epoch,
			"current_epoch", m.CurrentEpoch(deviceID))
		return false
	}
	return true
}
