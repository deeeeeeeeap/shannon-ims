package vowifihost

import (
	"context"
	"strings"
)

type LifecycleRecoverRequest struct {
	DeviceID     string
	Reason       string
	OverrideEPDG string
}

func (m *Manager) Enable(ctx context.Context, deviceID string) error {
	return m.SubmitLifecycle(ctx, LifecycleCommand{
		DeviceID: deviceID,
		Kind:     LifecycleCommandEnable,
		Reason:   "enable",
	})
}

func (m *Manager) Disable(ctx context.Context, deviceID, reason string, restoreRadio bool) error {
	deviceID = strings.TrimSpace(deviceID)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "disable"
	}
	if deviceID != "" {
		m.InvalidateRuntime(deviceID, reason)
	}
	return m.SubmitLifecycle(ctx, LifecycleCommand{
		DeviceID:     deviceID,
		Kind:         LifecycleCommandDisable,
		Reason:       reason,
		RestoreRadio: restoreRadio,
	})
}

func (m *Manager) Restart(ctx context.Context, deviceID string) error {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID != "" {
		m.InvalidateRuntime(deviceID, "restart")
	}
	return m.SubmitLifecycle(ctx, LifecycleCommand{
		DeviceID: deviceID,
		Kind:     LifecycleCommandRestart,
		Reason:   "restart",
	})
}

func (m *Manager) Recover(ctx context.Context, req LifecycleRecoverRequest) error {
	return m.SubmitLifecycle(ctx, LifecycleCommand{
		DeviceID:     req.DeviceID,
		Kind:         LifecycleCommandRecover,
		Reason:       req.Reason,
		OverrideEPDG: req.OverrideEPDG,
	})
}

func (m *Manager) recoverDesired(ctx context.Context, req LifecycleRecoverRequest, recoverGeneration uint64) error {
	return m.SubmitLifecycle(ctx, LifecycleCommand{
		DeviceID:                 req.DeviceID,
		Kind:                     LifecycleCommandRecover,
		Reason:                   req.Reason,
		OverrideEPDG:             req.OverrideEPDG,
		desiredRecoverGeneration: recoverGeneration,
	})
}

func (m *Manager) SwitchBegin(ctx context.Context, deviceID string) error {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID != "" {
		m.InvalidateRuntime(deviceID, "switch")
	}
	return m.SubmitLifecycle(ctx, LifecycleCommand{
		DeviceID: deviceID,
		Kind:     LifecycleCommandSwitchBegin,
	})
}

func (m *Manager) SwitchEnd(ctx context.Context, deviceID string, restoreRadio bool) error {
	return m.SubmitLifecycle(ctx, LifecycleCommand{
		DeviceID:     deviceID,
		Kind:         LifecycleCommandSwitchEnd,
		RestoreRadio: restoreRadio,
	})
}
