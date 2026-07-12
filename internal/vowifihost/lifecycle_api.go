package vowifihost

import (
	"context"
	"strings"
)

type LifecycleRecoverRequest struct {
	DeviceID     string
	Reason       string
	OverrideEPDG string
	Generation   uint64
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
		DeviceID:           deviceID,
		Kind:               LifecycleCommandDisable,
		Reason:             reason,
		RestoreRadio:       restoreRadio,
		RuntimeInvalidated: deviceID != "",
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
		Generation:   req.Generation,
	})
}

func (m *Manager) SwitchBegin(ctx context.Context, deviceID string) error {
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
