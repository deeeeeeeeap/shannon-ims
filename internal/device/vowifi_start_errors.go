package device

import (
	"errors"
	"strings"
	"time"

	"github.com/1239t/vohive/internal/apduarbiter"
	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/vowifihost"
	"github.com/1239t/vohive/pkg/logger"
	"github.com/1239t/vowifi-go/runtimehost"
	"github.com/1239t/vowifi-go/runtimehost/carrier"
)

func logVoWiFiFailureSummary(traceID, deviceID, stage, errorClass, reason string, retryable bool, nextRetry time.Duration) {
	if strings.TrimSpace(errorClass) == "" {
		errorClass = "unknown"
	}
	logger.Warn("VoWiFi 失败汇总",
		"trace_id", traceID,
		"device", deviceID,
		"stage", stage,
		"error_class", errorClass,
		"reason", reason,
		"retryable", retryable,
		"next_retry", nextRetry.String())
}

func (p *Pool) handleVoWiFiStartupError(traceID, deviceID, runtimeEPDGOverride string, enableStart time.Time, w *Worker, state runtimehost.State, err error) error {
	if errors.Is(err, apduarbiter.ErrAPDUBusy) {
		logger.Debug("VoWiFi 启动遇到 APDU busy，进入统一目标态恢复队列",
			"trace_id", traceID,
			"device", deviceID,
			"err", err)
		p.scheduleVoWiFiAPDUBusyRecover(deviceID, runtimeEPDGOverride)
		p.restoreNetworkAfterVoWiFiStartupFailure(traceID, deviceID, w)
		logger.Debug("EnableVoWiFi 结束（APDU busy）", "trace_id", traceID, "device", deviceID, "cost_ms", time.Since(enableStart).Milliseconds())
		return err
	}

	logger.Error("VoWiFi 启动失败", "trace_id", traceID, "device", deviceID, "err", err)
	retryable := shouldRetryVoWiFiAutoStart(err)
	nextRetry := vowifihost.DesiredRecoverDelay(0)
	if !retryable {
		nextRetry = 0
	}
	logVoWiFiFailureSummary(traceID, deviceID, "startup", state.LastErrorClass, err.Error(), retryable, nextRetry)
	p.restoreNetworkAfterVoWiFiStartupFailure(traceID, deviceID, w)
	logger.Debug("EnableVoWiFi 结束（失败）", "trace_id", traceID, "device", deviceID, "cost_ms", time.Since(enableStart).Milliseconds())
	return err
}

func (p *Pool) restoreNetworkAfterVoWiFiStartupFailure(traceID, deviceID string, w *Worker) {
	if w == nil {
		return
	}
	defer func() {
		w.restoreNetworkAfterVoWiFi = false
	}()
	nc := w.NetworkController()
	if nc == nil || !w.restoreNetworkAfterVoWiFi || w.Backend == nil {
		return
	}
	if restoreErr := w.Backend.SetOperatingMode(p.ctx, backend.ModeOnline); restoreErr != nil {
		logger.Warn("恢复射频失败", "trace_id", traceID, "device", deviceID, "err", restoreErr)
	}
	time.Sleep(500 * time.Millisecond)
	if connectErr := nc.Connect(); connectErr != nil {
		logger.Warn("恢复数据连接失败", "trace_id", traceID, "device", deviceID, "err", connectErr)
	}
}

func shouldRetryVoWiFiAutoStart(err error) bool {
	if err == nil {
		return false
	}
	return !carrier.IsVoWiFiPolicyBlockedError(err)
}

func (p *Pool) scheduleVoWiFiAPDUBusyRecover(deviceID, overrideEPDG string) {
	if p == nil {
		return
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return
	}
	if !p.desiredVoWiFiEligibility(p.GetWorker(deviceID), "apdu_busy", false) {
		return
	}
	p.voWiFiHost().ScheduleAPDUBusyRecover(p.ctx, vowifihost.APDUBusyRecoverRequest{
		DeviceID:     deviceID,
		OverrideEPDG: strings.TrimSpace(overrideEPDG),
	})
}
