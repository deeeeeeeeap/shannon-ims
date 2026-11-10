package device

import (
	"strings"

	"github.com/1239t/vohive/internal/upstreamproxy"
	"github.com/1239t/vohive/pkg/logger"
)

// voWiFiProxyProbeRetry bounds the proxy self-check that precedes a VoWiFi
// start. The zero value selects the probe's defaults: up to three attempts
// within twelve seconds.
var voWiFiProxyProbeRetry upstreamproxy.ProbeRetryPolicy

// logVoWiFiProxyProbe records how the proxy self-check went. The proxy is
// named by its ID; its address and credentials stay out of the log, which
// is why a failure is logged by stage and diagnosis and not by its error.
func logVoWiFiProxyProbe(deviceID, proxyID string, result upstreamproxy.ProbeResult, err error) {
	if err != nil {
		logger.Warn("VoWiFi 前置代理自检失败",
			"device", deviceID,
			"upstream_proxy_id", proxyID,
			"stage", result.Stage,
			"diagnosis", result.Diagnosis,
			"hint", result.Hint,
			"attempts", result.Attempts,
			"duration_ms", result.DurationMS)
		return
	}
	logger.Info("VoWiFi 前置代理自检通过",
		"device", deviceID,
		"upstream_proxy_id", proxyID,
		"auth_method", result.AuthMethod,
		"credentials_ignored", result.CredentialsIgnored,
		"relay_adjustment", result.RelayAdjustment,
		"warnings", strings.Join(result.Warnings, "；"),
		"attempts", result.Attempts,
		"duration_ms", result.DurationMS)
}
