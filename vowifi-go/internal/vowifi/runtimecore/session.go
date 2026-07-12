package runtimecore

import (
	"strings"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

// BeginSession allocates the runtimecore session handle that runtimehost fills
// as the SWu/IMS pipeline progresses.
func BeginSession(cfg SessionConfig) *SessionResult {
	return &SessionResult{
		DeviceID: strings.TrimSpace(cfg.DeviceID),
		TraceID:  strings.TrimSpace(cfg.TraceID),
	}
}

// AttachIMSService records the registered IMS messaging service and optional
// status provider (imscore.Service.Status in the upstream module).
func AttachIMSService(result *SessionResult, svc messaging.Service, status func() map[string]interface{}, localAddr, pcscf string) {
	if result == nil {
		return
	}
	result.IMSService = svc
	result.IMSStatus = status
	result.LocalAddr = strings.TrimSpace(localAddr)
	result.PCSCFAddr = strings.TrimSpace(pcscf)
}