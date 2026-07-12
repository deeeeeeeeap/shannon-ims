package runtimehost

import (
	"time"

	"github.com/1239t/vowifi-go/internal/vowifi/runtimecore"
)

func toRuntimecoreSessionConfig(req StartRequest) runtimecore.SessionConfig {
	var proxy *runtimecore.ProxyConfig
	if req.Proxy != nil {
		proxy = &runtimecore.ProxyConfig{
			ID:       req.Proxy.ID,
			Addr:     req.Proxy.Addr,
			Username: req.Proxy.Username,
			Password: req.Proxy.Password,
			Enabled:  req.Proxy.Enabled,
		}
	}
	var expiry int64
	if req.RegisterExpiry > 0 {
		expiry = int64(req.RegisterExpiry / time.Second)
	}
	return runtimecore.SessionConfig{
		DeviceID:        req.DeviceID,
		TraceID:         req.TraceID,
		Prepared:        req.Prepared,
		Profile:         req.Profile,
		NetworkMode:     req.NetworkMode,
		DataplaneMode:   req.Dataplane.Mode,
		Proxy:           proxy,
		PCSCFAddr:       req.PCSCFAddr,
		CellID:          req.CellID,
		RegisterProfile: req.RegisterProfile,
		SIPInstanceURN:  req.SIPInstanceURN,
		RegisterExpiry:  expiry,
		DeliveryStore:   req.DeliveryStore,
	}
}