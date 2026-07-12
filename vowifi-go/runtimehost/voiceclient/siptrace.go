package voiceclient

import (
	"os"
	"strings"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
)

type sipTraceLogger struct {
	traceID  string
	deviceID string
}

func (s sipTraceLogger) SIPTraceRead(transport string, laddr string, raddr string, sipmsg []byte) {
	logger.Info("IMS SIP read",
		logger.String("trace_id", strings.TrimSpace(s.traceID)),
		logger.String("device_id", strings.TrimSpace(s.deviceID)),
		logger.String("transport", strings.ToLower(strings.TrimSpace(transport))),
		logger.String("local_addr", laddr),
		logger.String("remote_addr", raddr),
		logger.Int("sip_bytes", len(sipmsg)))
}

func (s sipTraceLogger) SIPTraceWrite(transport string, laddr string, raddr string, sipmsg []byte) {
	logger.Info("IMS SIP write",
		logger.String("trace_id", strings.TrimSpace(s.traceID)),
		logger.String("device_id", strings.TrimSpace(s.deviceID)),
		logger.String("transport", strings.ToLower(strings.TrimSpace(transport))),
		logger.String("local_addr", laddr),
		logger.String("remote_addr", raddr),
		logger.Int("sip_bytes", len(sipmsg)))
}

func installSIPTrace(traceID, deviceID string) {
	// SIPDebug is process-global; only enable for single-session capture/debug.
	if strings.TrimSpace(os.Getenv("VOHIVE_SIP_TRACE")) == "" {
		return
	}
	sip.SIPDebug = true
	sip.SIPDebugTracer(sipTraceLogger{
		traceID:  traceID,
		deviceID: deviceID,
	})
}
