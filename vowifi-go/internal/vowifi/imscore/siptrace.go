package imscore

import (
	"os"
	"strings"

	"github.com/emiago/sipgo/sip"
)

type sipTraceLogger struct {
	traceID  string
	deviceID string
}

func (s sipTraceLogger) SIPTraceRead(transport string, laddr string, raddr string, sipmsg []byte) {
	_ = s
	_ = laddr
	_ = sipmsg
	logRegisterDiagnostic(registerDiagnostic{
		stage:         "sip_read",
		result:        "none",
		transport:     transport,
		addressFamily: registerAddressFamily(raddr),
	})
}

func (s sipTraceLogger) SIPTraceWrite(transport string, laddr string, raddr string, sipmsg []byte) {
	_ = s
	_ = laddr
	_ = sipmsg
	logRegisterDiagnostic(registerDiagnostic{
		stage:         "sip_write",
		result:        "none",
		transport:     transport,
		addressFamily: registerAddressFamily(raddr),
	})
}

func installSIPTrace(traceID, deviceID string) {
	if strings.TrimSpace(os.Getenv("VOHIVE_SIP_TRACE")) == "" {
		return
	}
	sip.SIPDebug = true
	sip.SIPDebugTracer(sipTraceLogger{
		traceID:  traceID,
		deviceID: deviceID,
	})
}

func logRegisterRouting(cfg Config, req *sip.Request) {
	if req == nil {
		return
	}
	logRegisterDiagnostic(registerDiagnostic{
		stage:            "request_prepared",
		result:           "none",
		transport:        req.Transport(),
		addressFamily:    registerAddressFamily(effectiveTransportAddr(cfg)),
		hasRequire:       req.GetHeader("Require") != nil,
		requiresSecAgree: req.GetHeader("Require") != nil || req.GetHeader("Proxy-Require") != nil,
	})
}
