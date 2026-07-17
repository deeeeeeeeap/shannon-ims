package imscore

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
	route := ""
	if h := req.GetHeader("Route"); h != nil {
		route = strings.TrimSpace(h.Value())
	}
	logger.Info("IMS REGISTER routing",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
		logger.String("registrar", strings.TrimSpace(cfg.PCSCFAddr)),
		logger.String("transport_target", effectiveTransportAddr(cfg)),
		logger.String("ipsec_gateway", effectiveIPSecGatewayAddr(cfg)),
		logger.Bool("route_present", route != ""),
		logger.Int("route_len", len(route)),
		logger.String("route_fingerprint", diagnosticFingerprint(route)),
		logger.Int("request_uri_len", len(req.Recipient.String())),
		logger.String("request_uri_fingerprint", diagnosticFingerprint(req.Recipient.String())),
		logger.Int("destination_len", len(strings.TrimSpace(req.Destination()))),
		logger.String("destination_fingerprint", diagnosticFingerprint(req.Destination())),
		logger.Bool("contact_present", req.GetHeader("Contact") != nil))
}
