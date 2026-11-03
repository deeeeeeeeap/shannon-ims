package voiceclient

import (
	"errors"
	"fmt"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/emiago/sipgo/sip"
)

func parseNetworkRPData(body []byte) (byte, []byte, error) {
	if len(body) < 5 || body[0] != 1 {
		return 0, nil, fmt.Errorf("invalid network RP-DATA")
	}
	offset := 2
	for field := 0; field < 2; field++ {
		if offset >= len(body) {
			return 0, nil, fmt.Errorf("truncated RP address")
		}
		offset += 1 + int(body[offset])
	}
	if offset >= len(body) || body[offset] == 0 || offset+1+int(body[offset]) != len(body) {
		return 0, nil, fmt.Errorf("invalid RP user data length")
	}
	return body[1], body[offset+1:], nil
}

func (c *Client) processIncomingSMS(req *sip.Request) (*sip.Response, *smsRPAckTask) {
	rpMR, tpdu, err := parseNetworkRPData(req.Body())
	if err != nil || tpdu[0]&3 != 0 {
		return sip.NewResponseFromRequest(req, 400, "Bad Request", nil), nil
	}
	store, ok := c.cfg.DeliveryStore.(messaging.IncomingSMSStore)
	if !ok {
		c.logInboundSMS("storage_unavailable", len(tpdu))
		return sip.NewResponseFromRequest(req, 503, "Service Unavailable", nil), nil
	}
	target, err := statusReportAckTarget(req)
	if err != nil {
		return sip.NewResponseFromRequest(req, 400, "Bad Request", nil), nil
	}
	if err := store.StoreIncomingSMS(c.cfg.IMSI, c.cfg.DeviceID, tpdu, time.Now()); err != nil {
		if errors.Is(err, messaging.ErrInvalidIncomingSMS) {
			c.logInboundSMS("invalid_tpdu", len(tpdu))
			return sip.NewResponseFromRequest(req, 400, "Bad Request", nil), nil
		}
		c.logInboundSMS("storage_failed", len(tpdu))
		return sip.NewResponseFromRequest(req, 503, "Service Unavailable", nil), nil
	}
	inReplyTo := ""
	if h := req.CallID(); h != nil {
		inReplyTo = h.Value()
	}
	c.logInboundSMS("stored", len(tpdu))
	return sip.NewResponseFromRequest(req, 200, "OK", nil), &smsRPAckTask{rpMR: rpMR, target: target, inReplyTo: inReplyTo}
}

func (c *Client) logInboundSMS(disposition string, length int) {
	logger.Info("IMS SMS inbound deliver", logger.String("report_kind", "sms_deliver"),
		logger.String("disposition", disposition), logger.Int("tpdu_len", length))
}
