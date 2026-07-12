package voiceclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/google/uuid"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

const smsContentType = "application/vnd.3gpp.sms"

// SendSMS submits each of parts as a separate SIP MESSAGE (3GPP TS 24.341),
// expecting the immediate 202 Accepted per part, and records delivery
// tracking via DeliveryStore. It does not wait for the delivery report
// (RP-ACK/RP-ERROR) -- that arrives asynchronously as a separate incoming
// MESSAGE and is handled by handleIncomingMessage, matching how vohive's own
// DeliveryStore.MarkSMSDeliveryPartReport is designed to be called well
// after the initial submission returns (see its In-Reply-To/Call-ID/
// rp_mr-plus-time-window correlation cascade).
func (c *Client) SendSMS(ctx context.Context, peer, content string, parts []messaging.SMSPart) (messaging.SendOutcome, error) {
	if len(parts) == 0 {
		return messaging.SendOutcome{}, fmt.Errorf("voiceclient: no parts to send")
	}
	serviceCentreURI, err := c.smsServiceCentreURI()
	if err != nil {
		return messaging.SendOutcome{}, err
	}

	messageID := uuid.NewString()
	now := time.Now()

	if c.cfg.DeliveryStore != nil {
		if err := c.cfg.DeliveryStore.CreateSMSDelivery(messageID, "", c.cfg.DeviceID, peer, content, len(parts), now); err != nil {
			return messaging.SendOutcome{}, fmt.Errorf("voiceclient: CreateSMSDelivery: %w", err)
		}
	}

	for partIndex, part := range parts {
		partNo := partIndex + 1
		req, err := c.newRequest(sip.MESSAGE, serviceCentreURI, false)
		if err != nil {
			return messaging.SendOutcome{}, err
		}
		req.AppendHeader(sip.NewHeader("Content-Type", smsContentType))
		req.SetBody(part.Body)

		res, err := c.doTransaction(ctx, req)
		if err != nil {
			return messaging.SendOutcome{}, fmt.Errorf("voiceclient: submit part %d: %w", partNo, err)
		}
		if res.StatusCode != 202 {
			return messaging.SendOutcome{}, fmt.Errorf("voiceclient: submit part %d: unexpected response %d %s", partNo, res.StatusCode, res.Reason)
		}

		if c.cfg.DeliveryStore != nil {
			callID := req.CallID().Value()
			if err := c.cfg.DeliveryStore.UpsertSMSDeliveryPart(messageID, partNo, callID, int(part.RPMR), "pending", now); err != nil {
				return messaging.SendOutcome{}, fmt.Errorf("voiceclient: UpsertSMSDeliveryPart: %w", err)
			}
		}
	}

	return messaging.SendOutcome{
		MessageID:     messageID,
		PartsTotal:    len(parts),
		DeliveryState: "pending",
	}, nil
}

func (c *Client) smsServiceCentreURI() (string, error) {
	raw := strings.TrimSpace(c.cfg.SMSC)
	if raw == "" {
		return "", fmt.Errorf("voiceclient: SMS service centre is unavailable")
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		return raw, nil
	}
	if strings.HasPrefix(lower, "tel:") {
		raw = strings.TrimSpace(raw[4:])
	}
	if strings.Contains(raw, "@") {
		return "sip:" + raw, nil
	}
	number := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(raw)
	if number == "" {
		return "", fmt.Errorf("voiceclient: SMS service centre is invalid")
	}
	digits := number
	if strings.HasPrefix(digits, "+") {
		digits = digits[1:]
	}
	if digits == "" {
		return "", fmt.Errorf("voiceclient: SMS service centre is invalid")
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("voiceclient: SMS service centre is invalid")
		}
	}
	domain := strings.TrimSpace(c.cfg.HomeDomain)
	if domain == "" {
		return "", fmt.Errorf("voiceclient: IMS home domain is unavailable for SMS service centre")
	}
	return "sip:" + number + "@" + domain + ";user=phone", nil
}

// rpKind is the outer RP envelope's message type, per 3GPP TS 24.011 --
// just enough to recognize a delivery report and its cause, not a full TPDU
// decode. See the package doc comment for why the TPDU layer itself stays
// in vohive.
type rpKind int

const (
	rpKindUnknown rpKind = iota
	rpKindAck
	rpKindError
)

type deliveryReport struct {
	kind  rpKind
	rpMR  byte
	cause int
}

// classifyRPEnvelope reads the RP-level framing needed to recognize an
// RP-ACK/RP-ERROR and its RP-MR/cause. Message type octet values: 0x02/0x03
// = RP-ACK, 0x04/0x05 = RP-ERROR (MS->Network / Network->MS pairs
// respectively); a delivery report for our own submission arrives as the
// Network->MS variant (0x03 or 0x05), but both are accepted here since the
// direction doesn't affect how we correlate/record it. Cause parsing
// mirrors 3GPP TS 24.011: cause IE is [length][value], value's low 7 bits
// are the cause code.
func classifyRPEnvelope(body []byte) (deliveryReport, error) {
	if len(body) < 2 {
		return deliveryReport{}, fmt.Errorf("voiceclient: RP body too short (%d bytes)", len(body))
	}
	switch body[0] {
	case 0x02, 0x03:
		return deliveryReport{kind: rpKindAck, rpMR: body[1]}, nil
	case 0x04, 0x05:
		if len(body) < 4 {
			return deliveryReport{}, fmt.Errorf("voiceclient: RP-ERROR body too short (%d bytes)", len(body))
		}
		causeIELen := int(body[2])
		if causeIELen <= 0 || 3+causeIELen > len(body) {
			return deliveryReport{}, fmt.Errorf("voiceclient: RP-ERROR cause IE out of range")
		}
		cause := int(body[3] & 0x7F)
		return deliveryReport{kind: rpKindError, rpMR: body[1], cause: cause}, nil
	default:
		return deliveryReport{}, fmt.Errorf("voiceclient: unrecognized RP message type 0x%02x", body[0])
	}
}

// handleIncomingMessage is the SIP server's MESSAGE handler. It only
// recognizes delivery reports for our own outbound SMS (Content-Type +
// classifiable RP envelope); anything else -- notably an inbound
// SMS-DELIVER from another party -- is out of scope (see package doc
// comment) and just gets a bare 200 OK so we don't leave the sender's
// transaction hanging.
func (c *Client) handleIncomingMessage(req *sip.Request, tx sip.ServerTransaction) {
	_ = tx.Respond(c.incomingMessageResponse(req))
}

func (c *Client) incomingMessageResponse(req *sip.Request) *sip.Response {
	ct := req.GetHeader("Content-Type")
	if ct == nil || !strings.EqualFold(ct.Value(), smsContentType) {
		return sip.NewResponseFromRequest(req, 415, "Unsupported Media Type", nil)
	}

	report, err := classifyRPEnvelope(req.Body())
	if err != nil {
		return sip.NewResponseFromRequest(req, 200, "OK", nil)
	}

	if c.cfg.DeliveryStore != nil {
		inReplyTo := ""
		if irt := req.GetHeader("In-Reply-To"); irt != nil {
			inReplyTo = irt.Value()
		}
		callID := req.CallID().Value()

		state := "acked"
		if report.kind == rpKindError {
			state = "failed"
		}
		_, _ = c.cfg.DeliveryStore.MarkSMSDeliveryPartReport(
			inReplyTo, callID, c.cfg.DeviceID, int(report.rpMR),
			state, 200, report.cause, "", time.Now(),
		)
	}

	return sip.NewResponseFromRequest(req, 200, "OK", nil)
}
