package voiceclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
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
	outcome := messaging.SendOutcome{
		MessageID:     messageID,
		PartsTotal:    len(parts),
		DeliveryState: "pending",
	}

	if c.cfg.DeliveryStore != nil {
		if err := c.cfg.DeliveryStore.CreateSMSDelivery(messageID, c.cfg.IMSI, c.cfg.DeviceID, peer, content, len(parts), now); err != nil {
			return messaging.SendOutcome{}, fmt.Errorf("voiceclient: CreateSMSDelivery: %w", err)
		}
	}

	for partIndex, part := range parts {
		partNo := partIndex + 1
		req, err := c.newRequest(sip.MESSAGE, serviceCentreURI, false)
		if err != nil {
			c.markSMSDeliveryPartSubmissionFailed(messageID, partNo, nil, int(part.RPMR))
			c.markSMSDeliveryFailed(&outcome)
			return outcome, err
		}
		req.AppendHeader(sip.NewHeader("Content-Type", smsContentType))
		req.SetBody(part.Body)

		// Establish RP-MR correlation before the request reaches the network.
		// A delivery report may follow the 202 response immediately on the
		// independent server flow, before this goroutine resumes.
		if c.cfg.DeliveryStore != nil {
			if err := c.cfg.DeliveryStore.UpsertSMSDeliveryPart(messageID, partNo, "", int(part.RPMR), "pending", now); err != nil {
				c.markSMSDeliveryFailed(&outcome)
				return outcome, fmt.Errorf("voiceclient: prepare SMS delivery part: %w", err)
			}
		}

		res, err := c.doTransaction(ctx, req)
		if err != nil {
			c.markSMSDeliveryPartSubmissionFailed(messageID, partNo, req, int(part.RPMR))
			outcome.DeliveryState = "failed"
			return outcome, fmt.Errorf("voiceclient: submit part %d: %w", partNo, err)
		}
		if res.StatusCode != 202 {
			c.markSMSDeliveryPartSubmissionFailed(messageID, partNo, req, int(part.RPMR))
			outcome.DeliveryState = "failed"
			return outcome, fmt.Errorf("voiceclient: submit part %d: unexpected response %d %s", partNo, res.StatusCode, res.Reason)
		}

		if c.cfg.DeliveryStore != nil {
			callID := ""
			if header := req.CallID(); header != nil {
				callID = header.Value()
			}
			if err := c.cfg.DeliveryStore.UpsertSMSDeliveryPart(messageID, partNo, callID, int(part.RPMR), "pending", now); err != nil {
				return outcome, fmt.Errorf("voiceclient: UpsertSMSDeliveryPart: %w", err)
			}
		}
	}

	return outcome, nil
}

func (c *Client) markSMSDeliveryFailed(outcome *messaging.SendOutcome) {
	if outcome == nil {
		return
	}
	outcome.DeliveryState = "failed"
	if c == nil || c.cfg.DeliveryStore == nil || strings.TrimSpace(outcome.MessageID) == "" {
		return
	}
	_ = c.cfg.DeliveryStore.UpdateSMSDeliveryState(outcome.MessageID, "failed", "", -1, time.Now())
}

func (c *Client) markSMSDeliveryPartSubmissionFailed(messageID string, partNo int, req *sip.Request, rpMR int) {
	if c == nil || c.cfg.DeliveryStore == nil {
		return
	}
	callID := ""
	if req != nil {
		if header := req.CallID(); header != nil {
			callID = header.Value()
		}
	}
	at := time.Now()
	if err := c.cfg.DeliveryStore.UpsertSMSDeliveryPart(messageID, partNo, callID, rpMR, "failed", at); err != nil {
		return
	}
	_ = c.cfg.DeliveryStore.RecomputeSMSDelivery(messageID, at)
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
	kind        rpKind
	rpMR        byte
	cause       int
	reportKind  rpReportKind
	hasUserData bool
	hasTPFCS    bool
	tpFCS       int
}

type rpReportKind int

const (
	rpReportKindUnknown rpReportKind = iota
	rpReportKindBareAck
	rpReportKindSubmitSuccess
	rpReportKindRPError
	rpReportKindSubmitFailure
	rpReportKindSubmitMalformed
)

func (kind rpReportKind) String() string {
	switch kind {
	case rpReportKindBareAck:
		return "bare_ack"
	case rpReportKindSubmitSuccess:
		return "submit_report_success"
	case rpReportKindRPError:
		return "rp_error"
	case rpReportKindSubmitFailure:
		return "submit_report_failure"
	case rpReportKindSubmitMalformed:
		return "submit_report_malformed"
	default:
		return "unknown"
	}
}

func (report deliveryReport) submitReportKind() string {
	switch report.reportKind {
	case rpReportKindSubmitSuccess:
		return "success"
	case rpReportKindSubmitFailure:
		return "failure"
	case rpReportKindSubmitMalformed:
		return "malformed"
	default:
		return "none"
	}
}

// classifyRPEnvelope reads the RP-level framing needed to recognize an
// RP-ACK/RP-ERROR and its RP-MR/cause. Message type octet values: 0x02/0x03
// = RP-ACK, 0x04/0x05 = RP-ERROR (MS->Network / Network->MS pairs
// respectively). An inbound report for our own submission must use the
// Network->MS variant (0x03 or 0x05); accepting the opposite direction would
// let an unrelated mobile-originated envelope update delivery state. Cause
// parsing mirrors 3GPP TS 24.011: cause IE is [length][value], value's low
// seven bits are the cause code.
func classifyRPEnvelope(body []byte) (deliveryReport, error) {
	if len(body) < 2 {
		return deliveryReport{}, fmt.Errorf("voiceclient: RP body too short (%d bytes)", len(body))
	}
	switch body[0] {
	case 0x03:
		userData, hasUserData, err := parseOptionalRPUserData(body, 2)
		if err != nil {
			return deliveryReport{}, fmt.Errorf("voiceclient: malformed RP-ACK user data")
		}
		if !hasUserData {
			return deliveryReport{
				kind:       rpKindAck,
				rpMR:       body[1],
				reportKind: rpReportKindBareAck,
			}, nil
		}
		if err := validateSMSSubmitReport(userData, false); err != nil {
			return deliveryReport{}, fmt.Errorf("voiceclient: malformed successful SMS-SUBMIT-REPORT")
		}
		return deliveryReport{
			kind:        rpKindAck,
			rpMR:        body[1],
			reportKind:  rpReportKindSubmitSuccess,
			hasUserData: true,
		}, nil
	case 0x05:
		if len(body) < 4 {
			return deliveryReport{}, fmt.Errorf("voiceclient: RP-ERROR body too short (%d bytes)", len(body))
		}
		causeIELen := int(body[2])
		if causeIELen <= 0 || 3+causeIELen > len(body) {
			return deliveryReport{}, fmt.Errorf("voiceclient: RP-ERROR cause IE out of range")
		}
		cause := int(body[3] & 0x7F)
		userDataOffset := 3 + causeIELen
		userData, hasUserData, err := parseOptionalRPUserData(body, userDataOffset)
		if err != nil {
			return deliveryReport{
				kind:        rpKindError,
				rpMR:        body[1],
				cause:       cause,
				reportKind:  rpReportKindSubmitMalformed,
				hasUserData: len(body) > userDataOffset,
			}, nil
		}
		if !hasUserData {
			return deliveryReport{
				kind:       rpKindError,
				rpMR:       body[1],
				cause:      cause,
				reportKind: rpReportKindRPError,
			}, nil
		}
		if err := validateSMSSubmitReport(userData, true); err != nil {
			return deliveryReport{
				kind:        rpKindError,
				rpMR:        body[1],
				cause:       cause,
				reportKind:  rpReportKindSubmitMalformed,
				hasUserData: true,
			}, nil
		}
		return deliveryReport{
			kind:        rpKindError,
			rpMR:        body[1],
			cause:       cause,
			reportKind:  rpReportKindSubmitFailure,
			hasUserData: true,
			hasTPFCS:    true,
			tpFCS:       int(userData[1]),
		}, nil
	case 0x02, 0x04:
		return deliveryReport{}, fmt.Errorf("voiceclient: unexpected mobile-originated RP report")
	default:
		return deliveryReport{}, fmt.Errorf("voiceclient: unrecognized RP message type")
	}
}

func validateSMSSubmitReport(tpdu []byte, hasTPFCS bool) error {
	// SMS-SUBMIT-REPORT is SC-to-MS and therefore has TP-MTI 01. A success
	// report carried by RP-ACK omits TP-FCS; an error report carried by
	// RP-ERROR includes it before TP-PI. Both forms then carry the mandatory
	// seven-octet TP-SCTS and only the optional fields named by TP-PI.
	if len(tpdu) < 1 || tpdu[0]&0x03 != 0x01 {
		return fmt.Errorf("voiceclient: unexpected TPDU report type")
	}
	offset := 1
	if hasTPFCS {
		if offset >= len(tpdu) {
			return fmt.Errorf("voiceclient: missing TP-FCS")
		}
		offset++
	}
	if offset >= len(tpdu) {
		return fmt.Errorf("voiceclient: missing TP-PI")
	}
	pi := tpdu[offset]
	offset++
	knownPI := pi & 0x07
	hasUnknownParameters := pi&0x78 != 0
	for pi&0x80 != 0 {
		if offset >= len(tpdu) {
			return fmt.Errorf("voiceclient: truncated TP-PI extension")
		}
		pi = tpdu[offset]
		offset++
		hasUnknownParameters = hasUnknownParameters || pi&0x7f != 0
	}
	if len(tpdu)-offset < 7 {
		return fmt.Errorf("voiceclient: missing TP-SCTS")
	}
	offset += 7
	if knownPI&0x01 != 0 { // TP-PID
		if offset >= len(tpdu) {
			return fmt.Errorf("voiceclient: missing TP-PID")
		}
		offset++
	}
	dcs := byte(0)
	hasDCS := knownPI&0x02 != 0
	if hasDCS { // TP-DCS
		if offset >= len(tpdu) {
			return fmt.Errorf("voiceclient: missing TP-DCS")
		}
		dcs = tpdu[offset]
		offset++
	}
	if knownPI&0x04 == 0 { // no TP-UDL / TP-UD
		if offset != len(tpdu) && !hasUnknownParameters {
			return fmt.Errorf("voiceclient: trailing SMS-SUBMIT-REPORT data")
		}
		return nil
	}
	if offset >= len(tpdu) {
		return fmt.Errorf("voiceclient: missing TP-UDL")
	}
	udl := int(tpdu[offset])
	offset++
	userDataOctets, err := submitReportUserDataOctets(udl, dcs, hasDCS)
	if err != nil || offset+userDataOctets > len(tpdu) ||
		(offset+userDataOctets != len(tpdu) && !hasUnknownParameters) {
		return fmt.Errorf("voiceclient: malformed TP-UD")
	}
	return nil
}

func submitReportUserDataOctets(udl int, dcs byte, hasDCS bool) (int, error) {
	if udl < 0 {
		return 0, fmt.Errorf("voiceclient: invalid TP-UDL")
	}
	if !hasDCS {
		return (udl*7 + 7) / 8, nil
	}
	switch {
	case dcs&0xc0 == 0x00:
		switch (dcs >> 2) & 0x03 {
		case 0:
			return (udl*7 + 7) / 8, nil
		case 1, 2:
			return udl, nil
		default:
			return 0, fmt.Errorf("voiceclient: reserved TP-DCS alphabet")
		}
	case dcs&0xf0 == 0xc0 || dcs&0xf0 == 0xd0:
		return (udl*7 + 7) / 8, nil
	case dcs&0xf0 == 0xe0:
		return udl, nil
	case dcs&0xf0 == 0xf0:
		if dcs&0x04 == 0 {
			return (udl*7 + 7) / 8, nil
		}
		return udl, nil
	default:
		return 0, fmt.Errorf("voiceclient: unsupported TP-DCS")
	}
}

func parseOptionalRPUserData(body []byte, offset int) ([]byte, bool, error) {
	if offset == len(body) {
		return nil, false, nil
	}
	if offset < 0 || offset > len(body) || len(body)-offset < 2 {
		return nil, false, fmt.Errorf("voiceclient: malformed RP-User-Data")
	}
	const rpUserDataIEI = 0x41
	if body[offset] != rpUserDataIEI {
		return nil, false, fmt.Errorf("voiceclient: unexpected RP optional IE")
	}
	length := int(body[offset+1])
	start := offset + 2
	if length == 0 || start+length != len(body) {
		return nil, false, fmt.Errorf("voiceclient: malformed RP-User-Data length")
	}
	return body[start:], true, nil
}

// handleIncomingMessage is the SIP server's MESSAGE handler. It only
// recognizes delivery reports for our own outbound SMS (Content-Type +
// classifiable RP envelope); anything else -- notably an inbound
// SMS-DELIVER from another party -- is out of scope (see package doc
// comment) and just gets a bare 200 OK so we don't leave the sender's
// transaction hanging.
func (c *Client) handleIncomingMessage(req *sip.Request, tx sip.ServerTransaction) {
	response, rpAck := c.incomingMessageResult(req)
	if err := tx.Respond(response); err == nil && rpAck != nil && c.secure != nil {
		c.secure.enqueueRPAck(*rpAck)
	}
}

func (c *Client) incomingMessageResponse(req *sip.Request) *sip.Response {
	response, _ := c.incomingMessageResult(req)
	return response
}

func (c *Client) incomingMessageResult(req *sip.Request) (*sip.Response, *smsRPAckTask) {
	ct := req.GetHeader("Content-Type")
	if ct == nil || !strings.EqualFold(ct.Value(), smsContentType) {
		return sip.NewResponseFromRequest(req, 415, "Unsupported Media Type", nil), nil
	}
	if body := req.Body(); len(body) > 0 && body[0] == 0x01 {
		return c.processSMSStatusReport(req)
	}

	report, err := classifyRPEnvelope(req.Body())
	if err != nil {
		return sip.NewResponseFromRequest(req, 200, "OK", nil), nil
	}

	correlationMethod := "none"
	partIndex := 0
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
		match, _ := c.cfg.DeliveryStore.MarkSMSDeliveryPartReport(
			inReplyTo, callID, c.cfg.DeviceID, int(report.rpMR),
			state, 200, report.cause, "", time.Now(),
		)
		correlationMethod = boundedSMSCorrelationMethod(match.CorrelationMethod)
		if match.PartNo > 0 && match.PartNo <= 255 {
			partIndex = match.PartNo
		}
	}

	logger.Info("IMS SMS delivery report",
		logger.String("rp_report_kind", report.reportKind.String()),
		logger.Bool("has_user_data", report.hasUserData),
		logger.String("submit_report_kind", report.submitReportKind()),
		logger.Bool("has_tp_fcs", report.hasTPFCS),
		logger.Int("tp_fcs", report.tpFCS),
		logger.Int("rp_cause", report.cause),
		logger.String("correlation_method", correlationMethod),
		logger.Int("part_index", partIndex))

	return sip.NewResponseFromRequest(req, 200, "OK", nil), nil
}

func boundedSMSCorrelationMethod(method string) string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "in_reply_to":
		return "in_reply_to"
	case "call_id":
		return "call_id"
	case "rp_mr":
		return "rp_mr"
	case "tp_mr":
		return "tp_mr"
	default:
		return "none"
	}
}
