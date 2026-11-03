package voiceclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

type smsStatusDisposition uint8

const (
	smsStatusUnknown smsStatusDisposition = iota
	smsStatusDelivered
	smsStatusForwardedUnconfirmed
	smsStatusReplaced
	smsStatusCompletedUnconfirmed
	smsStatusTemporaryRetrying
	smsStatusPermanentFailure
	smsStatusTemporaryStopped
)

func (d smsStatusDisposition) String() string {
	switch d {
	case smsStatusDelivered:
		return "delivered"
	case smsStatusForwardedUnconfirmed:
		return "forwarded_unconfirmed"
	case smsStatusReplaced:
		return "replaced"
	case smsStatusCompletedUnconfirmed:
		return "completed_unconfirmed"
	case smsStatusTemporaryRetrying:
		return "temporary_retrying"
	case smsStatusPermanentFailure:
		return "permanent_failure"
	case smsStatusTemporaryStopped:
		return "temporary_stopped"
	default:
		return "unknown"
	}
}

type smsStatusReport struct {
	rpMR        byte
	tpMR        byte
	tpStatus    byte
	disposition smsStatusDisposition
	recipient   string
}

type smsRPAckTask struct {
	rpMR      byte
	target    string
	inReplyTo string
}

// smsReportShape is the de-identified structure of a rejected RP-DATA: which
// message type it claims to be and how long it is. No user data, no addresses.
type smsReportShape struct {
	rpMTI    int
	tpduKind string
	tpSRQ    bool
	tpMMS    bool
	bodyLen  int
	tpduLen  int
}

// describeSMSReportShape walks just far enough into the envelope to name the TPDU
// type, without validating it. Deliberately tolerant: it runs on bodies the strict
// parser already rejected, so it must not reject them again -- an unparseable
// envelope still yields a useful "how far did we get" answer.
func describeSMSReportShape(body []byte) smsReportShape {
	shape := smsReportShape{rpMTI: -1, tpduKind: "unknown", bodyLen: len(body)}
	if len(body) == 0 {
		shape.tpduKind = "empty"
		return shape
	}
	shape.rpMTI = int(body[0] & 0x07)

	// Same envelope walk as classifySMSStatusReport: RP-MTI, RP-MR, then two
	// length-prefixed addresses, then the user-data length.
	offset := 2
	for field := 0; field < 2; field++ {
		if offset >= len(body) {
			shape.tpduKind = "truncated_address"
			return shape
		}
		offset += 1 + int(body[offset])
	}
	if offset >= len(body) {
		shape.tpduKind = "no_user_data"
		return shape
	}
	offset++ // skip the RP user-data length octet
	if offset >= len(body) {
		shape.tpduKind = "no_tpdu"
		return shape
	}

	tpdu := body[offset:]
	shape.tpduLen = len(tpdu)
	shape.tpduKind = smsTPDUKindFromFirstOctet(tpdu[0])
	shape.tpSRQ = tpdu[0]&0x20 != 0
	shape.tpMMS = tpdu[0]&0x04 != 0
	return shape
}

// smsTPDUKindFromFirstOctet names the TP-MTI for a network-to-MS TPDU
// (TS 23.040 table 9.2.3.1). Closed set.
func smsTPDUKindFromFirstOctet(first byte) string {
	switch first & 0x03 {
	case 0x00:
		return "sms_deliver"
	case 0x01:
		return "sms_submit_report"
	case 0x02:
		return "sms_status_report"
	default:
		return "reserved"
	}
}

// boundedSMSRejectReason maps a parser error to a closed enum. The error strings
// are ours, but mapping rather than forwarding them keeps the log key stable if
// the wording changes and guarantees nothing from the wire can reach a log value.
func boundedSMSRejectReason(err error) string {
	if err == nil {
		return "none"
	}
	switch msg := err.Error(); {
	case strings.Contains(msg, "not a network-originated RP-DATA"):
		return "not_network_rp_data"
	case strings.Contains(msg, "truncated RP address"):
		return "truncated_rp_address"
	case strings.Contains(msg, "RP address length out of range"):
		return "rp_address_length"
	case strings.Contains(msg, "missing RP user data"):
		return "missing_rp_user_data"
	case strings.Contains(msg, "invalid RP user data length"):
		return "rp_user_data_length"
	case strings.Contains(msg, "not an SMS-STATUS-REPORT"):
		return "tpdu_not_status_report"
	case strings.Contains(msg, "invalid TP recipient length"):
		return "tp_recipient_length"
	case strings.Contains(msg, "truncated TP recipient"):
		return "tp_recipient_truncated"
	case strings.Contains(msg, "timestamps or status"):
		return "tpdu_truncated"
	case strings.Contains(msg, "timestamp"):
		return "tp_timestamp_invalid"
	default:
		return "other"
	}
}

func (c *Client) processSMSStatusReport(req *sip.Request) (*sip.Response, *smsRPAckTask) {
	body := req.Body()
	report, err := classifySMSStatusReport(body)
	if err != nil {
		// "malformed" on its own is a dead end: every rejection reason inside
		// classifySMSStatusReport produced the same log line and the error was
		// discarded, so a message that simply is not a STATUS-REPORT looked
		// identical to a corrupt one.
		//
		// A live 310/240 send sat at acked forever with exactly this warning, and
		// there was no way to tell whether the carrier sent a STATUS-REPORT this
		// parser rejects (e.g. TP-SRQ set) or an inbound SMS-DELIVER that reached
		// this function only because incomingMessageResult routes on RP-MTI alone --
		// SMS-DELIVER shares RP-MTI = 1.
		//
		// The fields below are structural: message-type bits and lengths, never user
		// data, addresses or identifiers.
		shape := describeSMSReportShape(body)
		logger.Warn("IMS SMS status report",
			logger.String("report_kind", "sms_status_report"),
			logger.String("tp_status_class", "malformed"),
			logger.Int("tp_status", 0),
			logger.String("correlation_method", "none"),
			logger.Int("part_index", 0),
			logger.String("reject_reason", boundedSMSRejectReason(err)),
			logger.String("tpdu_kind", shape.tpduKind),
			logger.Bool("tp_srq", shape.tpSRQ),
			logger.Bool("tp_mms", shape.tpMMS),
			logger.Int("rp_mti", shape.rpMTI),
			logger.Int("body_len", shape.bodyLen),
			logger.Int("tpdu_len", shape.tpduLen))
		return sip.NewResponseFromRequest(req, 200, "OK", nil), nil
	}

	correlationMethod := "none"
	partIndex := 0
	if store, ok := c.cfg.DeliveryStore.(messaging.StatusReportStore); ok {
		match, storeErr := store.MarkSMSDeliveryPartStatusReport(
			c.cfg.IMSI,
			c.cfg.DeviceID,
			report.recipient,
			int(report.tpMR),
			statusReportDeliveryState(report.disposition),
			int(report.tpStatus),
			time.Now(),
		)
		if storeErr != nil && !errors.Is(storeErr, messaging.ErrDeliveryNotFound) {
			return sip.NewResponseFromRequest(req, 503, "Service Unavailable", nil), nil
		}
		correlationMethod = boundedSMSCorrelationMethod(match.CorrelationMethod)
		if match.PartNo > 0 && match.PartNo <= 255 {
			partIndex = match.PartNo
		}
	}

	logger.Info("IMS SMS status report",
		logger.String("report_kind", "sms_status_report"),
		logger.String("tp_status_class", report.disposition.String()),
		logger.Int("tp_status", int(report.tpStatus)),
		logger.String("correlation_method", correlationMethod),
		logger.Int("part_index", partIndex))

	target, err := statusReportAckTarget(req)
	if err != nil {
		c.logStatusReportRPAckResult("target_missing")
		return sip.NewResponseFromRequest(req, 200, "OK", nil), nil
	}
	inReplyTo := ""
	if callID := req.CallID(); callID != nil {
		inReplyTo = strings.TrimSpace(callID.Value())
	}
	return sip.NewResponseFromRequest(req, 200, "OK", nil), &smsRPAckTask{
		rpMR:      report.rpMR,
		target:    target,
		inReplyTo: inReplyTo,
	}
}

func statusReportDeliveryState(disposition smsStatusDisposition) string {
	switch disposition {
	case smsStatusDelivered:
		return "delivered"
	case smsStatusTemporaryRetrying:
		return "delivery_pending"
	case smsStatusPermanentFailure, smsStatusTemporaryStopped:
		return "delivery_failed"
	default:
		return "delivery_unconfirmed"
	}
}

func statusReportAckTarget(req *sip.Request) (string, error) {
	header := req.GetHeader("P-Asserted-Identity")
	if header == nil {
		return "", fmt.Errorf("voiceclient: status report missing asserted identity")
	}
	var uri sip.Uri
	if _, err := sip.ParseAddressValue(strings.TrimSpace(header.Value()), &uri, nil); err != nil {
		return "", fmt.Errorf("voiceclient: invalid asserted identity")
	}
	if (uri.Scheme != "sip" && uri.Scheme != "sips") || strings.TrimSpace(uri.Host) == "" {
		return "", fmt.Errorf("voiceclient: unsupported asserted identity")
	}
	return uri.String(), nil
}

func (c *Client) sendStatusReportRPAck(task smsRPAckTask) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := c.newRequest(sip.MESSAGE, task.target, false)
	if err != nil {
		c.logStatusReportRPAckResult("build_failed")
		return
	}
	if strings.TrimSpace(task.inReplyTo) != "" {
		req.AppendHeader(sip.NewHeader("In-Reply-To", task.inReplyTo))
	}
	req.AppendHeader(sip.NewHeader("Content-Type", smsContentType))
	req.SetBody([]byte{0x02, task.rpMR})
	response, err := c.doTransaction(ctx, req)
	if err != nil {
		c.logStatusReportRPAckResult("transport_failed")
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		c.logStatusReportRPAckResult("rejected")
		return
	}
	c.logStatusReportRPAckResult("accepted")
}

func (c *Client) logStatusReportRPAckResult(result string) {
	switch result {
	case "accepted", "rejected", "transport_failed", "build_failed", "target_missing", "queue_full", "canceled":
	default:
		result = "unknown"
	}
	logger.Info("IMS SMS status report RP-ACK",
		logger.String("stage", "status_report_rp_ack"),
		logger.String("rp_ack_result", result))
}

func classifySMSStatusReport(body []byte) (smsStatusReport, error) {
	if len(body) < 5 || body[0] != 0x01 {
		return smsStatusReport{}, fmt.Errorf("voiceclient: not a network-originated RP-DATA")
	}
	offset := 2
	for field := 0; field < 2; field++ {
		if offset >= len(body) {
			return smsStatusReport{}, fmt.Errorf("voiceclient: truncated RP address")
		}
		length := int(body[offset])
		offset++
		if length < 0 || offset+length > len(body) {
			return smsStatusReport{}, fmt.Errorf("voiceclient: RP address length out of range")
		}
		offset += length
	}
	if offset >= len(body) {
		return smsStatusReport{}, fmt.Errorf("voiceclient: missing RP user data")
	}
	userDataLength := int(body[offset])
	offset++
	if userDataLength == 0 || offset+userDataLength != len(body) {
		return smsStatusReport{}, fmt.Errorf("voiceclient: invalid RP user data length")
	}
	tpdu := body[offset:]
	if len(tpdu) < 3 || tpdu[0]&0x03 != 0x02 || tpdu[0]&0x20 != 0 {
		return smsStatusReport{}, fmt.Errorf("voiceclient: not an SMS-STATUS-REPORT")
	}

	tpOffset := 2
	recipientDigits := int(tpdu[tpOffset])
	tpOffset++
	if recipientDigits <= 0 || recipientDigits > 20 {
		return smsStatusReport{}, fmt.Errorf("voiceclient: invalid TP recipient length")
	}
	recipientOctets := 1 + (recipientDigits+1)/2
	if tpOffset+recipientOctets > len(tpdu) {
		return smsStatusReport{}, fmt.Errorf("voiceclient: truncated TP recipient")
	}
	recipient, err := decodeStatusReportRecipient(tpdu[tpOffset:tpOffset+recipientOctets], recipientDigits)
	if err != nil {
		return smsStatusReport{}, err
	}
	tpOffset += recipientOctets
	if len(tpdu)-tpOffset < 15 {
		return smsStatusReport{}, fmt.Errorf("voiceclient: truncated SMS-STATUS-REPORT timestamps or status")
	}
	if err := validateStatusReportTimestamp(tpdu[tpOffset : tpOffset+7]); err != nil {
		return smsStatusReport{}, err
	}
	tpOffset += 7
	if err := validateStatusReportTimestamp(tpdu[tpOffset : tpOffset+7]); err != nil {
		return smsStatusReport{}, err
	}
	tpOffset += 7
	tpStatus := tpdu[tpOffset]
	tpOffset++
	if err := validateStatusReportOptionals(tpdu, tpOffset); err != nil {
		return smsStatusReport{}, err
	}

	return smsStatusReport{
		rpMR:        body[1],
		tpMR:        tpdu[1],
		tpStatus:    tpStatus,
		disposition: classifyTPStatus(tpStatus),
		recipient:   recipient,
	}, nil
}

func classifyTPStatus(status byte) smsStatusDisposition {
	switch {
	case status == 0x00:
		return smsStatusDelivered
	case status == 0x01:
		return smsStatusForwardedUnconfirmed
	case status == 0x02:
		return smsStatusReplaced
	case status <= 0x1f:
		return smsStatusCompletedUnconfirmed
	case status <= 0x3f:
		return smsStatusTemporaryRetrying
	case status <= 0x5f:
		return smsStatusPermanentFailure
	case status <= 0x7f:
		return smsStatusTemporaryStopped
	default:
		return smsStatusUnknown
	}
}

func decodeStatusReportRecipient(encoded []byte, digits int) (string, error) {
	if len(encoded) != 1+(digits+1)/2 || encoded[0]&0x80 == 0 {
		return "", fmt.Errorf("voiceclient: invalid TP recipient address")
	}
	var out strings.Builder
	if encoded[0]&0x70 == 0x10 {
		out.WriteByte('+')
	}
	for i := 0; i < digits; i++ {
		octet := encoded[1+i/2]
		nibble := octet & 0x0f
		if i%2 != 0 {
			nibble = octet >> 4
		}
		if nibble > 9 {
			return "", fmt.Errorf("voiceclient: invalid TP recipient digit")
		}
		out.WriteByte('0' + nibble)
	}
	if digits%2 != 0 && encoded[len(encoded)-1]>>4 != 0x0f {
		return "", fmt.Errorf("voiceclient: invalid TP recipient filler")
	}
	return out.String(), nil
}

func validateStatusReportTimestamp(encoded []byte) error {
	if len(encoded) != 7 {
		return fmt.Errorf("voiceclient: invalid TP timestamp length")
	}
	decode := func(octet byte) (int, bool) {
		lo, hi := int(octet&0x0f), int(octet>>4)
		return lo*10 + hi, lo <= 9 && hi <= 9
	}
	month, okMonth := decode(encoded[1])
	day, okDay := decode(encoded[2])
	hour, okHour := decode(encoded[3])
	minute, okMinute := decode(encoded[4])
	second, okSecond := decode(encoded[5])
	_, okYear := decode(encoded[0])
	tzLow := encoded[6] & 0x07
	tzHigh := encoded[6] >> 4
	if !okYear || !okMonth || !okDay || !okHour || !okMinute || !okSecond ||
		month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59 ||
		tzLow > 9 || tzHigh > 9 {
		return fmt.Errorf("voiceclient: invalid TP timestamp")
	}
	return nil
}

func validateStatusReportOptionals(tpdu []byte, offset int) error {
	if offset == len(tpdu) {
		return nil
	}
	if offset < 0 || offset >= len(tpdu) {
		return fmt.Errorf("voiceclient: invalid TP optional offset")
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
	if knownPI&0x01 != 0 {
		if offset >= len(tpdu) {
			return fmt.Errorf("voiceclient: missing TP-PID")
		}
		offset++
	}
	dcs := byte(0)
	hasDCS := knownPI&0x02 != 0
	if hasDCS {
		if offset >= len(tpdu) {
			return fmt.Errorf("voiceclient: missing TP-DCS")
		}
		dcs = tpdu[offset]
		offset++
	}
	if knownPI&0x04 == 0 {
		if offset != len(tpdu) && !hasUnknownParameters {
			return fmt.Errorf("voiceclient: trailing SMS-STATUS-REPORT data")
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
		return fmt.Errorf("voiceclient: malformed SMS-STATUS-REPORT user data")
	}
	return nil
}
