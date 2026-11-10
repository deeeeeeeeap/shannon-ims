package device

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/pkg/logger"
	"github.com/1239t/vohive/pkg/smscodec"
	"github.com/1239t/vowifi-go/runtimehost"
)

// SMSChannel names the path an outgoing short message takes.
type SMSChannel string

const (
	// SMSChannelIMS is SMS over IMS on the Wi-Fi Calling session of the device.
	SMSChannelIMS SMSChannel = "ims"
	// SMSChannelCellular is the short message service of the modem itself,
	// reached over AT, QMI or MBIM.
	SMSChannelCellular SMSChannel = "cellular"
)

// Label is the name of the channel as it is shown to people.
func (c SMSChannel) Label() string {
	if c == SMSChannelIMS {
		return "VoWiFi"
	}
	return "蜂窝"
}

var (
	// ErrSMSDeviceNotFound reports a request for a device the pool does not have.
	ErrSMSDeviceNotFound = errors.New("设备未找到")
	// ErrSMSRequestInvalid reports a destination, text or encoding that cannot
	// be sent as written. Nothing was handed to a channel, and the same request
	// will fail the same way on any device.
	ErrSMSRequestInvalid = errors.New("短信请求无效")
)

// smsRequestError marks an error as ErrSMSRequestInvalid and keeps its text.
type smsRequestError struct{ err error }

func (e smsRequestError) Error() string        { return e.err.Error() }
func (e smsRequestError) Unwrap() error        { return e.err }
func (e smsRequestError) Is(target error) bool { return target == ErrSMSRequestInvalid }

const (
	// cellularSMSSendTimeout bounds one message on the modem, all parts included.
	cellularSMSSendTimeout = 35 * time.Second

	// Values of db.SMS.Type and db.SMS.Status for a message sent through the modem.
	smsHistoryTypeSent     = 2
	smsHistoryStatusSent   = 2
	smsHistoryStatusFailed = 3
)

// SMSSendRequest is one text message to send from a device.
type SMSSendRequest struct {
	DeviceID string
	// To is the destination as a person writes it; smscodec.NormalizeDestination
	// says what is accepted.
	To   string
	Text string
	// Encoding forces an alphabet. Empty or smscodec.SMSEncodingAuto leaves the
	// choice to the codec: the GSM 7-bit alphabet when the text fits it, UCS-2
	// otherwise.
	Encoding smscodec.SMSEncoding
}

// SMSSendResult says what became of a request. It is filled in as far as the
// request got, also when SendSMS returns an error.
type SMSSendResult struct {
	DeviceID string
	// Channel is empty when the device was not found.
	Channel SMSChannel
	// To is the destination that was put into the message, or the destination
	// as requested when it could not be used.
	To string
	// MessageID identifies the submission for delivery tracking. Only SMS over
	// IMS assigns one.
	MessageID string
	// PartsTotal is the number of parts the message was split into, and zero
	// for a request that could not be prepared.
	PartsTotal int
	// DeliveryState is one of the db.SMSDeliveryState values: "acked" once a
	// modem has accepted the message, the state the IMS engine reports for a
	// message it took, and "failed" otherwise.
	DeliveryState string
}

// NormalizeSMSDeliveryState returns state in its canonical spelling when it is
// a known delivery state, fallback when that is one, and "pending" otherwise.
func NormalizeSMSDeliveryState(state, fallback string) string {
	for _, candidate := range []string{state, fallback} {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		switch candidate {
		case db.SMSDeliveryStatePending, db.SMSDeliveryStatePartialAck, db.SMSDeliveryStateAcked,
			db.SMSDeliveryStateDeliveryPending, db.SMSDeliveryStateDeliveryUnconfirmed,
			db.SMSDeliveryStateDelivered, db.SMSDeliveryStateFailed, db.SMSDeliveryPartStateTimeout:
			return candidate
		}
	}
	return db.SMSDeliveryStatePending
}

// SMSChannelFor tells which channel a message sent from the device now would take.
func (p *Pool) SMSChannelFor(deviceID string) SMSChannel {
	if p.IsVoWiFiActive(deviceID) {
		return SMSChannelIMS
	}
	return SMSChannelCellular
}

// SendSMS sends one text message from a device. It is the one way out for
// short messages: the web API and the bot commands both end here.
//
// The request is checked, the channel is the one the device is on (SMS over
// IMS while its Wi-Fi Calling session is up, the modem otherwise), the message
// is prepared once and handed to that channel. Every message that reached a
// channel leaves one row in the message history, sent or failed. A request
// that cannot be sent as written is refused with ErrSMSRequestInvalid before
// anything is done with it, and leaves no row.
//
// ctx bounds SMS over IMS. A message on the modem is not abandoned when ctx
// ends, because a modem cannot take back a message it has started to send; it
// is bounded by cellularSMSSendTimeout instead.
func (p *Pool) SendSMS(ctx context.Context, req SMSSendRequest) (SMSSendResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	deviceID := strings.TrimSpace(req.DeviceID)
	result := SMSSendResult{
		DeviceID:      deviceID,
		To:            strings.TrimSpace(req.To),
		DeliveryState: db.SMSDeliveryStateFailed,
	}
	worker := p.GetWorker(deviceID)
	if worker == nil {
		return result, fmt.Errorf("%w: %s", ErrSMSDeviceNotFound, deviceID)
	}

	// The instance is taken once, here: a session that is replaced while the
	// message is on its way must not carry it.
	inst := p.voWiFiHost().Instance(deviceID)
	result.Channel = SMSChannelCellular
	if inst != nil {
		result.Channel = SMSChannelIMS
	}

	opts := smscodec.SubmitOptions{
		Encoding: req.Encoding,
		// SMS over IMS always asks the service centre for a status report.
		RequestStatusReport: inst != nil,
	}
	submission, err := smscodec.PrepareSubmission(req.To, req.Text, opts)
	if err != nil {
		logger.Warn(fmt.Sprintf("[%s] 短信请求无效，未发送", deviceID),
			"channel", string(result.Channel), "to_len", len(result.To), "text_len", len(req.Text), "err", err)
		return result, smsRequestError{err}
	}
	result.To = submission.To()
	result.PartsTotal = submission.PartCount()

	started := time.Now()
	if inst != nil {
		err = p.sendSMSOverIMS(ctx, inst, worker, submission, req.Text, &result)
	} else {
		err = worker.sendSMSOverCellular(ctx, submission, req.Text, opts, &result)
	}
	fields := []interface{}{
		"channel", string(result.Channel),
		"to_fingerprint", logger.Fingerprint(result.To),
		"parts", result.PartsTotal,
		"delivery_state", result.DeliveryState,
		"elapsed_ms", time.Since(started).Milliseconds(),
	}
	if err != nil {
		logger.Warn(fmt.Sprintf("[%s] 短信发送失败", deviceID), append(fields, "err", logger.RedactText(err.Error()))...)
		return result, err
	}
	logger.Info(fmt.Sprintf("[%s] 短信已提交", deviceID), fields...)
	return result, nil
}

// sendSMSOverIMS hands a prepared message to the IMS engine. The engine
// reports a submission it accepted to the message history itself; one that
// failed is recorded here.
func (p *Pool) sendSMSOverIMS(ctx context.Context, inst *runtimehost.Instance, worker *Worker, submission *smscodec.Submission, text string, result *SMSSendResult) error {
	outcome, err := sendPreparedVoWiFiSMS(ctx, inst, worker, worker.ID, submission, text)
	if outcome.PartsTotal > 0 {
		result.PartsTotal = outcome.PartsTotal
	}
	result.MessageID = strings.TrimSpace(outcome.MessageID)
	if err != nil {
		result.DeliveryState = NormalizeSMSDeliveryState(outcome.DeliveryState, db.SMSDeliveryStateFailed)
		if recordErr := RecordVoWiFiSMSSendFailure(p, worker.ID, result.MessageID, result.To, text, time.Now()); recordErr != nil {
			logger.Warn(fmt.Sprintf("[%s] 发送失败的短信未能写入历史", worker.ID), "channel", string(result.Channel), "err", recordErr)
		}
		return err
	}
	result.DeliveryState = NormalizeSMSDeliveryState(outcome.DeliveryState, db.SMSDeliveryStatePending)
	return nil
}

// sendSMSOverCellular hands a prepared message to the modem and records the
// outcome in the message history.
func (w *Worker) sendSMSOverCellular(ctx context.Context, submission *smscodec.Submission, text string, opts smscodec.SubmitOptions, result *SMSSendResult) error {
	// Read before sending: a modem that has just failed to send may not answer.
	imsi := w.GetIMSI()

	err := w.submitPreparedSMS(ctx, submission, text, opts)
	status := smsHistoryStatusFailed
	if err == nil {
		status = smsHistoryStatusSent
		result.DeliveryState = db.SMSDeliveryStateAcked
	}
	if imsi != "" {
		if saveErr := db.SaveSMS(imsi, w.ID, result.To, text, smsHistoryTypeSent, status, time.Now()); saveErr != nil {
			logger.Warn(fmt.Sprintf("[%s] 发出的短信未能写入历史", w.ID), "channel", string(result.Channel), "err", saveErr)
		}
	}
	return err
}

// submitPreparedSMS sends a prepared message through the modem of the device.
func (w *Worker) submitPreparedSMS(ctx context.Context, submission *smscodec.Submission, text string, opts smscodec.SubmitOptions) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cellularSMSSendTimeout)
	defer cancel()

	if w.Backend != nil {
		if sender, ok := w.Backend.(backend.PreparedSMSSender); ok {
			return sender.SendPreparedSMS(ctx, submission)
		}
		// A backend that only takes text encodes the message itself.
		if sender, ok := w.Backend.(interface {
			SendSMSWithOptions(context.Context, string, string, smscodec.SubmitOptions) error
		}); ok {
			return sender.SendSMSWithOptions(ctx, submission.To(), text, opts)
		}
		if encoding, _ := smscodec.NormalizeSMSEncoding(string(opts.Encoding)); encoding != smscodec.SMSEncodingAuto {
			return fmt.Errorf("设备 %s 的短信后端不支持编码选项: %s", w.ID, opts.Encoding)
		}
		return w.Backend.SendSMS(ctx, submission.To(), text)
	}
	if w.Modem != nil {
		return w.Modem.SendPreparedSMS(submission)
	}
	return fmt.Errorf("设备 %s 无可用的短信发送后端", w.ID)
}
