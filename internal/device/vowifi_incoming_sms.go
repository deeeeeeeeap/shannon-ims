package device

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/internal/smsnotify"
	"github.com/1239t/vohive/pkg/smscodec"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

func (s vowifiDeliveryStore) StoreIncomingSMS(imsi, deviceID string, tpdu []byte, receivedAt time.Time) error {
	if imsi == "" || len(tpdu) == 0 || tpdu[0]&3 != 0 {
		return messaging.ErrInvalidIncomingSMS
	}
	sender, content, timestamp, concat, err := smscodec.DecodeDeliverTPDU(tpdu)
	if err != nil || sender == "" || timestamp.IsZero() {
		return messaging.ErrInvalidIncomingSMS
	}
	if smsnotify.ShouldSuppressReceivedSMS(content) {
		return nil
	}
	total, sequence := 1, 1
	if concat.IsConcat {
		total, sequence = concat.Total, concat.Seq
		if total < 2 || total > 255 || sequence < 1 || sequence > total {
			return messaging.ErrInvalidIncomingSMS
		}
	}
	// TP-MMS/TP-RP can change on network retransmission without changing the SMS.
	// The dedup key is SIM-scoped and excludes those envelope hint bits.
	h := sha256.New()
	_, _ = h.Write([]byte(imsi))
	_, _ = h.Write([]byte{0, tpdu[0] &^ 0x84})
	_, _ = h.Write(tpdu[1:])
	result, err := db.StoreIncomingSMSPart(db.IncomingSMSPart{
		Fingerprint: hex.EncodeToString(h.Sum(nil)), IMSI: imsi, Sender: sender,
		Content: content, Timestamp: timestamp, Reference: concat.Ref, ReferenceBits: concat.RefBits,
		Total: total, Sequence: sequence,
	}, vowifiReceivedSMSDuplicateWindow)
	if err != nil || !result.Stored {
		return err
	}
	s.pool.notifyStoredIncomingSMS(deviceID, result.SMS, "VoWiFi")
	return nil
}

func (p *Pool) notifyStoredIncomingSMS(deviceID string, sms db.SMS, source string) {
	if p != nil {
		if notifier := p.getNotifier(); notifier != nil {
			if withSource, ok := notifier.(SMSSourceNotifier); ok {
				withSource.NotifySMSWithSource(deviceID, sms.Sender, sms.Content, source, sms.Timestamp)
			} else {
				notifier.NotifySMS(deviceID, sms.Sender, sms.Content, sms.Timestamp)
			}
		}
	}
}
