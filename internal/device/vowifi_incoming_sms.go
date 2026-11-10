package device

import (
	"errors"
	"time"

	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

func (s vowifiDeliveryStore) StoreIncomingSMS(imsi, deviceID string, tpdu []byte, receivedAt time.Time) error {
	if imsi == "" {
		return messaging.ErrInvalidIncomingSMS
	}
	err := s.pool.storeIncomingDeliver(imsi, deviceID, tpdu, incomingSMSViaIMS)
	if errors.Is(err, errIncomingSMSUnusable) {
		return messaging.ErrInvalidIncomingSMS
	}
	return err
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
