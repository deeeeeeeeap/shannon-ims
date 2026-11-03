package voiceclient

import (
	"errors"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

type failingStatusStore struct {
	messaging.DeliveryStore
	err error
}

func (s failingStatusStore) MarkSMSDeliveryPartStatusReport(string, string, string, int, string, int, time.Time) (messaging.DeliveryPartMatch, error) {
	return messaging.DeliveryPartMatch{}, s.err
}

func TestStatusReportStorageFailureIsNotAcknowledged(t *testing.T) {
	c := &Client{cfg: Config{DeliveryStore: failingStatusStore{err: errors.New("storage unavailable")}}}
	response, ack := c.incomingMessageResult(newSyntheticStatusReportRequest(1, 2, 0))
	if response.StatusCode != 503 || ack != nil {
		t.Fatal("temporary storage failure was acknowledged and would lose the report")
	}
	c.cfg.DeliveryStore = failingStatusStore{err: messaging.ErrDeliveryNotFound}
	response, ack = c.incomingMessageResult(newSyntheticStatusReportRequest(1, 2, 0))
	if response.StatusCode != 200 || ack == nil {
		t.Fatal("an unmatched report should terminate without updating an unrelated message")
	}
}
