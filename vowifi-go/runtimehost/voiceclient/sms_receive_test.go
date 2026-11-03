package voiceclient

import (
	"errors"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

type incomingSMSStore struct {
	messaging.DeliveryStore
	calls int
	err   error
}

func (s *incomingSMSStore) StoreIncomingSMS(imsi, deviceID string, tpdu []byte, at time.Time) error {
	s.calls++
	return s.err
}

func TestInboundSMSRequiresDurableStorageBeforeRPAck(t *testing.T) {
	store := &incomingSMSStore{}
	c := &Client{cfg: Config{DeliveryStore: store}}
	req := newSyntheticStatusReportRequest(1, 2, 0)
	req.SetBody(syntheticRPDataWithTPDUFirstOctet(0))
	response, ack := c.incomingMessageResult(req)
	if store.calls != 1 || response.StatusCode != 200 || ack == nil {
		t.Fatal("inbound SMS was not handed to durable storage and acknowledged")
	}
	store.err = errors.New("storage unavailable")
	response, ack = c.incomingMessageResult(req)
	if response.StatusCode != 503 || ack != nil {
		t.Fatal("failed storage must not receive a success ACK")
	}
	store.err = nil
	body := req.Body()
	req.SetBody(append(body, 0))
	response, ack = c.incomingMessageResult(req)
	if response.StatusCode != 400 || ack != nil || store.calls != 2 {
		t.Fatal("invalid RP length reached storage")
	}
}
