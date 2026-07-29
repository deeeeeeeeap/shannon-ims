package voiceclient

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

func TestSendSMSDoesNotLoseDeliveryReportImmediatelyAfterAccepted(t *testing.T) {
	conn := newScriptedSMSConn()
	store := newOrderedSMSDeliveryStore(&conn.networkStarted)
	cfg := Config{
		DeviceID:        "test-device",
		LocalIP:         net.ParseIP("192.0.2.10"),
		LocalPort:       5062,
		ContactPort:     5063,
		PCSCFAddr:       net.JoinHostPort("192.0.2.20", "5090"),
		SecurityVerify:  "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=1;spi-s=2;port-c=5062;port-s=5063",
		SMSC:            "sip:smsc@ims.example.invalid",
		Realm:           "ims.example.invalid",
		PrivateID:       "subscriber@ims.example.invalid",
		PublicURI:       "sip:subscriber@ims.example.invalid",
		IMSI:            "synthetic-imsi",
		HomeDomain:      "ims.example.invalid",
		SkipRegister:    true,
		DeliveryStore:   store,
		RegisterProfile: SimAdminGBEERegisterProfile(),
	}
	client, err := AttachSecureStreamMessaging(context.Background(), cfg, conn)
	if err != nil {
		t.Fatalf("AttachSecureStreamMessaging: %v", err)
	}
	defer client.Close(context.Background())

	serverDone := make(chan error, 1)
	go func() {
		requestPayload, err := conn.nextClientWrite()
		if err != nil {
			serverDone <- err
			return
		}
		message, err := sip.NewParser().ParseSIP(requestPayload)
		if err != nil {
			serverDone <- err
			return
		}
		request, ok := message.(*sip.Request)
		if !ok {
			serverDone <- errors.New("outbound frame is not a SIP request")
			return
		}
		conn.queueInbound([]byte(sip.NewResponseFromRequest(request, 202, "Accepted", nil).String()))

		report := sip.NewRequest(sip.MESSAGE, request.Recipient)
		report.AppendHeader(sip.NewHeader("Via", "SIP/2.0/TCP 192.0.2.20:5090;branch=z9hG4bK-report"))
		report.AppendHeader(sip.NewHeader("From", "<sip:network@ims.example.invalid>;tag=report"))
		report.AppendHeader(sip.NewHeader("To", "<sip:subscriber@ims.example.invalid>"))
		report.AppendHeader(sip.NewHeader("Call-ID", "delivery-report"))
		report.AppendHeader(sip.NewHeader("CSeq", "1 MESSAGE"))
		report.AppendHeader(sip.NewHeader("Content-Type", smsContentType))
		report.SetBody([]byte{0x03, 0x2a})
		conn.queueInbound([]byte(report.String()))

		responsePayload, err := conn.nextServerWrite()
		if err != nil {
			serverDone <- err
			return
		}
		responseMessage, err := sip.NewParser().ParseSIP(responsePayload)
		if err != nil {
			serverDone <- err
			return
		}
		response, ok := responseMessage.(*sip.Response)
		if !ok || response.StatusCode != sip.StatusOK {
			serverDone <- errors.New("delivery report was not acknowledged")
			return
		}
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	outcome, err := client.SendSMS(ctx, "sip:peer@ims.example.invalid", "synthetic", []messaging.SMSPart{{RPMR: 0x2a, Body: []byte{0x01}}})
	if err != nil {
		t.Fatalf("SendSMS: %v", err)
	}
	if outcome.DeliveryState != "pending" {
		t.Fatalf("DeliveryState = %q, want pending submission semantics", outcome.DeliveryState)
	}
	select {
	case <-store.reportDone:
	case <-ctx.Done():
		t.Fatal("delivery report was not processed")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

	status, err := store.GetSMSDeliveryStatus(outcome.MessageID)
	if err != nil {
		t.Fatalf("GetSMSDeliveryStatus: %v", err)
	}
	if len(status.Parts) != 1 || status.Parts[0].State != "acked" {
		t.Fatalf("delivery parts = %+v, want one acked part", status.Parts)
	}
}

func TestSendSMSCreatesDeliveryWithConfiguredIMSI(t *testing.T) {
	conn := newScriptedSMSConn()
	store := &capturingSMSDeliveryStore{}
	cfg := Config{
		DeviceID:        "test-device",
		LocalIP:         net.ParseIP("192.0.2.10"),
		LocalPort:       5062,
		ContactPort:     5063,
		PCSCFAddr:       net.JoinHostPort("192.0.2.20", "5090"),
		SecurityVerify:  "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=1;spi-s=2;port-c=5062;port-s=5063",
		SMSC:            "sip:smsc@ims.example.invalid",
		Realm:           "ims.example.invalid",
		PrivateID:       "subscriber@ims.example.invalid",
		PublicURI:       "sip:subscriber@ims.example.invalid",
		IMSI:            "synthetic-imsi",
		HomeDomain:      "ims.example.invalid",
		SkipRegister:    true,
		DeliveryStore:   store,
		RegisterProfile: SimAdminGBEERegisterProfile(),
	}
	client, err := AttachSecureStreamMessaging(context.Background(), cfg, conn)
	if err != nil {
		t.Fatalf("AttachSecureStreamMessaging: %v", err)
	}
	defer client.Close(context.Background())

	serverDone := make(chan error, 1)
	go func() {
		requestPayload, err := conn.nextClientWrite()
		if err != nil {
			serverDone <- err
			return
		}
		message, err := sip.NewParser().ParseSIP(requestPayload)
		if err != nil {
			serverDone <- err
			return
		}
		request, ok := message.(*sip.Request)
		if !ok {
			serverDone <- errors.New("outbound frame is not a SIP request")
			return
		}
		conn.queueInbound([]byte(sip.NewResponseFromRequest(request, 202, "Accepted", nil).String()))
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.SendSMS(ctx, "sip:peer@ims.example.invalid", "synthetic", []messaging.SMSPart{{RPMR: 0x2a, Body: []byte{0x01}}}); err != nil {
		t.Fatalf("SendSMS: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if got := store.createdIMSI(); got != "synthetic-imsi" {
		t.Fatalf("delivery IMSI = %q, want configured synthetic IMSI", got)
	}
}

func TestSendSMSMarksPreparedPartFailedWhenGatewayRejectsSubmission(t *testing.T) {
	conn := newScriptedSMSConn()
	store := newOrderedSMSDeliveryStore(&conn.networkStarted)
	cfg := Config{
		DeviceID:        "test-device",
		LocalIP:         net.ParseIP("192.0.2.10"),
		LocalPort:       5062,
		ContactPort:     5063,
		PCSCFAddr:       net.JoinHostPort("192.0.2.20", "5090"),
		SecurityVerify:  "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=1;spi-s=2;port-c=5062;port-s=5063",
		SMSC:            "sip:smsc@ims.example.invalid",
		Realm:           "ims.example.invalid",
		PrivateID:       "subscriber@ims.example.invalid",
		PublicURI:       "sip:subscriber@ims.example.invalid",
		IMSI:            "synthetic-imsi",
		HomeDomain:      "ims.example.invalid",
		SkipRegister:    true,
		DeliveryStore:   store,
		RegisterProfile: SimAdminGBEERegisterProfile(),
	}
	client, err := AttachSecureStreamMessaging(context.Background(), cfg, conn)
	if err != nil {
		t.Fatalf("AttachSecureStreamMessaging: %v", err)
	}
	defer client.Close(context.Background())

	serverDone := make(chan error, 1)
	go func() {
		requestPayload, err := conn.nextClientWrite()
		if err != nil {
			serverDone <- err
			return
		}
		message, err := sip.NewParser().ParseSIP(requestPayload)
		if err != nil {
			serverDone <- err
			return
		}
		request, ok := message.(*sip.Request)
		if !ok {
			serverDone <- errors.New("outbound frame is not a SIP request")
			return
		}
		conn.queueInbound([]byte(sip.NewResponseFromRequest(request, 500, "Rejected", nil).String()))
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	outcome, err := client.SendSMS(ctx, "sip:peer@ims.example.invalid", "synthetic", []messaging.SMSPart{{RPMR: 0x2a, Body: []byte{0x01}}})
	if err == nil {
		t.Fatal("SendSMS() error=nil for rejected submission")
	}
	if outcome.MessageID == "" || outcome.DeliveryState != "failed" {
		t.Fatalf("failed outcome missing tracking metadata: message_id_present=%v state=%q", outcome.MessageID != "", outcome.DeliveryState)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	status, statusErr := store.GetSMSDeliveryStatus(outcome.MessageID)
	if statusErr != nil {
		t.Fatalf("GetSMSDeliveryStatus: %v", statusErr)
	}
	if len(status.Parts) != 1 || status.Parts[0].State != "failed" {
		t.Fatalf("delivery parts = %+v, want one failed part", status.Parts)
	}
}

func TestSendSMSKeepsTrackingOutcomeWhenRequestConstructionFails(t *testing.T) {
	conn := newScriptedSMSConn()
	store := &capturingSMSDeliveryStore{}
	cfg := Config{
		DeviceID:        "test-device",
		LocalIP:         net.ParseIP("192.0.2.10"),
		LocalPort:       5062,
		ContactPort:     5063,
		PCSCFAddr:       net.JoinHostPort("192.0.2.20", "5090"),
		SMSC:            "sip:[",
		Realm:           "ims.example.invalid",
		PrivateID:       "subscriber@ims.example.invalid",
		PublicURI:       "sip:subscriber@ims.example.invalid",
		IMSI:            "synthetic-imsi",
		HomeDomain:      "ims.example.invalid",
		SkipRegister:    true,
		DeliveryStore:   store,
		RegisterProfile: SimAdminGBEERegisterProfile(),
	}
	client, err := AttachSecureStreamMessaging(context.Background(), cfg, conn)
	if err != nil {
		t.Fatalf("AttachSecureStreamMessaging: %v", err)
	}
	defer client.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	outcome, err := client.SendSMS(ctx, "sip:peer@ims.example.invalid", "synthetic", []messaging.SMSPart{{RPMR: 0x2a, Body: []byte{0x01}}})
	if err == nil {
		t.Fatal("SendSMS() error=nil for malformed service-centre URI")
	}
	if !strings.Contains(err.Error(), "parse target uri") {
		t.Fatalf("SendSMS() error=%v, want request-construction failure", err)
	}
	if outcome.MessageID == "" || outcome.DeliveryState != "failed" {
		t.Fatalf("request-construction failure lost tracking outcome: message_id_present=%v state=%q", outcome.MessageID != "", outcome.DeliveryState)
	}
	if got := store.upsertCallCount(); got != 1 {
		t.Fatalf("request-construction failure prepared terminal parts=%d, want 1", got)
	}
	if got := store.lastUpdatedAcks(); got != -1 {
		t.Fatalf("request-construction failure aggregate ACK update=%d, want preserve sentinel -1", got)
	}
}

func TestSendSMSKeepsTrackingOutcomeWhenPartPreparationFails(t *testing.T) {
	conn := newScriptedSMSConn()
	store := &capturingSMSDeliveryStore{failUpsertAt: 1}
	cfg := Config{
		DeviceID:        "test-device",
		LocalIP:         net.ParseIP("192.0.2.10"),
		LocalPort:       5062,
		ContactPort:     5063,
		PCSCFAddr:       net.JoinHostPort("192.0.2.20", "5090"),
		SMSC:            "sip:smsc@ims.example.invalid",
		Realm:           "ims.example.invalid",
		PrivateID:       "subscriber@ims.example.invalid",
		PublicURI:       "sip:subscriber@ims.example.invalid",
		IMSI:            "synthetic-imsi",
		HomeDomain:      "ims.example.invalid",
		SkipRegister:    true,
		DeliveryStore:   store,
		RegisterProfile: SimAdminGBEERegisterProfile(),
	}
	client, err := AttachSecureStreamMessaging(context.Background(), cfg, conn)
	if err != nil {
		t.Fatalf("AttachSecureStreamMessaging: %v", err)
	}
	defer client.Close(context.Background())

	outcome, err := client.SendSMS(context.Background(), "sip:peer@ims.example.invalid", "synthetic", []messaging.SMSPart{{RPMR: 0x2a, Body: []byte{0x01}}})
	if err == nil || !strings.Contains(err.Error(), "prepare SMS delivery part") {
		t.Fatalf("SendSMS() error=%v, want part-preparation failure", err)
	}
	if outcome.MessageID == "" || outcome.DeliveryState != "failed" {
		t.Fatalf("part-preparation failure lost tracking outcome: message_id_present=%v state=%q", outcome.MessageID != "", outcome.DeliveryState)
	}
}

func TestSendSMSKeepsPendingOutcomeWhenFinalCorrelationWriteFails(t *testing.T) {
	conn := newScriptedSMSConn()
	store := &capturingSMSDeliveryStore{failUpsertAt: 2}
	cfg := Config{
		DeviceID:        "test-device",
		LocalIP:         net.ParseIP("192.0.2.10"),
		LocalPort:       5062,
		ContactPort:     5063,
		PCSCFAddr:       net.JoinHostPort("192.0.2.20", "5090"),
		SMSC:            "sip:smsc@ims.example.invalid",
		Realm:           "ims.example.invalid",
		PrivateID:       "subscriber@ims.example.invalid",
		PublicURI:       "sip:subscriber@ims.example.invalid",
		IMSI:            "synthetic-imsi",
		HomeDomain:      "ims.example.invalid",
		SkipRegister:    true,
		DeliveryStore:   store,
		RegisterProfile: SimAdminGBEERegisterProfile(),
	}
	client, err := AttachSecureStreamMessaging(context.Background(), cfg, conn)
	if err != nil {
		t.Fatalf("AttachSecureStreamMessaging: %v", err)
	}
	defer client.Close(context.Background())

	serverDone := make(chan error, 1)
	go func() {
		payload, err := conn.nextClientWrite()
		if err != nil {
			serverDone <- err
			return
		}
		message, err := sip.NewParser().ParseSIP(payload)
		if err != nil {
			serverDone <- err
			return
		}
		request, ok := message.(*sip.Request)
		if !ok {
			serverDone <- errors.New("outbound frame is not a SIP request")
			return
		}
		conn.queueInbound([]byte(sip.NewResponseFromRequest(request, 202, "Accepted", nil).String()))
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	outcome, err := client.SendSMS(ctx, "sip:peer@ims.example.invalid", "synthetic", []messaging.SMSPart{{RPMR: 0x2a, Body: []byte{0x01}}})
	if err == nil || !strings.Contains(err.Error(), "UpsertSMSDeliveryPart") {
		t.Fatalf("SendSMS() error=%v, want final correlation write failure", err)
	}
	if outcome.MessageID == "" || outcome.DeliveryState != "pending" {
		t.Fatalf("post-202 correlation failure lost pending outcome: message_id_present=%v state=%q", outcome.MessageID != "", outcome.DeliveryState)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

type scriptedSMSConn struct {
	networkStarted atomic.Bool
	clientWrites   chan []byte
	inbound        chan []byte
	serverWrites   chan []byte
	closed         chan struct{}
	closeOnce      sync.Once
}

func newScriptedSMSConn() *scriptedSMSConn {
	return &scriptedSMSConn{
		clientWrites: make(chan []byte, 1),
		inbound:      make(chan []byte, 2),
		serverWrites: make(chan []byte, 1),
		closed:       make(chan struct{}),
	}
}

func (c *scriptedSMSConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *scriptedSMSConn) Write(payload []byte) (int, error) {
	c.networkStarted.Store(true)
	copyPayload := append([]byte(nil), payload...)
	select {
	case c.clientWrites <- copyPayload:
		return len(payload), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *scriptedSMSConn) ReadSIPMessage() ([]byte, error) {
	select {
	case payload := <-c.inbound:
		return append([]byte(nil), payload...), nil
	case <-c.closed:
		return nil, net.ErrClosed
	}
}

func (c *scriptedSMSConn) WriteServerFlow(payload []byte) (int, error) {
	copyPayload := append([]byte(nil), payload...)
	select {
	case c.serverWrites <- copyPayload:
		return len(payload), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *scriptedSMSConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*scriptedSMSConn) LocalAddr() net.Addr              { return scriptedSMSAddr("local") }
func (*scriptedSMSConn) RemoteAddr() net.Addr             { return scriptedSMSAddr("remote") }
func (*scriptedSMSConn) SetDeadline(time.Time) error      { return nil }
func (*scriptedSMSConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedSMSConn) SetWriteDeadline(time.Time) error { return nil }
func (c *scriptedSMSConn) queueInbound(payload []byte)    { c.inbound <- append([]byte(nil), payload...) }

func (c *scriptedSMSConn) nextClientWrite() ([]byte, error) {
	select {
	case payload := <-c.clientWrites:
		return payload, nil
	case <-c.closed:
		return nil, net.ErrClosed
	}
}

func (c *scriptedSMSConn) nextServerWrite() ([]byte, error) {
	select {
	case payload := <-c.serverWrites:
		return payload, nil
	case <-c.closed:
		return nil, net.ErrClosed
	}
}

type scriptedSMSAddr string

func (a scriptedSMSAddr) Network() string { return "test" }
func (a scriptedSMSAddr) String() string  { return string(a) }

type orderedSMSDeliveryStore struct {
	networkStarted *atomic.Bool

	mu              sync.Mutex
	messageID       string
	imsi            string
	deviceID        string
	part            *messaging.DeliveryPartStatus
	reportAttempted chan struct{}
	reportDone      chan struct{}
	reportOnce      sync.Once
}

type capturingSMSDeliveryStore struct {
	mu           sync.Mutex
	imsi         string
	upsertCalls  int
	failUpsertAt int
	updatedState string
	updatedAcks  int
}

func (s *capturingSMSDeliveryStore) CreateSMSDelivery(_, imsi, _, _, _ string, _ int, _ time.Time) error {
	s.mu.Lock()
	s.imsi = imsi
	s.mu.Unlock()
	return nil
}

func (s *capturingSMSDeliveryStore) UpsertSMSDeliveryPart(string, int, string, int, string, time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsertCalls++
	if s.failUpsertAt > 0 && s.upsertCalls == s.failUpsertAt {
		return errors.New("synthetic delivery store failure")
	}
	return nil
}

func (*capturingSMSDeliveryStore) MarkSMSDeliveryPartReport(string, string, string, int, string, int, int, string, time.Time) (messaging.DeliveryPartMatch, error) {
	return messaging.DeliveryPartMatch{}, messaging.ErrDeliveryNotFound
}

func (*capturingSMSDeliveryStore) RecomputeSMSDelivery(string, time.Time) error { return nil }

func (s *capturingSMSDeliveryStore) UpdateSMSDeliveryState(_ string, state, _ string, acks int, _ time.Time) error {
	s.mu.Lock()
	s.updatedState = state
	s.updatedAcks = acks
	s.mu.Unlock()
	return nil
}

func (*capturingSMSDeliveryStore) GetSMSDeliveryStatus(string) (*messaging.DeliveryStatus, error) {
	return nil, messaging.ErrDeliveryNotFound
}

func (s *capturingSMSDeliveryStore) createdIMSI() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.imsi
}

func (s *capturingSMSDeliveryStore) upsertCallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upsertCalls
}

func (s *capturingSMSDeliveryStore) lastUpdatedAcks() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updatedAcks
}

func newOrderedSMSDeliveryStore(networkStarted *atomic.Bool) *orderedSMSDeliveryStore {
	return &orderedSMSDeliveryStore{
		networkStarted:  networkStarted,
		reportAttempted: make(chan struct{}),
		reportDone:      make(chan struct{}),
	}
}

func (s *orderedSMSDeliveryStore) CreateSMSDelivery(messageID, imsi, deviceID, _, _ string, _ int, _ time.Time) error {
	s.mu.Lock()
	s.messageID = messageID
	s.imsi = imsi
	s.deviceID = deviceID
	s.mu.Unlock()
	return nil
}

func (s *orderedSMSDeliveryStore) UpsertSMSDeliveryPart(_ string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error {
	s.mu.Lock()
	partMissing := s.part == nil
	s.mu.Unlock()
	if partMissing && s.networkStarted.Load() {
		<-s.reportAttempted
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.part == nil {
		s.part = &messaging.DeliveryPartStatus{PartNo: partNo, CallID: callID, RPMR: rpMR, State: state, SentAt: sentAt}
		return nil
	}
	s.part.CallID = callID
	s.part.RPMR = rpMR
	if s.part.State != "acked" && s.part.State != "failed" {
		s.part.State = state
	}
	return nil
}

func (s *orderedSMSDeliveryStore) MarkSMSDeliveryPartReport(_, _ string, deviceID string, rpMR int, state string, _ int, _ int, _ string, _ time.Time) (messaging.DeliveryPartMatch, error) {
	s.reportOnce.Do(func() { close(s.reportAttempted) })
	s.mu.Lock()
	defer s.mu.Unlock()
	defer close(s.reportDone)
	if s.part == nil || s.deviceID != deviceID || s.part.RPMR != rpMR {
		return messaging.DeliveryPartMatch{}, messaging.ErrDeliveryNotFound
	}
	s.part.State = state
	return messaging.DeliveryPartMatch{MessageID: s.messageID, PartNo: s.part.PartNo, State: state}, nil
}

func (*orderedSMSDeliveryStore) RecomputeSMSDelivery(string, time.Time) error { return nil }

func (*orderedSMSDeliveryStore) UpdateSMSDeliveryState(string, string, string, int, time.Time) error {
	return nil
}

func (s *orderedSMSDeliveryStore) GetSMSDeliveryStatus(messageID string) (*messaging.DeliveryStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(messageID) == "" || messageID != s.messageID {
		return nil, messaging.ErrDeliveryNotFound
	}
	status := &messaging.DeliveryStatus{MessageID: s.messageID, IMSI: s.imsi, DeviceID: s.deviceID, State: "pending"}
	if s.part != nil {
		status.Parts = []messaging.DeliveryPartStatus{*s.part}
		status.State = s.part.State
	}
	return status, nil
}
