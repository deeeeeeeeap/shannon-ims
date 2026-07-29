package voiceclient

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

func TestClassifySMSStatusReportExtractsInnerReferenceAndDeliveredStatus(t *testing.T) {
	report, err := classifySMSStatusReport(syntheticSMSStatusReportRPData(0x71, 0x2a, 0x00))
	if err != nil {
		t.Fatalf("classifySMSStatusReport: %v", err)
	}
	if report.rpMR != 0x71 || report.tpMR != 0x2a {
		t.Fatal("status report references were not parsed from their respective layers")
	}
	if report.disposition.String() != "delivered" || report.recipient != "55501" {
		t.Fatal("status report delivery disposition or recipient mismatch")
	}
}

func TestIncomingStatusReportEmitsOnlyBoundedDiagnosticMetadata(t *testing.T) {
	core, observed := observer.New(zap.InfoLevel)
	previousLogger := logger.Get()
	logger.SetLogger(zap.New(core))
	t.Cleanup(func() { logger.SetLogger(previousLogger) })

	store := &statusReportDeliveryStore{statusDone: make(chan struct{})}
	client := &Client{cfg: Config{IMSI: "synthetic-imsi", DeviceID: "synthetic-device", DeliveryStore: store}}
	request := newSyntheticSMSReportRequest(t, syntheticSMSStatusReportRPData(0x71, 0x2a, 0x00))
	request.AppendHeader(sip.NewHeader("P-Asserted-Identity", "<sip:ipsmgw@ims.example.invalid>"))
	if response := client.incomingMessageResponse(request); response.StatusCode != sip.StatusOK {
		t.Fatalf("response status=%d", response.StatusCode)
	}
	entries := observed.FilterMessage("IMS SMS status report").All()
	if len(entries) != 1 {
		t.Fatalf("status report diagnostic events=%d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	allowed := map[string]bool{
		"report_kind":        true,
		"tp_status_class":    true,
		"tp_status":          true,
		"correlation_method": true,
		"part_index":         true,
	}
	if len(fields) != len(allowed) {
		t.Fatalf("status report diagnostic fields=%d, want %d", len(fields), len(allowed))
	}
	for key := range fields {
		if !allowed[key] {
			t.Fatalf("non-allowlisted status report field %q", key)
		}
	}
	if fields["report_kind"] != "sms_status_report" || fields["tp_status_class"] != "delivered" ||
		fields["tp_status"] != int64(0) || fields["correlation_method"] != "tp_mr" || fields["part_index"] != int64(1) {
		t.Fatal("status report diagnostic metadata mismatch")
	}
}

func TestStatusReportRPAckDiagnosticUsesStrictFieldWhitelist(t *testing.T) {
	core, observed := observer.New(zap.InfoLevel)
	previousLogger := logger.Get()
	logger.SetLogger(zap.New(core))
	t.Cleanup(func() { logger.SetLogger(previousLogger) })

	(&Client{}).logStatusReportRPAckResult("accepted")
	entries := observed.FilterMessage("IMS SMS status report RP-ACK").All()
	if len(entries) != 1 {
		t.Fatalf("RP-ACK diagnostic events=%d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if len(fields) != 2 || fields["stage"] != "status_report_rp_ack" || fields["rp_ack_result"] != "accepted" {
		t.Fatalf("RP-ACK diagnostic fields=%v", fields)
	}
}

func TestClassifySMSStatusReportRejectsCommandReport(t *testing.T) {
	body := syntheticSMSStatusReportRPData(0x71, 0x2a, 0x00)
	body[5] |= 0x20
	if _, err := classifySMSStatusReport(body); err == nil {
		t.Fatal("SMS-STATUS-REPORT with TP-SRQ=1 was accepted")
	}
}

func TestClassifyTPStatusDoesNotOverstateCompletedOrTemporaryReports(t *testing.T) {
	tests := []struct {
		status byte
		want   string
	}{
		{0x00, "delivered"},
		{0x01, "forwarded_unconfirmed"},
		{0x02, "replaced"},
		{0x1f, "completed_unconfirmed"},
		{0x20, "temporary_retrying"},
		{0x40, "permanent_failure"},
		{0x60, "temporary_stopped"},
		{0x80, "unknown"},
	}
	for _, test := range tests {
		if got := classifyTPStatus(test.status).String(); got != test.want {
			t.Fatalf("TP-ST 0x%02x classified as %q, want %q", test.status, got, test.want)
		}
	}
}

func TestSecureStreamStatusReportUpdatesDeliveryAndSendsRPAck(t *testing.T) {
	conn := newScriptedSMSConn()
	store := &statusReportDeliveryStore{statusDone: make(chan struct{})}
	client := newStatusReportTestClient(t, conn, store)
	defer client.Close(context.Background())

	request := newSyntheticStatusReportRequest(0x71, 0x2a, 0x00)

	serverDone := make(chan error, 1)
	go func() {
		conn.queueInbound([]byte(request.String()))
		responsePayload, err := conn.nextServerWrite()
		if err != nil {
			serverDone <- err
			return
		}
		message, err := sip.NewParser().ParseSIP(responsePayload)
		if err != nil {
			serverDone <- err
			return
		}
		response, ok := message.(*sip.Response)
		if !ok || response.StatusCode != sip.StatusOK {
			serverDone <- errors.New("status report did not receive SIP 200")
			return
		}
		ackPayload, err := conn.nextClientWrite()
		if err != nil {
			serverDone <- err
			return
		}
		message, err = sip.NewParser().ParseSIP(ackPayload)
		if err != nil {
			serverDone <- err
			return
		}
		ack, ok := message.(*sip.Request)
		if !ok || ack.Method != sip.MESSAGE || ack.Recipient.String() != "sip:ipsmgw@ims.example.invalid" || string(ack.Body()) != string([]byte{0x02, 0x71}) {
			serverDone <- errors.New("independent RP-ACK did not use inbound RP-MR")
			return
		}
		conn.queueInbound([]byte(sip.NewResponseFromRequest(ack, 200, "OK", nil).String()))
		serverDone <- nil
	}()

	select {
	case <-store.statusDone:
	case <-time.After(time.Second):
		t.Fatal("status report did not update delivery state")
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("status report RP-ACK flow did not complete")
	}
	if store.tpMR != 0x2a || store.state != "delivered" || store.recipient != "55501" {
		t.Fatal("status report store metadata mismatch")
	}
}

func TestSecureStreamMalformedStatusReportDoesNotUpdateOrAcknowledgeRP(t *testing.T) {
	conn := newScriptedSMSConn()
	store := &statusReportDeliveryStore{statusDone: make(chan struct{})}
	client := newStatusReportTestClient(t, conn, store)
	defer client.Close(context.Background())

	request := newSyntheticStatusReportRequest(0x71, 0x2a, 0x00)
	request.SetBody(request.Body()[:len(request.Body())-1])
	conn.queueInbound([]byte(request.String()))
	if _, err := conn.nextServerWrite(); err != nil {
		t.Fatal(err)
	}

	barrier := sip.NewRequest(sip.OPTIONS, sip.Uri{Scheme: "sip", User: "subscriber", Host: "ims.example.invalid"})
	barrier.AppendHeader(sip.NewHeader("Via", "SIP/2.0/TCP 192.0.2.20:5090;branch=z9hG4bK-barrier"))
	barrier.AppendHeader(sip.NewHeader("From", "<sip:network@ims.example.invalid>;tag=barrier"))
	barrier.AppendHeader(sip.NewHeader("To", "<sip:subscriber@ims.example.invalid>"))
	barrier.AppendHeader(sip.NewHeader("Call-ID", "status-report-barrier"))
	barrier.AppendHeader(sip.NewHeader("CSeq", "2 OPTIONS"))
	conn.queueInbound([]byte(barrier.String()))
	if _, err := conn.nextServerWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.statusDone:
		t.Fatal("malformed status report updated delivery state")
	default:
	}
	select {
	case <-conn.clientWrites:
		t.Fatal("malformed status report generated RP-ACK")
	default:
	}
}

func TestSecureStreamStatusReportRPAckIsCanceledAndJoinedByClose(t *testing.T) {
	conn := newScriptedSMSConn()
	store := &statusReportDeliveryStore{statusDone: make(chan struct{})}
	client := newStatusReportTestClient(t, conn, store)
	request := newSyntheticStatusReportRequest(0x72, 0x2b, 0x00)
	conn.queueInbound([]byte(request.String()))
	if _, err := conn.nextServerWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.nextClientWrite(); err != nil {
		t.Fatal(err)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close(context.Background()) }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join in-flight status report RP-ACK")
	}
}

func TestSecureStreamDuplicateStatusReportsAreIdempotentlyUpdatedAndEachAcknowledged(t *testing.T) {
	conn := newScriptedSMSConn()
	store := &countingStatusReportStore{}
	client := newStatusReportTestClient(t, conn, store)
	defer client.Close(context.Background())

	for index, rpMR := range []byte{0x73, 0x74} {
		request := newSyntheticStatusReportRequest(rpMR, 0x2c, 0x00)
		request.RemoveHeader("Call-ID")
		request.AppendHeader(sip.NewHeader("Call-ID", string(rune('a'+index))+"-status-report"))
		conn.queueInbound([]byte(request.String()))
		if _, err := conn.nextServerWrite(); err != nil {
			t.Fatal(err)
		}
		ackPayload, err := conn.nextClientWrite()
		if err != nil {
			t.Fatal(err)
		}
		message, err := sip.NewParser().ParseSIP(ackPayload)
		if err != nil {
			t.Fatal(err)
		}
		ack, ok := message.(*sip.Request)
		if !ok || string(ack.Body()) != string([]byte{0x02, rpMR}) {
			t.Fatal("duplicate status transaction did not receive its own RP-ACK")
		}
		conn.queueInbound([]byte(sip.NewResponseFromRequest(ack, 200, "OK", nil).String()))
	}
	if calls := store.callCount(); calls != 2 {
		t.Fatalf("status report updates=%d, want 2 idempotent attempts", calls)
	}
}

func newStatusReportTestClient(t *testing.T, conn *scriptedSMSConn, store messaging.DeliveryStore) *Client {
	t.Helper()
	client, err := AttachSecureStreamMessaging(context.Background(), Config{
		DeviceID:       "test-device",
		LocalIP:        net.ParseIP("192.0.2.10"),
		LocalPort:      5062,
		ContactPort:    5063,
		PCSCFAddr:      net.JoinHostPort("192.0.2.20", "5090"),
		SecurityVerify: "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=1;spi-s=2;port-c=5062;port-s=5063",
		SMSC:           "sip:smsc@ims.example.invalid",
		Realm:          "ims.example.invalid",
		PrivateID:      "subscriber@ims.example.invalid",
		PublicURI:      "sip:subscriber@ims.example.invalid",
		IMSI:           "synthetic-imsi",
		HomeDomain:     "ims.example.invalid",
		DeliveryStore:  store,
	}, conn)
	if err != nil {
		t.Fatalf("AttachSecureStreamMessaging: %v", err)
	}
	return client
}

func newSyntheticStatusReportRequest(rpMR, tpMR, tpStatus byte) *sip.Request {
	request := sip.NewRequest(sip.MESSAGE, sip.Uri{Scheme: "sip", User: "subscriber", Host: "ims.example.invalid"})
	request.AppendHeader(sip.NewHeader("Via", "SIP/2.0/TCP 192.0.2.20:5090;branch=z9hG4bK-status"))
	request.AppendHeader(sip.NewHeader("From", "<sip:network@ims.example.invalid>;tag=status"))
	request.AppendHeader(sip.NewHeader("To", "<sip:subscriber@ims.example.invalid>"))
	request.AppendHeader(sip.NewHeader("P-Asserted-Identity", "<sip:ipsmgw@ims.example.invalid>"))
	request.AppendHeader(sip.NewHeader("Call-ID", "status-report-call"))
	request.AppendHeader(sip.NewHeader("CSeq", "1 MESSAGE"))
	request.AppendHeader(sip.NewHeader("Content-Type", smsContentType))
	request.SetBody(syntheticSMSStatusReportRPData(rpMR, tpMR, tpStatus))
	return request
}

type statusReportDeliveryStore struct {
	capturingSMSDeliveryStore
	statusDone chan struct{}
	tpMR       int
	state      string
	recipient  string
}

type countingStatusReportStore struct {
	capturingSMSDeliveryStore
	mu    sync.Mutex
	calls int
}

func (s *countingStatusReportStore) MarkSMSDeliveryPartStatusReport(_, _, _ string, _ int, state string, _ int, _ time.Time) (messaging.DeliveryPartMatch, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return messaging.DeliveryPartMatch{MessageID: "synthetic", PartNo: 1, State: state, CorrelationMethod: "tp_mr"}, nil
}

func (s *countingStatusReportStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *statusReportDeliveryStore) MarkSMSDeliveryPartStatusReport(_, _, recipient string, tpMR int, state string, _ int, _ time.Time) (messaging.DeliveryPartMatch, error) {
	s.tpMR = tpMR
	s.state = state
	s.recipient = recipient
	close(s.statusDone)
	return messaging.DeliveryPartMatch{MessageID: "synthetic", PartNo: 1, State: state, CorrelationMethod: "tp_mr"}, nil
}

func syntheticSMSStatusReportRPData(rpMR, tpMR, tpStatus byte) []byte {
	tpdu := []byte{
		0x02, tpMR,
		0x05, 0x81, 0x55, 0x05, 0xf1,
		0x62, 0x70, 0x92, 0x21, 0x43, 0x65, 0x00,
		0x62, 0x70, 0x92, 0x21, 0x44, 0x65, 0x00,
		tpStatus,
	}
	body := []byte{0x01, rpMR, 0x00, 0x00, byte(len(tpdu))}
	return append(body, tpdu...)
}
