package voiceclient

import (
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

func TestClassifyRPEnvelopeRejectsMalformedRPACKUserData(t *testing.T) {
	// RP-ACK may carry one RP-User-Data IE (0x41). The declared length is
	// two octets, but only one follows, so accepting the outer RP type alone
	// would turn a malformed report into a false delivery acknowledgement.
	body := []byte{0x03, 0x2a, 0x41, 0x02, 0x01}

	if _, err := classifyRPEnvelope(body); err == nil {
		t.Fatal("malformed RP-ACK user data was accepted")
	}
}

func TestClassifyRPEnvelopeDistinguishesBareAckAndSuccessfulSubmitReport(t *testing.T) {
	bare, err := classifyRPEnvelope([]byte{0x03, 0x2a})
	if err != nil {
		t.Fatalf("classify bare RP-ACK: %v", err)
	}
	if bare.reportKind != rpReportKindBareAck || bare.hasUserData || bare.hasTPFCS {
		t.Fatal("bare RP-ACK classification mismatch")
	}

	// Successful SMS-SUBMIT-REPORT: first octet, TP-PI, and TP-SCTS. The
	// outer RP-ACK carries it in the optional RP-User-Data IE (0x41).
	submitReport := []byte{0x01, 0x00, 0x62, 0x70, 0x92, 0x51, 0x43, 0x21, 0x00}
	body := append([]byte{0x03, 0x2a, 0x41, byte(len(submitReport))}, submitReport...)
	got, err := classifyRPEnvelope(body)
	if err != nil {
		t.Fatalf("classify successful SMS-SUBMIT-REPORT: %v", err)
	}
	if got.reportKind != rpReportKindSubmitSuccess || !got.hasUserData || got.hasTPFCS {
		t.Fatal("successful SMS-SUBMIT-REPORT classification mismatch")
	}
}

func TestClassifyRPEnvelopeExtractsFailureSubmitReportFromRPError(t *testing.T) {
	// Unsuccessful SMS-SUBMIT-REPORT adds TP-FCS between the first octet and
	// TP-PI and is carried as RP-User-Data on RP-ERROR.
	submitReport := []byte{0x01, 0x90, 0x00, 0x62, 0x70, 0x92, 0x51, 0x43, 0x21, 0x00}
	body := append([]byte{0x05, 0x2a, 0x01, 0x5f, 0x41, byte(len(submitReport))}, submitReport...)

	got, err := classifyRPEnvelope(body)
	if err != nil {
		t.Fatalf("classify RP-ERROR submit report: %v", err)
	}
	if got.kind != rpKindError || got.reportKind != rpReportKindSubmitFailure ||
		!got.hasUserData || !got.hasTPFCS || got.tpFCS != 0x90 || got.cause != 0x5f {
		t.Fatal("failure SMS-SUBMIT-REPORT classification mismatch")
	}
}

func TestClassifyRPEnvelopeKeepsOuterRPErrorAuthoritativeWhenOptionalReportMalformed(t *testing.T) {
	body := []byte{0x05, 0x2a, 0x01, 0x5f, 0x41, 0x01, 0xff}

	got, err := classifyRPEnvelope(body)
	if err != nil {
		t.Fatalf("classify RP-ERROR with malformed optional report: %v", err)
	}
	if got.kind != rpKindError || got.reportKind != rpReportKindSubmitMalformed ||
		!got.hasUserData || got.hasTPFCS || got.cause != 0x5f || got.submitReportKind() != "malformed" {
		t.Fatal("outer RP-ERROR did not remain an authoritative failure")
	}
}

func TestClassifyRPEnvelopeAcceptsBoundedTPPIExtensionChain(t *testing.T) {
	// TP-PI bit 7 announces another TP-PI octet. A zero extension octet adds
	// no optional fields and must not turn a valid success report malformed.
	submitReport := []byte{0x01, 0x80, 0x00, 0x62, 0x70, 0x92, 0x51, 0x43, 0x21, 0x00}
	body := append([]byte{0x03, 0x2a, 0x41, byte(len(submitReport))}, submitReport...)

	got, err := classifyRPEnvelope(body)
	if err != nil {
		t.Fatalf("classify extended TP-PI: %v", err)
	}
	if got.reportKind != rpReportKindSubmitSuccess {
		t.Fatal("extended TP-PI did not retain success classification")
	}
}

func TestClassifyRPEnvelopeIgnoresReservedTPPIExtensionData(t *testing.T) {
	// Reserved bits in the first TP-PI octet and future flags in extension
	// octets announce additional information after the known fields. A legacy
	// receiver discards that bounded tail; it must not lose the outer RP-ACK.
	submitReport := []byte{
		0x01, 0x88, 0x01,
		0x62, 0x70, 0x92, 0x51, 0x43, 0x21, 0x00,
		0xaa, 0xbb,
	}
	body := append([]byte{0x03, 0x2a, 0x41, byte(len(submitReport))}, submitReport...)

	got, err := classifyRPEnvelope(body)
	if err != nil {
		t.Fatalf("classify reserved TP-PI extension data: %v", err)
	}
	if got.reportKind != rpReportKindSubmitSuccess {
		t.Fatal("reserved TP-PI extension data did not retain success classification")
	}
}

func TestClassifyRPEnvelopeRejectsMobileOriginatedReportDirection(t *testing.T) {
	for _, body := range [][]byte{
		{0x02, 0x2a},
		{0x04, 0x2a, 0x01, 0x5f},
	} {
		if _, err := classifyRPEnvelope(body); err == nil {
			t.Fatal("mobile-originated RP report direction was accepted as inbound")
		}
	}
}

func TestIncomingSMSReportEmitsOnlyBoundedDiagnosticMetadata(t *testing.T) {
	core, observed := observer.New(zap.InfoLevel)
	previousLogger := logger.Get()
	logger.SetLogger(zap.New(core))
	t.Cleanup(func() { logger.SetLogger(previousLogger) })

	store := &smsReportDiagnosticStore{}
	client := &Client{cfg: Config{DeviceID: "synthetic-device", DeliveryStore: store}}
	submitReport := []byte{0x01, 0x90, 0x00, 0x62, 0x70, 0x92, 0x51, 0x43, 0x21, 0x00}
	body := append([]byte{0x05, 0x2a, 0x01, 0x5f, 0x41, byte(len(submitReport))}, submitReport...)
	request := newSyntheticSMSReportRequest(t, body)

	response := client.incomingMessageResponse(request)
	if response.StatusCode != sip.StatusOK {
		t.Fatalf("response status = %d, want 200", response.StatusCode)
	}

	entries := observed.FilterMessage("IMS SMS delivery report").All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic events = %d, want exactly 1", len(entries))
	}
	fields := entries[0].ContextMap()
	allowed := map[string]bool{
		"rp_report_kind":     true,
		"has_user_data":      true,
		"submit_report_kind": true,
		"has_tp_fcs":         true,
		"tp_fcs":             true,
		"rp_cause":           true,
		"correlation_method": true,
		"part_index":         true,
	}
	if len(fields) != len(allowed) {
		t.Fatalf("diagnostic field count = %d, want %d", len(fields), len(allowed))
	}
	for key := range fields {
		if !allowed[key] {
			t.Fatalf("non-allowlisted diagnostic field %q", key)
		}
	}
	if fields["rp_report_kind"] != "submit_report_failure" ||
		fields["has_user_data"] != true ||
		fields["submit_report_kind"] != "failure" ||
		fields["has_tp_fcs"] != true ||
		fields["tp_fcs"] != int64(0x90) ||
		fields["rp_cause"] != int64(0x5f) ||
		fields["correlation_method"] != "rp_mr" ||
		fields["part_index"] != int64(1) {
		t.Fatal("diagnostic metadata classification mismatch")
	}
}

func newSyntheticSMSReportRequest(t *testing.T, body []byte) *sip.Request {
	t.Helper()
	var recipient sip.Uri
	if err := sip.ParseUri("sip:subscriber@ims.example.invalid", &recipient); err != nil {
		t.Fatalf("ParseUri: %v", err)
	}
	request := sip.NewRequest(sip.MESSAGE, recipient)
	request.AppendHeader(sip.NewHeader("Via", "SIP/2.0/TCP pcscf.example.invalid;branch=z9hG4bK-synthetic"))
	request.AppendHeader(sip.NewHeader("From", "<sip:network@ims.example.invalid>;tag=synthetic"))
	request.AppendHeader(sip.NewHeader("To", "<sip:subscriber@ims.example.invalid>"))
	request.AppendHeader(sip.NewHeader("Call-ID", "synthetic-report"))
	request.AppendHeader(sip.NewHeader("CSeq", "1 MESSAGE"))
	request.AppendHeader(sip.NewHeader("Content-Type", smsContentType))
	request.SetBody(body)
	return request
}

type smsReportDiagnosticStore struct{}

func (*smsReportDiagnosticStore) CreateSMSDelivery(string, string, string, string, string, int, time.Time) error {
	return nil
}
func (*smsReportDiagnosticStore) UpsertSMSDeliveryPart(string, int, string, int, string, time.Time) error {
	return nil
}
func (*smsReportDiagnosticStore) MarkSMSDeliveryPartReport(string, string, string, int, string, int, int, string, time.Time) (messaging.DeliveryPartMatch, error) {
	return messaging.DeliveryPartMatch{PartNo: 1, CorrelationMethod: "rp_mr"}, nil
}
func (*smsReportDiagnosticStore) RecomputeSMSDelivery(string, time.Time) error { return nil }
func (*smsReportDiagnosticStore) UpdateSMSDeliveryState(string, string, string, int, time.Time) error {
	return nil
}
func (*smsReportDiagnosticStore) GetSMSDeliveryStatus(string) (*messaging.DeliveryStatus, error) {
	return nil, messaging.ErrDeliveryNotFound
}

var _ messaging.DeliveryStore = (*smsReportDiagnosticStore)(nil)
