package voiceclient

import (
	"errors"
	"testing"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// A rejected report used to log the single word "malformed" with the parser error
// discarded, so every rejection reason looked the same.
//
// That cost a real investigation: a 310/240 message sat at "acked" indefinitely with
// this warning, and there was no way to tell whether the carrier had sent a
// STATUS-REPORT this parser rejects or an inbound SMS-DELIVER that reached the
// function at all only because incomingMessageResult routes on RP-MTI, which
// SMS-DELIVER shares.
//
// These tests pin the structural fields down and, just as importantly, pin down that
// they stay structural: message-type bits and lengths, never user data.

func TestRejectedReportNamesTheReason(t *testing.T) {
	cases := []struct {
		name       string
		body       []byte
		wantReason string
		wantKind   string
	}{
		{
			// TP-SRQ set: a status report for an SMS-COMMAND rather than a SUBMIT.
			name:       "status report with TP-SRQ set",
			body:       syntheticRPDataWithTPDUFirstOctet(0x22),
			wantReason: "tpdu_not_status_report",
			wantKind:   "sms_status_report",
		},
		{
			// Truncated after the envelope: reaches the parser (RP-MTI is 1) but has
			// no readable TPDU.
			// Declares 5 octets of user data and then ends: the length check catches
			// it before any TPDU exists to describe.
			name:       "truncated before TPDU",
			body:       []byte{0x01, 0x2a, 0x00, 0x00, 0x05},
			wantReason: "rp_user_data_length",
			wantKind:   "no_tpdu",
		},
	}
	// SMS-DELIVER has its own diagnostic; the rejection path handles status reports.

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			core, observed := observer.New(zap.InfoLevel)
			previous := logger.Get()
			logger.SetLogger(zap.New(core))
			t.Cleanup(func() { logger.SetLogger(previous) })

			client := &Client{cfg: Config{IMSI: "synthetic-imsi", DeviceID: "synthetic-device"}}
			req := newSyntheticSMSReportRequest(t, c.body)
			if res := client.incomingMessageResponse(req); res.StatusCode != sip.StatusOK {
				// A report we cannot read is still acknowledged at the SIP layer, so the
				// carrier's transaction is not left hanging.
				t.Fatalf("response status=%d, want 200", res.StatusCode)
			}

			entries := observed.FilterMessage("IMS SMS status report").All()
			if len(entries) != 1 {
				t.Fatalf("diagnostic events=%d, want 1", len(entries))
			}
			fields := entries[0].ContextMap()

			if got := fields["reject_reason"]; got != c.wantReason {
				t.Errorf("reject_reason=%v, want %q", got, c.wantReason)
			}
			if got := fields["tpdu_kind"]; got != c.wantKind {
				t.Errorf("tpdu_kind=%v, want %q", got, c.wantKind)
			}
			if fields["tp_status_class"] != "malformed" {
				t.Errorf("tp_status_class=%v, want malformed", fields["tp_status_class"])
			}
		})
	}
}

func TestRejectedReportDiagnosticUsesStrictFieldWhitelist(t *testing.T) {
	core, observed := observer.New(zap.InfoLevel)
	previous := logger.Get()
	logger.SetLogger(zap.New(core))
	t.Cleanup(func() { logger.SetLogger(previous) })

	client := &Client{cfg: Config{IMSI: "synthetic-imsi", DeviceID: "synthetic-device"}}
	// A status report with TP-SRQ set reaches the strict rejection path.
	body := syntheticRPDataWithTPDUFirstOctet(0x22)
	req := newSyntheticSMSReportRequest(t, body)
	req.AppendHeader(sip.NewHeader("P-Asserted-Identity", "<sip:ipsmgw@ims.example.invalid>"))
	client.incomingMessageResponse(req)

	entries := observed.FilterMessage("IMS SMS status report").All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic events=%d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()

	allowed := map[string]bool{
		"report_kind":        true,
		"tp_status_class":    true,
		"tp_status":          true,
		"correlation_method": true,
		"part_index":         true,
		"reject_reason":      true,
		"tpdu_kind":          true,
		"tp_srq":             true,
		"tp_mms":             true,
		"rp_mti":             true,
		"body_len":           true,
		"tpdu_len":           true,
	}
	if len(fields) != len(allowed) {
		t.Fatalf("diagnostic fields=%d, want %d (fields=%v)", len(fields), len(allowed), fields)
	}
	for key := range fields {
		if !allowed[key] {
			t.Fatalf("non-allowlisted field %q", key)
		}
	}
}

func TestInboundDeliverHasItsOwnDiagnostic(t *testing.T) {
	core, observed := observer.New(zap.InfoLevel)
	previous := logger.Get()
	logger.SetLogger(zap.New(core))
	t.Cleanup(func() { logger.SetLogger(previous) })
	client := &Client{}
	request := newSyntheticSMSReportRequest(t, syntheticRPDataWithTPDUFirstOctet(0x00))
	response, ack := client.incomingMessageResult(request)
	if response.StatusCode != sip.StatusServiceUnavailable || ack != nil {
		t.Fatal("inbound SMS without a store must not be acknowledged as delivered")
	}
	if observed.FilterMessage("IMS SMS status report").Len() != 0 {
		t.Fatal("inbound SMS-DELIVER was misclassified as a status report")
	}
	entries := observed.FilterMessage("IMS SMS inbound deliver").All()
	if len(entries) != 1 {
		t.Fatalf("inbound diagnostic count=%d", len(entries))
	}
	fields := entries[0].ContextMap()
	if len(fields) != 3 || fields["report_kind"] != "sms_deliver" || fields["disposition"] != "storage_unavailable" {
		t.Fatal("unexpected inbound diagnostic metadata")
	}
}

func TestRejectReasonIsAClosedSet(t *testing.T) {
	// The reason is mapped, never forwarded, so no wire-derived text can become a
	// log value even if a parser message changes.
	if got := boundedSMSRejectReason(errors.New("something nobody anticipated")); got != "other" {
		t.Errorf("unmapped error should collapse to other, got %q", got)
	}
	if got := boundedSMSRejectReason(nil); got != "none" {
		t.Errorf("nil error should be none, got %q", got)
	}
}

func TestShapeDescriptionSurvivesTruncatedBodies(t *testing.T) {
	// describeSMSReportShape runs on bodies the strict parser already rejected, so
	// it must never panic and must always name how far it got.
	for _, body := range [][]byte{
		nil,
		{},
		{0x01},
		{0x01, 0x2a},
		{0x01, 0x2a, 0xff},
		{0x01, 0x2a, 0x00, 0x00},
		{0x01, 0x2a, 0x00, 0x00, 0x05},
	} {
		shape := describeSMSReportShape(body)
		if shape.tpduKind == "" {
			t.Errorf("body len=%d produced an empty kind", len(body))
		}
		if shape.bodyLen != len(body) {
			t.Errorf("body_len=%d, want %d", shape.bodyLen, len(body))
		}
	}
}

// syntheticRPDataWithTPDUFirstOctet builds a network-originated RP-DATA whose TPDU
// starts with the given octet, so a test can choose the TP-MTI and TP-SRQ bits.
func syntheticRPDataWithTPDUFirstOctet(first byte) []byte {
	tpdu := []byte{first, 0x01, 0x04, 0x91, 0x21, 0x43}
	ts := []byte{0x62, 0x80, 0x50, 0x61, 0x03, 0x10, 0x00}
	tpdu = append(tpdu, ts...)
	tpdu = append(tpdu, ts...)
	tpdu = append(tpdu, 0x00)
	body := []byte{0x01, 0x2a, 0x00, 0x00, byte(len(tpdu))}
	return append(body, tpdu...)
}
