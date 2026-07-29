package device

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vowifi-go/runtimehost/eventhost"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

func TestVoWiFiSMSHistoryRecorderPersistsSentSMS(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	if err := db.UpdateSIMCardVoWiFiPhoneNumberByIMSI("imsi-vowifi-1", "+8613800000000"); err != nil {
		t.Fatalf("UpdateSIMCardVoWiFiPhoneNumberByIMSI() error=%v", err)
	}
	p := NewPool(nil)
	p.workers["dev-1"] = &Worker{ID: "dev-1", Backend: &workerPhoneBackendStub{imsi: "imsi-vowifi-1"}}

	at := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	err := vowifiSMSHistoryRecorder{pool: p}.RecordSent(eventhost.SMSSent{
		DevID:         "dev-1",
		TargetURI:     "+10010",
		Content:       "hello",
		Time:          at,
		TotalParts:    1,
		DeliveryState: "acked",
	})
	if err != nil {
		t.Fatalf("RecordSent() error=%v", err)
	}

	var sms db.SMS
	if err := db.DB.Where("imsi = ? AND type = ?", "imsi-vowifi-1", 2).First(&sms).Error; err != nil {
		t.Fatalf("First(sent sms) error=%v", err)
	}
	if sms.Sender != "+8613800000000" || sms.Recipient != "+10010" || sms.Content != "hello" || sms.Status != 2 {
		t.Fatalf("sent sms=%+v", sms)
	}
}

func TestVoWiFiSMSHistoryRecorderKeepsPendingSubmissionDistinctFromDelivered(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	p := NewPool(nil)
	p.workers["dev-pending"] = &Worker{ID: "dev-pending", Backend: &workerPhoneBackendStub{imsi: "imsi-pending"}}

	err := vowifiSMSHistoryRecorder{pool: p}.RecordSent(eventhost.SMSSent{
		DevID:         "dev-pending",
		TargetURI:     "+10010",
		Content:       "pending submission",
		Time:          time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC),
		MessageID:     "synthetic-message",
		TotalParts:    1,
		DeliveryState: "pending",
	})
	if err != nil {
		t.Fatalf("RecordSent() error=%v", err)
	}

	var sms db.SMS
	if err := db.DB.Where("imsi = ? AND type = ?", "imsi-pending", 2).First(&sms).Error; err != nil {
		t.Fatalf("First(pending sms) error=%v", err)
	}
	if sms.Status != 4 {
		t.Fatalf("pending SMS status=%d, want 4", sms.Status)
	}
	if sms.MessageID != "synthetic-message" {
		t.Fatalf("pending SMS message_id=%q, want delivery correlation", sms.MessageID)
	}
}

func TestVoWiFiDeliveryReportUpdatesCorrelatedHistoryRow(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	p := NewPool(nil)
	p.workers["dev-report"] = &Worker{ID: "dev-report", Backend: &workerPhoneBackendStub{imsi: "imsi-report"}}
	at := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	const messageID = "synthetic-report-message"

	if err := (vowifiSMSHistoryRecorder{pool: p}).RecordSent(eventhost.SMSSent{
		DevID:         "dev-report",
		TargetURI:     "+10010",
		Content:       "pending submission",
		Time:          at,
		MessageID:     messageID,
		TotalParts:    1,
		DeliveryState: "pending",
	}); err != nil {
		t.Fatalf("RecordSent: %v", err)
	}
	if err := db.CreateSMSDelivery(messageID, "imsi-report", "dev-report", "+10010", "pending submission", 1, at); err != nil {
		t.Fatalf("CreateSMSDelivery: %v", err)
	}
	if err := db.UpsertSMSDeliveryPart(messageID, 1, "", 42, db.SMSDeliveryPartStatePending, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart: %v", err)
	}
	match, err := (vowifiDeliveryStore{}).MarkSMSDeliveryPartReport("", "", "dev-report", 42, db.SMSDeliveryPartStateAcked, 200, 0, "", at.Add(time.Second))
	if err != nil {
		t.Fatalf("MarkSMSDeliveryPartReport: %v", err)
	}
	if match.CorrelationMethod != "rp_mr" {
		t.Fatalf("correlation method = %q, want rp_mr", match.CorrelationMethod)
	}

	var sms db.SMS
	if err := db.DB.Where("message_id = ?", messageID).First(&sms).Error; err != nil {
		t.Fatalf("load correlated SMS: %v", err)
	}
	if sms.Status != 2 {
		t.Fatalf("correlated SMS status=%d, want acknowledged status 2", sms.Status)
	}
}

func TestVoWiFiDeliveryStoreFailsClosedOnAmbiguousRPMR(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	at := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	if err := db.CreateSMSDelivery("old-report", "synthetic-imsi", "dev-ambiguous", "+10010", "old", 1, at); err != nil {
		t.Fatalf("CreateSMSDelivery(old): %v", err)
	}
	if err := db.UpsertSMSDeliveryPart("old-report", 1, "old-call", 42, db.SMSDeliveryPartStateAcked, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart(old): %v", err)
	}
	newAt := at.Add(30 * time.Second)
	if err := db.CreateSMSDelivery("new-report", "synthetic-imsi", "dev-ambiguous", "+10010", "new", 1, newAt); err != nil {
		t.Fatalf("CreateSMSDelivery(new): %v", err)
	}
	if err := db.UpsertSMSDeliveryPart("new-report", 1, "new-call", 42, db.SMSDeliveryPartStatePending, newAt); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart(new): %v", err)
	}

	_, err := (vowifiDeliveryStore{}).MarkSMSDeliveryPartReport("", "", "dev-ambiguous", 42, db.SMSDeliveryPartStateAcked, 200, 0, "", newAt.Add(time.Second))
	if !errors.Is(err, messaging.ErrDeliveryNotFound) {
		t.Fatalf("ambiguous adapter result = %v, want delivery not found", err)
	}
}

func TestVoWiFiSMSHistoryRecorderReconcilesTerminalDeliveryAfterStalePendingEvent(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	p := NewPool(nil)
	p.workers["dev-early-report"] = &Worker{ID: "dev-early-report", Backend: &workerPhoneBackendStub{imsi: "imsi-early-report"}}
	at := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	const messageID = "synthetic-early-report"

	if err := db.CreateSMSDelivery(messageID, "imsi-early-report", "dev-early-report", "+10010", "synthetic", 1, at); err != nil {
		t.Fatalf("CreateSMSDelivery: %v", err)
	}
	if err := db.UpsertSMSDeliveryPart(messageID, 1, "", 41, db.SMSDeliveryPartStatePending, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart: %v", err)
	}
	if _, err := (vowifiDeliveryStore{}).MarkSMSDeliveryPartReport("", "", "dev-early-report", 41, db.SMSDeliveryPartStateAcked, 200, 0, "", at.Add(time.Second)); err != nil {
		t.Fatalf("MarkSMSDeliveryPartReport: %v", err)
	}

	// The runtime event may carry a stale pending snapshot if the report lands
	// after its status read but before history publication. Persistence must
	// reconcile against the authoritative delivery row instead of downgrading.
	if err := (vowifiSMSHistoryRecorder{pool: p}).RecordSent(eventhost.SMSSent{
		DevID:         "dev-early-report",
		TargetURI:     "+10010",
		Content:       "synthetic",
		Time:          at,
		MessageID:     messageID,
		TotalParts:    1,
		DeliveryState: "pending",
	}); err != nil {
		t.Fatalf("RecordSent: %v", err)
	}

	var sms db.SMS
	if err := db.DB.Where("message_id = ?", messageID).First(&sms).Error; err != nil {
		t.Fatalf("load correlated SMS: %v", err)
	}
	if sms.Status != 2 {
		t.Fatalf("stale pending event downgraded terminal history status=%d, want 2", sms.Status)
	}
}

func TestVoWiFiDeliveryReportUsesAggregateStateForMultipartHistory(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	p := NewPool(nil)
	p.workers["dev-multipart"] = &Worker{ID: "dev-multipart", Backend: &workerPhoneBackendStub{imsi: "imsi-multipart"}}
	at := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	const messageID = "synthetic-multipart-report"

	if err := (vowifiSMSHistoryRecorder{pool: p}).RecordSent(eventhost.SMSSent{
		DevID:         "dev-multipart",
		TargetURI:     "+10010",
		Content:       "synthetic multipart",
		Time:          at,
		MessageID:     messageID,
		TotalParts:    2,
		DeliveryState: "pending",
	}); err != nil {
		t.Fatalf("RecordSent: %v", err)
	}
	if err := db.CreateSMSDelivery(messageID, "imsi-multipart", "dev-multipart", "+10010", "synthetic multipart", 2, at); err != nil {
		t.Fatalf("CreateSMSDelivery: %v", err)
	}
	if err := db.UpsertSMSDeliveryPart(messageID, 1, "", 51, db.SMSDeliveryPartStatePending, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart(part 1): %v", err)
	}
	if err := db.UpsertSMSDeliveryPart(messageID, 2, "", 52, db.SMSDeliveryPartStatePending, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart(part 2): %v", err)
	}
	store := vowifiDeliveryStore{}
	if _, err := store.MarkSMSDeliveryPartReport("", "", "dev-multipart", 51, db.SMSDeliveryPartStateFailed, 200, 95, "", at.Add(time.Second)); err != nil {
		t.Fatalf("MarkSMSDeliveryPartReport(failed): %v", err)
	}
	if _, err := store.MarkSMSDeliveryPartReport("", "", "dev-multipart", 52, db.SMSDeliveryPartStateAcked, 200, 0, "", at.Add(2*time.Second)); err != nil {
		t.Fatalf("MarkSMSDeliveryPartReport(acked): %v", err)
	}

	status, err := db.GetSMSDeliveryStatus(messageID)
	if err != nil {
		t.Fatalf("GetSMSDeliveryStatus: %v", err)
	}
	if status.State != db.SMSDeliveryStateFailed {
		t.Fatalf("aggregate delivery state=%q, want failed", status.State)
	}
	var sms db.SMS
	if err := db.DB.Where("message_id = ?", messageID).First(&sms).Error; err != nil {
		t.Fatalf("load correlated SMS: %v", err)
	}
	if sms.Status != 3 {
		t.Fatalf("multipart history status=%d after failure then ACK, want failed status 3", sms.Status)
	}
}

func TestConcurrentMultipartReportsConvergeHistoryToAggregateFailure(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	p := NewPool(nil)
	p.workers["dev-concurrent"] = &Worker{ID: "dev-concurrent", Backend: &workerPhoneBackendStub{imsi: "imsi-concurrent"}}
	at := time.Unix(1, 0).UTC()
	const messageID = "synthetic-concurrent-report"

	if err := (vowifiSMSHistoryRecorder{pool: p}).RecordSent(eventhost.SMSSent{
		DevID:         "dev-concurrent",
		TargetURI:     "+10010",
		Content:       "synthetic concurrent",
		Time:          at,
		MessageID:     messageID,
		TotalParts:    2,
		DeliveryState: "pending",
	}); err != nil {
		t.Fatalf("RecordSent: %v", err)
	}
	if err := db.CreateSMSDelivery(messageID, "imsi-concurrent", "dev-concurrent", "+10010", "synthetic concurrent", 2, at); err != nil {
		t.Fatalf("CreateSMSDelivery: %v", err)
	}
	if err := db.UpsertSMSDeliveryPart(messageID, 1, "", 61, db.SMSDeliveryPartStatePending, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart(part 1): %v", err)
	}
	if err := db.UpsertSMSDeliveryPart(messageID, 2, "", 62, db.SMSDeliveryPartStatePending, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart(part 2): %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	store := vowifiDeliveryStore{}
	go func() {
		<-start
		_, err := store.MarkSMSDeliveryPartReport("", "", "dev-concurrent", 61, db.SMSDeliveryPartStateAcked, 200, 0, "", at.Add(time.Second))
		results <- err
	}()
	go func() {
		<-start
		_, err := store.MarkSMSDeliveryPartReport("", "", "dev-concurrent", 62, db.SMSDeliveryPartStateFailed, 200, 95, "", at.Add(time.Second))
		results <- err
	}()
	close(start)
	for attempt := 0; attempt < 2; attempt++ {
		if err := <-results; err != nil {
			t.Fatalf("MarkSMSDeliveryPartReport: %v", err)
		}
	}

	status, err := db.GetSMSDeliveryStatus(messageID)
	if err != nil {
		t.Fatalf("GetSMSDeliveryStatus: %v", err)
	}
	if status.State != db.SMSDeliveryStateFailed {
		t.Fatalf("aggregate delivery state=%q, want failed", status.State)
	}
	var sms db.SMS
	if err := db.DB.Where("message_id = ?", messageID).First(&sms).Error; err != nil {
		t.Fatalf("load correlated SMS: %v", err)
	}
	if sms.Status != 3 {
		t.Fatalf("concurrent report history status=%d, want failed status 3", sms.Status)
	}
}

func TestVoWiFiSMSHistoryRecorderPersistsReceivedSMS(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	if err := db.UpdateSIMCardVoWiFiPhoneNumberByIMSI("imsi-vowifi-2", "+8613900000000"); err != nil {
		t.Fatalf("UpdateSIMCardVoWiFiPhoneNumberByIMSI() error=%v", err)
	}
	p := NewPool(nil)
	p.workers["dev-2"] = &Worker{ID: "dev-2", Backend: &workerPhoneBackendStub{imsi: "imsi-vowifi-2"}}

	at := time.Date(2026, 6, 3, 12, 1, 0, 0, time.UTC)
	_, err := vowifiSMSHistoryRecorder{pool: p}.RecordReceived(eventhost.SMSReceived{
		DevID:   "dev-2",
		Sender:  "+10086",
		Content: "inbound",
		Time:    at,
	})
	if err != nil {
		t.Fatalf("RecordReceived() error=%v", err)
	}

	var sms db.SMS
	if err := db.DB.Where("imsi = ? AND type = ?", "imsi-vowifi-2", 1).First(&sms).Error; err != nil {
		t.Fatalf("First(received sms) error=%v", err)
	}
	if sms.Sender != "+10086" || sms.Recipient != "+8613900000000" || sms.Content != "inbound" || sms.Status != 0 {
		t.Fatalf("received sms=%+v", sms)
	}
}

func TestVoWiFiSMSHistoryRecorderSkipsSuppressedReceivedSMS(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	p := NewPool(nil)
	p.workers["dev-ota"] = &Worker{ID: "dev-ota", Backend: &workerPhoneBackendStub{imsi: "imsi-ota"}}

	_, err := vowifiSMSHistoryRecorder{pool: p}.RecordReceived(eventhost.SMSReceived{
		DevID:   "dev-ota",
		Sender:  "+10086",
		Content: "[SIM OTA 23.048]\ndecrypt=not_attempted\nsecurity=可能加密\nraw=0011",
		Time:    time.Now(),
	})
	if err != nil {
		t.Fatalf("RecordReceived() error=%v", err)
	}

	var count int64
	if err := db.DB.Model(&db.SMS{}).Where("imsi = ? AND type = ?", "imsi-ota", 1).Count(&count).Error; err != nil {
		t.Fatalf("Count(received sms) error=%v", err)
	}
	if count != 0 {
		t.Fatalf("suppressed received sms count=%d want 0", count)
	}
}

func TestWorkerProcessSMSSkipsSuppressedReceivedSMS(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	p := NewPool(nil)
	w := &Worker{
		ID:      "dev-worker-ota",
		Pool:    p,
		Backend: &workerPhoneBackendStub{imsi: "imsi-worker-ota"},
	}

	w.processSMS("+10086", "[SIM OTA 23.048]\ndecrypt=not_attempted\nsecurity=可能加密\nraw=0011", time.Now())

	var count int64
	if err := db.DB.Model(&db.SMS{}).Where("imsi = ? AND type = ?", "imsi-worker-ota", 1).Count(&count).Error; err != nil {
		t.Fatalf("Count(received sms) error=%v", err)
	}
	if count != 0 {
		t.Fatalf("suppressed worker sms count=%d want 0", count)
	}
}

func TestVoWiFiSMSHistoryRecorderPersistsSendFailure(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	p := NewPool(nil)
	p.workers["dev-fail"] = &Worker{ID: "dev-fail", Backend: &workerPhoneBackendStub{imsi: "imsi-fail"}}

	err := vowifiSMSHistoryRecorder{pool: p}.RecordSendFailure("dev-fail", "+10010", "failed sms", time.Now())
	if err != nil {
		t.Fatalf("RecordSendFailure() error=%v", err)
	}

	var sms db.SMS
	if err := db.DB.Where("imsi = ? AND type = ? AND status = ?", "imsi-fail", 2, 3).First(&sms).Error; err != nil {
		t.Fatalf("First(failed sms) error=%v", err)
	}
	if sms.Recipient != "+10010" || sms.Content != "failed sms" {
		t.Fatalf("failed sms=%+v", sms)
	}
}

func TestRecordVoWiFiSMSSendFailurePreservesTrackingMessageID(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	p := NewPool(nil)
	p.workers["dev-tracked-fail"] = &Worker{ID: "dev-tracked-fail", Backend: &workerPhoneBackendStub{imsi: "imsi-tracked-fail"}}
	at := time.Unix(1, 0).UTC()
	const messageID = "synthetic-tracked-failure"
	if err := db.CreateSMSDelivery(messageID, "imsi-tracked-fail", "dev-tracked-fail", "+10010", "synthetic", 1, at); err != nil {
		t.Fatalf("CreateSMSDelivery: %v", err)
	}
	if err := db.UpdateSMSDeliveryState(messageID, db.SMSDeliveryStateFailed, "", 0, at); err != nil {
		t.Fatalf("UpdateSMSDeliveryState: %v", err)
	}

	if err := RecordVoWiFiSMSSendFailure(p, "dev-tracked-fail", messageID, "+10010", "synthetic", at); err != nil {
		t.Fatalf("RecordVoWiFiSMSSendFailure: %v", err)
	}
	var sms db.SMS
	if err := db.DB.Where("message_id = ?", messageID).First(&sms).Error; err != nil {
		t.Fatalf("load tracked failure history: %v", err)
	}
	if sms.Status != 3 {
		t.Fatalf("tracked failure history status=%d, want 3", sms.Status)
	}
}

func TestVoWiFiSMSHistoryRecorderPersistsLocalNumberLearned(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	p := NewPool(nil)
	p.workers["dev-3"] = &Worker{ID: "dev-3", Backend: &workerPhoneBackendStub{imsi: "imsi-vowifi-3"}}

	err := vowifiSMSHistoryRecorder{pool: p}.RecordLocalNumberLearned(eventhost.LocalNumberLearned{
		DevID:  "dev-3",
		IMSI:   "imsi-vowifi-3",
		Number: "+8613700000000",
		Source: "register",
	})
	if err != nil {
		t.Fatalf("RecordLocalNumberLearned() error=%v", err)
	}

	sub := loadDeviceTestSIMSubscriptionByIMSI(t, "imsi-vowifi-3")
	if sub.VowifiPhoneNumber != "+8613700000000" || sub.PhoneNumber != "+8613700000000" {
		t.Fatalf("subscription=%+v", sub)
	}
}

func TestRecordLocalNumberLearnedStagesByICCIDWhenIMSIEmpty(t *testing.T) {
	initDevicePhoneNumberTestDB(t)

	p := NewPool(nil)
	defer p.cancel()
	w := &Worker{ID: "dev-1"}
	w.state.Identity.Ready = true
	w.state.Identity.ICCID = "8944000000000000111"
	p.workers["dev-1"] = w

	rec := vowifiSMSHistoryRecorder{pool: p}
	err := rec.RecordLocalNumberLearned(eventhost.LocalNumberLearned{
		DevID: "dev-1", IMSI: "", Number: "+447700900200", Source: "P-Associated-URI",
	})
	if err != nil {
		t.Fatalf("RecordLocalNumberLearned error=%v", err)
	}
	got, err := db.GetPhoneNumberByIMSIOrICCID("", "8944000000000000111")
	if err != nil {
		t.Fatalf("GetPhoneNumberByIMSIOrICCID error=%v", err)
	}
	if got != "+447700900200" {
		t.Fatalf("phone=%q, want +447700900200 staged by ICCID", got)
	}
}

func TestVoWiFiRuntimeDispatcherPersistsSMSSentWithoutNotifier(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	p := NewPool(nil)
	p.workers["dev-dispatch"] = &Worker{ID: "dev-dispatch", Backend: &workerPhoneBackendStub{imsi: "imsi-dispatch"}}

	poolVoWiFiRuntimeDispatcher{pool: p}.Dispatch(context.Background(), eventhost.SMSSent{
		DevID:         "dev-dispatch",
		TargetURI:     "+10010",
		Content:       "sent through dispatcher",
		Time:          time.Now(),
		DeliveryState: "acked",
	})

	var count int64
	if err := db.DB.Model(&db.SMS{}).Where("imsi = ? AND type = ? AND status = ?", "imsi-dispatch", 2, 2).Count(&count).Error; err != nil {
		t.Fatalf("Count(sent sms) error=%v", err)
	}
	if count != 1 {
		t.Fatalf("sent sms count=%d want 1", count)
	}
}

func TestVoWiFiSMSHistoryRecorderSkipsDuplicateReceivedSMS(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	if err := db.UpdateSIMCardVoWiFiPhoneNumberByIMSI("imsi-vowifi-dup", "+8613900000000"); err != nil {
		t.Fatalf("UpdateSIMCardVoWiFiPhoneNumberByIMSI() error=%v", err)
	}
	p := NewPool(nil)
	p.workers["dev-dup"] = &Worker{ID: "dev-dup", Backend: &workerPhoneBackendStub{imsi: "imsi-vowifi-dup"}}

	rec := vowifiSMSHistoryRecorder{pool: p}
	at := time.Date(2026, 6, 29, 23, 58, 55, 0, time.UTC)
	first, err := rec.RecordReceived(eventhost.SMSReceived{
		DevID:   "dev-dup",
		Sender:  "+447751284582",
		Content: "ij991818短信登录验证码，5分钟内有效，请勿泄露。",
		Time:    at,
	})
	if err != nil {
		t.Fatalf("first RecordReceived() error=%v", err)
	}
	if !first.Stored || first.Duplicate || first.Suppressed {
		t.Fatalf("first result=%+v, want stored only", first)
	}

	second, err := rec.RecordReceived(eventhost.SMSReceived{
		DevID:   "dev-dup",
		Sender:  "+447751284582",
		Content: "ij991818短信登录验证码，5分钟内有效，请勿泄露。",
		Time:    at.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatalf("second RecordReceived() error=%v", err)
	}
	if second.Stored || !second.Duplicate || second.Suppressed {
		t.Fatalf("second result=%+v, want duplicate only", second)
	}

	var count int64
	if err := db.DB.Model(&db.SMS{}).Where("imsi = ? AND type = ?", "imsi-vowifi-dup", 1).Count(&count).Error; err != nil {
		t.Fatalf("Count(received sms) error=%v", err)
	}
	if count != 1 {
		t.Fatalf("received sms count=%d want 1", count)
	}
}

type countingVoWiFiNotifier struct {
	smsCount int
	rawCount int
}

func (n *countingVoWiFiNotifier) NotifySMS(deviceID, sender, content string, timestamp time.Time) {
	n.smsCount++
}

func (n *countingVoWiFiNotifier) NotifySMSWithSource(deviceID, sender, content, source string, timestamp time.Time) {
	n.smsCount++
}

func (n *countingVoWiFiNotifier) NotifyRaw(msg string) {
	n.rawCount++
}

func (n *countingVoWiFiNotifier) NotifyIPRotated(deviceID, oldIP, newIP string, duration time.Duration) {
}

func TestVoWiFiRuntimeDispatcherSkipsDuplicateReceivedNotification(t *testing.T) {
	initDevicePhoneNumberTestDB(t)
	if err := db.UpdateSIMCardVoWiFiPhoneNumberByIMSI("imsi-vowifi-dispatch-dup", "+8613900000000"); err != nil {
		t.Fatalf("UpdateSIMCardVoWiFiPhoneNumberByIMSI() error=%v", err)
	}
	p := NewPool(nil)
	p.workers["dev-dispatch-dup"] = &Worker{ID: "dev-dispatch-dup", Backend: &workerPhoneBackendStub{imsi: "imsi-vowifi-dispatch-dup"}}
	notifier := &countingVoWiFiNotifier{}
	p.SetNotifier(notifier)

	ev := eventhost.SMSReceived{
		DevID:   "dev-dispatch-dup",
		Sender:  "+447751284582",
		Content: "ij991818短信登录验证码，5分钟内有效，请勿泄露。",
		Time:    time.Date(2026, 6, 29, 23, 58, 55, 0, time.UTC),
	}
	poolVoWiFiRuntimeDispatcher{pool: p}.Dispatch(context.Background(), ev)
	ev.Time = ev.Time.Add(73 * time.Second)
	poolVoWiFiRuntimeDispatcher{pool: p}.Dispatch(context.Background(), ev)

	if notifier.smsCount != 1 {
		t.Fatalf("sms notification count=%d want 1", notifier.smsCount)
	}
	var count int64
	if err := db.DB.Model(&db.SMS{}).Where("imsi = ? AND type = ?", "imsi-vowifi-dispatch-dup", 1).Count(&count).Error; err != nil {
		t.Fatalf("Count(received sms) error=%v", err)
	}
	if count != 1 {
		t.Fatalf("received sms count=%d want 1", count)
	}
}
