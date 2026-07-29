package db

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestEnsureSMSDeliveryPartUniqueIndexReplacesLegacyNonUniqueIndex(t *testing.T) {
	database := newLegacySMSDeliveryPartDB(t)

	if err := ensureSMSDeliveryPartUniqueIndex(database); err != nil {
		t.Fatalf("ensureSMSDeliveryPartUniqueIndex: %v", err)
	}

	indexes, err := smsDeliveryPartIndexes(database)
	if err != nil {
		t.Fatalf("smsDeliveryPartIndexes: %v", err)
	}
	for _, index := range indexes {
		if index.Name == smsDeliveryPartUniqueIndex {
			if index.IsUnique != 1 {
				t.Fatalf("index unique=%d, want 1", index.IsUnique)
			}
			return
		}
	}
	t.Fatal("unique delivery part index was not created")
}

func TestEnsureSMSDeliveryPartUniqueIndexRejectsDuplicatesWithoutDroppingLegacyIndex(t *testing.T) {
	database := newLegacySMSDeliveryPartDB(t)
	if err := database.Exec(`
		INSERT INTO sms_delivery_part(id, message_id, part_no)
		VALUES (1, 'duplicate', 1), (2, 'duplicate', 1)
	`).Error; err != nil {
		t.Fatalf("insert duplicates: %v", err)
	}

	if err := ensureSMSDeliveryPartUniqueIndex(database); err == nil {
		t.Fatal("expected duplicate migration error")
	}

	indexes, err := smsDeliveryPartIndexes(database)
	if err != nil {
		t.Fatalf("smsDeliveryPartIndexes: %v", err)
	}
	for _, index := range indexes {
		if index.Name == smsDeliveryPartUniqueIndex {
			if index.IsUnique != 0 {
				t.Fatalf("legacy index unique=%d, want 0 after rejected migration", index.IsUnique)
			}
			return
		}
	}
	t.Fatal("legacy index was removed after rejected migration")
}

func TestEnsureSMSDeliveryPartUniqueIndexRestoresDeliveryPartUpsert(t *testing.T) {
	database := newLegacySMSDeliveryPartDB(t)
	previousDB := DB
	DB = database
	t.Cleanup(func() { DB = previousDB })

	sentAt := time.Unix(1, 0).UTC()
	if err := UpsertSMSDeliveryPart("message", 1, "call-before", 1, SMSDeliveryPartStatePending, sentAt); err == nil {
		t.Fatal("legacy non-unique index unexpectedly accepted ON CONFLICT upsert")
	}

	if err := ensureSMSDeliveryPartUniqueIndex(database); err != nil {
		t.Fatalf("ensureSMSDeliveryPartUniqueIndex: %v", err)
	}
	if err := UpsertSMSDeliveryPart("message", 1, "call-first", 1, SMSDeliveryPartStatePending, sentAt); err != nil {
		t.Fatalf("first upsert after migration: %v", err)
	}
	if err := UpsertSMSDeliveryPart("message", 1, "call-updated", 2, SMSDeliveryPartStateAcked, sentAt.Add(time.Second)); err != nil {
		t.Fatalf("second upsert after migration: %v", err)
	}

	var count int64
	if err := database.Model(&SMSDeliveryPart{}).
		Where("message_id = ? AND part_no = ?", "message", 1).
		Count(&count).Error; err != nil {
		t.Fatalf("count delivery parts: %v", err)
	}
	if count != 1 {
		t.Fatalf("delivery part count=%d, want 1", count)
	}
	var part SMSDeliveryPart
	if err := database.Where("message_id = ? AND part_no = ?", "message", 1).First(&part).Error; err != nil {
		t.Fatalf("load delivery part: %v", err)
	}
	if part.CallID != "call-updated" || part.RPMR != 2 || part.State != SMSDeliveryPartStateAcked {
		t.Fatalf("delivery part was not updated: call_id=%q rp_mr=%d state=%q", part.CallID, part.RPMR, part.State)
	}
}

func TestUpsertSMSDeliveryPartPendingDoesNotDowngradeTerminalReport(t *testing.T) {
	database := newLegacySMSDeliveryPartDB(t)
	if err := ensureSMSDeliveryPartUniqueIndex(database); err != nil {
		t.Fatalf("ensureSMSDeliveryPartUniqueIndex: %v", err)
	}
	previousDB := DB
	DB = database
	t.Cleanup(func() { DB = previousDB })

	sentAt := time.Unix(1, 0).UTC()
	if err := UpsertSMSDeliveryPart("message", 1, "", 42, SMSDeliveryPartStatePending, sentAt); err != nil {
		t.Fatalf("prepare delivery part: %v", err)
	}
	if err := UpsertSMSDeliveryPart("message", 1, "", 42, SMSDeliveryPartStateAcked, sentAt.Add(time.Second)); err != nil {
		t.Fatalf("record delivery report: %v", err)
	}
	if err := UpsertSMSDeliveryPart("message", 1, "call-final", 42, SMSDeliveryPartStatePending, sentAt); err != nil {
		t.Fatalf("bind final correlation: %v", err)
	}

	var part SMSDeliveryPart
	if err := database.Where("message_id = ? AND part_no = ?", "message", 1).First(&part).Error; err != nil {
		t.Fatalf("load delivery part: %v", err)
	}
	if part.CallID != "call-final" {
		t.Fatalf("call_id=%q, want final correlation", part.CallID)
	}
	if part.State != SMSDeliveryPartStateAcked {
		t.Fatalf("state=%q, want acked terminal state", part.State)
	}
}

func TestUpsertSMSDeliveryPartSubmissionFailureDoesNotOverrideAcknowledgement(t *testing.T) {
	database := newLegacySMSDeliveryPartDB(t)
	if err := ensureSMSDeliveryPartUniqueIndex(database); err != nil {
		t.Fatalf("ensureSMSDeliveryPartUniqueIndex: %v", err)
	}
	previousDB := DB
	DB = database
	t.Cleanup(func() { DB = previousDB })

	sentAt := time.Unix(1, 0).UTC()
	if err := UpsertSMSDeliveryPart("message", 1, "call", 42, SMSDeliveryPartStateAcked, sentAt); err != nil {
		t.Fatalf("record acknowledgement: %v", err)
	}
	if err := UpsertSMSDeliveryPart("message", 1, "call", 42, SMSDeliveryPartStateFailed, sentAt.Add(time.Second)); err != nil {
		t.Fatalf("record later submission failure: %v", err)
	}

	var part SMSDeliveryPart
	if err := database.Where("message_id = ? AND part_no = ?", "message", 1).First(&part).Error; err != nil {
		t.Fatalf("load delivery part: %v", err)
	}
	if part.State != SMSDeliveryPartStateAcked {
		t.Fatalf("state=%q, want acked terminal state", part.State)
	}
}

func TestRecomputeSMSDeliveryWaitsForAllDeclaredMultipartParts(t *testing.T) {
	database := newSMSDeliveryStateTestDB(t)
	previousDB := DB
	DB = database
	t.Cleanup(func() { DB = previousDB })

	at := time.Unix(1, 0).UTC()
	if err := CreateSMSDelivery("multipart", "synthetic-imsi", "synthetic-device", "+10010", "synthetic", 2, at); err != nil {
		t.Fatalf("CreateSMSDelivery: %v", err)
	}
	if err := UpsertSMSDeliveryPart("multipart", 1, "", 41, SMSDeliveryPartStateAcked, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart: %v", err)
	}
	if err := RecomputeSMSDelivery("multipart", at.Add(time.Second)); err != nil {
		t.Fatalf("RecomputeSMSDelivery: %v", err)
	}
	status, err := GetSMSDeliveryStatus("multipart")
	if err != nil {
		t.Fatalf("GetSMSDeliveryStatus: %v", err)
	}
	if status.State != SMSDeliveryStatePartialAck {
		t.Fatalf("state=%q with one of two declared parts acknowledged, want partial_ack", status.State)
	}
}

func TestMarkSMSDeliveryPartReportKeepsFirstTerminalResult(t *testing.T) {
	database := newSMSDeliveryStateTestDB(t)
	previousDB := DB
	DB = database
	t.Cleanup(func() { DB = previousDB })

	at := time.Unix(1, 0).UTC()
	if err := CreateSMSDelivery("terminal", "synthetic-imsi", "synthetic-device", "+10010", "synthetic", 1, at); err != nil {
		t.Fatalf("CreateSMSDelivery: %v", err)
	}
	if err := UpsertSMSDeliveryPart("terminal", 1, "", 42, SMSDeliveryPartStatePending, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart: %v", err)
	}
	if _, err := MarkSMSDeliveryPartReport("", "", "", 42, SMSDeliveryPartStateAcked, 200, 0, "", at.Add(time.Second)); err != nil {
		t.Fatalf("MarkSMSDeliveryPartReport(acked): %v", err)
	}
	if _, err := MarkSMSDeliveryPartReport("", "", "", 42, SMSDeliveryPartStateFailed, 200, 95, "", at.Add(2*time.Second)); err != nil {
		t.Fatalf("MarkSMSDeliveryPartReport(conflicting failed): %v", err)
	}

	status, err := GetSMSDeliveryStatus("terminal")
	if err != nil {
		t.Fatalf("GetSMSDeliveryStatus: %v", err)
	}
	if len(status.Parts) != 1 || status.Parts[0].State != SMSDeliveryPartStateAcked || status.State != SMSDeliveryStateAcked {
		t.Fatalf("terminal report changed after conflict: aggregate=%q parts=%v", status.State, status.Parts)
	}
}

func TestMarkSMSDeliveryPartReportReturnsStrongCorrelationMethod(t *testing.T) {
	database := newSMSDeliveryStateTestDB(t)
	previousDB := DB
	DB = database
	t.Cleanup(func() { DB = previousDB })

	at := time.Unix(1, 0).UTC()
	if err := CreateSMSDelivery("strong-correlation", "synthetic-imsi", "synthetic-device", "+10010", "synthetic", 1, at); err != nil {
		t.Fatalf("CreateSMSDelivery: %v", err)
	}
	if err := UpsertSMSDeliveryPart("strong-correlation", 1, "synthetic-call", 42, SMSDeliveryPartStatePending, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart: %v", err)
	}

	part, err := MarkSMSDeliveryPartReport("synthetic-call", "", "synthetic-device", 42, SMSDeliveryPartStateAcked, 200, 0, "", at.Add(time.Second))
	if err != nil {
		t.Fatalf("MarkSMSDeliveryPartReport: %v", err)
	}
	if part.CorrelationMethod != "in_reply_to" {
		t.Fatalf("correlation method = %q, want in_reply_to", part.CorrelationMethod)
	}
}

func TestMarkSMSDeliveryPartReportRejectsAmbiguousRPMRFallback(t *testing.T) {
	database := newSMSDeliveryStateTestDB(t)
	previousDB := DB
	DB = database
	t.Cleanup(func() { DB = previousDB })

	at := time.Unix(1, 0).UTC()
	if err := CreateSMSDelivery("old-transaction", "synthetic-imsi", "synthetic-device", "+10010", "old", 1, at); err != nil {
		t.Fatalf("CreateSMSDelivery(old): %v", err)
	}
	if err := UpsertSMSDeliveryPart("old-transaction", 1, "old-call", 42, SMSDeliveryPartStateAcked, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart(old): %v", err)
	}
	newAt := at.Add(30 * time.Second)
	if err := CreateSMSDelivery("new-transaction", "synthetic-imsi", "synthetic-device", "+10010", "new", 1, newAt); err != nil {
		t.Fatalf("CreateSMSDelivery(new): %v", err)
	}
	if err := UpsertSMSDeliveryPart("new-transaction", 1, "new-call", 42, SMSDeliveryPartStatePending, newAt); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart(new): %v", err)
	}

	_, err := MarkSMSDeliveryPartReport("", "", "synthetic-device", 42, SMSDeliveryPartStateAcked, 200, 0, "", newAt.Add(time.Second))
	if !errors.Is(err, ErrSMSDeliveryReportAmbiguous) {
		t.Fatalf("ambiguous RP-MR correlation error = %v", err)
	}

	status, err := GetSMSDeliveryStatus("new-transaction")
	if err != nil {
		t.Fatalf("GetSMSDeliveryStatus(new): %v", err)
	}
	if len(status.Parts) != 1 || status.Parts[0].State != SMSDeliveryPartStatePending {
		t.Fatal("ambiguous late report changed the new pending transaction")
	}
}

func TestRecomputeSMSDeliveryDoesNotDowngradeExplicitSubmissionFailure(t *testing.T) {
	database := newSMSDeliveryStateTestDB(t)
	previousDB := DB
	DB = database
	t.Cleanup(func() { DB = previousDB })

	at := time.Unix(1, 0).UTC()
	if err := CreateSMSDelivery("submission-failed", "synthetic-imsi", "synthetic-device", "+10010", "synthetic", 2, at); err != nil {
		t.Fatalf("CreateSMSDelivery: %v", err)
	}
	if err := UpsertSMSDeliveryPart("submission-failed", 1, "", 41, SMSDeliveryPartStateAcked, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart: %v", err)
	}
	if err := UpdateSMSDeliveryState("submission-failed", SMSDeliveryStateFailed, "", 1, at.Add(time.Second)); err != nil {
		t.Fatalf("UpdateSMSDeliveryState: %v", err)
	}
	if err := RecomputeSMSDelivery("submission-failed", at.Add(2*time.Second)); err != nil {
		t.Fatalf("RecomputeSMSDelivery: %v", err)
	}
	status, err := GetSMSDeliveryStatus("submission-failed")
	if err != nil {
		t.Fatalf("GetSMSDeliveryStatus: %v", err)
	}
	if status.State != SMSDeliveryStateFailed {
		t.Fatalf("explicit submission failure was downgraded to %q", status.State)
	}
}

func newLegacySMSDeliveryPartDB(t *testing.T) *gorm.DB {
	t.Helper()
	dialector, err := openSQLiteDialector("modernc", filepath.Join(t.TempDir(), "sms-delivery.db"))
	if err != nil {
		t.Fatalf("openSQLiteDialector: %v", err)
	}
	database, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}
	if err := database.AutoMigrate(&SMSDeliveryPart{}); err != nil {
		t.Fatalf("create delivery part table: %v", err)
	}
	if err := database.Exec(`DROP INDEX IF EXISTS idx_sms_delivery_part_mid_no`).Error; err != nil {
		t.Fatalf("drop generated unique index: %v", err)
	}
	if err := database.Exec(`CREATE INDEX idx_sms_delivery_part_mid_no
		ON sms_delivery_part(message_id, part_no)`).Error; err != nil {
		t.Fatalf("create legacy index: %v", err)
	}
	return database
}

func newSMSDeliveryStateTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dialector, err := openSQLiteDialector("modernc", filepath.Join(t.TempDir(), "sms-delivery-state.db"))
	if err != nil {
		t.Fatalf("openSQLiteDialector: %v", err)
	}
	database, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}
	if err := database.AutoMigrate(&SMS{}, &SMSDelivery{}, &SMSDeliveryPart{}); err != nil {
		t.Fatalf("AutoMigrate delivery state: %v", err)
	}
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatalf("database.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	return database
}
