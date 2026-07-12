package db

import (
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
