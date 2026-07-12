package db

import (
	"fmt"

	"gorm.io/gorm"
)

const smsDeliveryPartUniqueIndex = "idx_sms_delivery_part_mid_no"

type sqliteIndexInfo struct {
	Name     string `gorm:"column:name"`
	IsUnique int    `gorm:"column:unique"`
}

func ensureSMSDeliveryPartUniqueIndex(tx *gorm.DB) error {
	if tx == nil {
		return fmt.Errorf("sms delivery part index migration: database is nil")
	}
	if !tx.Migrator().HasTable(&SMSDeliveryPart{}) {
		return nil
	}

	return tx.Transaction(func(migration *gorm.DB) error {
		indexes, err := smsDeliveryPartIndexes(migration)
		if err != nil {
			return err
		}
		legacyIndexExists := false
		for _, index := range indexes {
			if index.Name != smsDeliveryPartUniqueIndex {
				continue
			}
			if index.IsUnique == 1 {
				return nil
			}
			legacyIndexExists = true
		}

		var duplicateGroups int64
		if err := migration.Raw(`
			SELECT COUNT(*) FROM (
				SELECT message_id, part_no
				FROM sms_delivery_part
				GROUP BY message_id, part_no
				HAVING COUNT(*) > 1
			)
		`).Scan(&duplicateGroups).Error; err != nil {
			return fmt.Errorf("sms delivery part index migration: duplicate check: %w", err)
		}
		if duplicateGroups > 0 {
			return fmt.Errorf(
				"sms delivery part index migration: duplicate_groups=%d",
				duplicateGroups,
			)
		}

		if legacyIndexExists {
			if err := migration.Exec(`DROP INDEX IF EXISTS idx_sms_delivery_part_mid_no`).Error; err != nil {
				return fmt.Errorf("sms delivery part index migration: drop legacy index: %w", err)
			}
		}
		if err := migration.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS idx_sms_delivery_part_mid_no
			ON sms_delivery_part(message_id, part_no)
		`).Error; err != nil {
			return fmt.Errorf("sms delivery part index migration: create unique index: %w", err)
		}

		indexes, err = smsDeliveryPartIndexes(migration)
		if err != nil {
			return err
		}
		for _, index := range indexes {
			if index.Name == smsDeliveryPartUniqueIndex && index.IsUnique == 1 {
				return nil
			}
		}
		return fmt.Errorf("sms delivery part index migration: unique index verification failed")
	})
}

func smsDeliveryPartIndexes(tx *gorm.DB) ([]sqliteIndexInfo, error) {
	var indexes []sqliteIndexInfo
	if err := tx.Raw(`PRAGMA index_list('sms_delivery_part')`).Scan(&indexes).Error; err != nil {
		return nil, fmt.Errorf("sms delivery part index migration: index list: %w", err)
	}
	return indexes, nil
}
