package db

import (
	"strings"

	"gorm.io/gorm"
)

// P4：把 IMSI 关联的历史表统一补上 iccid 维度（加列回填，不改主键、不破坏现有 IMSI 读取）。
// 与现有 migrateSIMCardsToSubscriptions 保持同样的 reader-imsi- 合成 ICCID 排除语义。

// iccidReKeyTables 是直接带 imsi 列、需要补 iccid 维度的表。
// 主键不变（sms 用自增 ID，contacts/delivery 维持原主键），仅新增并回填 iccid。
// sms_delivery_part 不在此列：它无 imsi 列，经 message_id 关联 sms_delivery 间接获得 ICCID。
var iccidReKeyTables = []string{"sms", "sms_contacts", "sms_delivery"}

// buildIMSIToICCIDMap 用 sim_cards 建立 IMSI→真实 ICCID 映射，排除 reader-imsi- 合成 ICCID。
func buildIMSIToICCIDMap(tx *gorm.DB) (map[string]string, error) {
	out := map[string]string{}
	if tx == nil || !tx.Migrator().HasTable("sim_cards") {
		return out, nil
	}
	type row struct {
		ICCID string `gorm:"column:iccid"`
		IMSI  string `gorm:"column:imsi"`
	}
	var rows []row
	if err := tx.Table("sim_cards").Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		imsi := strings.TrimSpace(r.IMSI)
		iccid := strings.TrimSpace(r.ICCID)
		if imsi == "" || iccid == "" || strings.HasPrefix(iccid, "reader-imsi-") {
			continue
		}
		out[imsi] = iccid
	}
	return out, nil
}

// resolveICCIDForRow 把一行的 IMSI 解析为 ICCID；
// 无真实映射的孤儿用 "imsi:" 前缀合成键保数据可审计；空 IMSI 返回空串（跳过）。
func resolveICCIDForRow(imsi string, m map[string]string) string {
	imsi = strings.TrimSpace(imsi)
	if imsi == "" {
		return ""
	}
	if iccid, ok := m[imsi]; ok && iccid != "" {
		return iccid
	}
	return "imsi:" + imsi
}

// backfillICCIDColumn 给指定表加 iccid 列（若无）并按 IMSI→ICCID 回填全部行。幂等。
func backfillICCIDColumn(tx *gorm.DB, table string) error {
	if tx == nil || !tx.Migrator().HasTable(table) {
		return nil
	}
	// 防御：无 imsi 列的表无法按 IMSI 回填，跳过。
	var hasIMSI int64
	if err := tx.Raw("SELECT count(*) FROM pragma_table_info(?) WHERE name = 'imsi'", table).Scan(&hasIMSI).Error; err != nil {
		return err
	}
	if hasIMSI == 0 {
		return nil
	}
	var hasCol int64
	if err := tx.Raw("SELECT count(*) FROM pragma_table_info(?) WHERE name = 'iccid'", table).Scan(&hasCol).Error; err != nil {
		return err
	}
	if hasCol == 0 {
		if err := tx.Exec("ALTER TABLE " + table + " ADD COLUMN iccid TEXT NOT NULL DEFAULT ''").Error; err != nil {
			return err
		}
	}
	m, err := buildIMSIToICCIDMap(tx)
	if err != nil {
		return err
	}
	type imsiRow struct {
		IMSI string `gorm:"column:imsi"`
	}
	var imsis []imsiRow
	if err := tx.Raw("SELECT DISTINCT imsi FROM " + table + " WHERE imsi IS NOT NULL AND imsi <> ''").Scan(&imsis).Error; err != nil {
		return err
	}
	for _, r := range imsis {
		iccid := resolveICCIDForRow(r.IMSI, m)
		if iccid == "" {
			continue
		}
		// 仅回填尚未赋值的行，幂等且不覆盖已存在的 iccid。
		if err := tx.Exec(
			"UPDATE "+table+" SET iccid = ? WHERE imsi = ? AND (iccid IS NULL OR iccid = '')",
			iccid, strings.TrimSpace(r.IMSI),
		).Error; err != nil {
			return err
		}
	}
	return nil
}

// RunICCIDReKeyMigration 对所有 IMSI 关联表回填 iccid 列。幂等，可重复执行。
func RunICCIDReKeyMigration(tx *gorm.DB) error {
	for _, table := range iccidReKeyTables {
		if err := backfillICCIDColumn(tx, table); err != nil {
			return err
		}
	}
	return nil
}
