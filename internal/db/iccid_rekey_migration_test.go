package db

import "testing"

func TestBuildIMSIToICCIDMapExcludesReaderSynthetic(t *testing.T) {
	openTestDB(t)
	if err := DB.Create(&SIMCard{ICCID: "ICC1", IMSI: "IMSI1"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Create(&SIMCard{ICCID: "reader-imsi-IMSI2", IMSI: "IMSI2"}).Error; err != nil {
		t.Fatal(err)
	}

	m, err := buildIMSIToICCIDMap(DB)
	if err != nil {
		t.Fatal(err)
	}
	if m["IMSI1"] != "ICC1" {
		t.Fatalf("真实映射错: %+v", m)
	}
	if _, ok := m["IMSI2"]; ok {
		t.Fatalf("reader-imsi- 合成 ICCID 应被排除: %+v", m)
	}
}

func TestResolveICCIDForRow(t *testing.T) {
	m := map[string]string{"IMSI1": "ICC1"}
	if got := resolveICCIDForRow("IMSI1", m); got != "ICC1" {
		t.Fatalf("got=%q", got)
	}
	if got := resolveICCIDForRow("IMSI_X", m); got != "imsi:IMSI_X" {
		t.Fatalf("孤儿键错: %q", got)
	}
	if got := resolveICCIDForRow("  ", m); got != "" {
		t.Fatalf("空 IMSI 应返回空串: %q", got)
	}
}

func TestBackfillSMSICCIDWithOrphan(t *testing.T) {
	openTestDB(t)
	if err := DB.Create(&SIMCard{ICCID: "ICCA", IMSI: "IMSIA"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Exec("INSERT INTO sms (imsi, peer, content) VALUES (?,?,?)", "IMSIA", "+100", "hi").Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Exec("INSERT INTO sms (imsi, peer, content) VALUES (?,?,?)", "IMSI_ORPHAN", "+200", "x").Error; err != nil {
		t.Fatal(err)
	}

	if err := backfillICCIDColumn(DB, "sms"); err != nil {
		t.Fatalf("backfill error=%v", err)
	}

	var iccidA, iccidOrphan string
	DB.Raw("SELECT iccid FROM sms WHERE imsi = ?", "IMSIA").Scan(&iccidA)
	DB.Raw("SELECT iccid FROM sms WHERE imsi = ?", "IMSI_ORPHAN").Scan(&iccidOrphan)
	if iccidA != "ICCA" {
		t.Fatalf("真实回填错: %q", iccidA)
	}
	if iccidOrphan != "imsi:IMSI_ORPHAN" {
		t.Fatalf("孤儿回填错: %q", iccidOrphan)
	}
}

func TestRunICCIDReKeyMigrationIdempotent(t *testing.T) {
	openTestDB(t)
	if err := DB.Create(&SIMCard{ICCID: "ICCB", IMSI: "IMSIB"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Exec("INSERT INTO sms (imsi, peer, content) VALUES (?,?,?)", "IMSIB", "+1", "a").Error; err != nil {
		t.Fatal(err)
	}

	// 跑两次应得到同样结果，且不报错（幂等）。
	if err := RunICCIDReKeyMigration(DB); err != nil {
		t.Fatalf("first run error=%v", err)
	}
	if err := RunICCIDReKeyMigration(DB); err != nil {
		t.Fatalf("second run error=%v", err)
	}

	var iccid string
	DB.Raw("SELECT iccid FROM sms WHERE imsi = ?", "IMSIB").Scan(&iccid)
	if iccid != "ICCB" {
		t.Fatalf("幂等回填错: %q", iccid)
	}
	// 所有目标表都应已具备 iccid 列
	for _, table := range iccidReKeyTables {
		var has int64
		DB.Raw("SELECT count(*) FROM pragma_table_info(?) WHERE name = 'iccid'", table).Scan(&has)
		if has == 0 {
			t.Fatalf("%s 表缺 iccid 列", table)
		}
	}
}
