package db

import (
	"testing"
	"time"
)

func TestGetICCIDForIMSI(t *testing.T) {
	openTestDB(t)
	if err := DB.Create(&SIMCard{ICCID: "ICC_A", IMSI: "IMSI_A"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Create(&SIMCard{ICCID: "reader-imsi-IMSI_B", IMSI: "IMSI_B"}).Error; err != nil {
		t.Fatal(err)
	}

	if got := GetICCIDForIMSI("IMSI_A"); got != "ICC_A" {
		t.Fatalf("真实映射错: %q", got)
	}
	// reader-imsi- 合成 ICCID 应回退为 imsi: 前缀
	if got := GetICCIDForIMSI("IMSI_B"); got != "imsi:IMSI_B" {
		t.Fatalf("合成 ICCID 应使用 imsi: 前缀: %q", got)
	}
	// 无记录应回退
	if got := GetICCIDForIMSI("IMSI_NONE"); got != "imsi:IMSI_NONE" {
		t.Fatalf("无映射应使用 imsi: 前缀: %q", got)
	}
	// 空 IMSI
	if got := GetICCIDForIMSI(""); got != "" {
		t.Fatalf("空 IMSI 应返回空串: %q", got)
	}
}

func TestGetSMSByICCID(t *testing.T) {
	openTestDB(t)
	now := time.Now()
	if err := DB.Exec("INSERT INTO sms (iccid, imsi, peer, content, timestamp) VALUES (?,?,?,?,?)",
		"ICC1", "IMSI1", "+100", "hello", now).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Exec("INSERT INTO sms (iccid, imsi, peer, content, timestamp) VALUES (?,?,?,?,?)",
		"ICC2", "IMSI2", "+200", "other", now).Error; err != nil {
		t.Fatal(err)
	}

	list, err := GetSMSByICCID("ICC1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Peer != "+100" {
		t.Fatalf("ICCID 过滤错: %+v", list)
	}
}

func TestGetSMSContactsByICCID(t *testing.T) {
	openTestDB(t)
	now := time.Now()
	// 直接插入 sms_contacts 行（跳过触发器逻辑）
	if err := DB.Exec(`INSERT INTO sms_contacts (iccid, imsi, peer, last_sms_id, last_timestamp, last_content, last_type, unread_count)
		VALUES (?,?,?,?,?,?,?,?)`, "ICC_C", "IMSI_C", "+300", 1, now, "hi", 1, 0).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Exec(`INSERT INTO sms_contacts (iccid, imsi, peer, last_sms_id, last_timestamp, last_content, last_type, unread_count)
		VALUES (?,?,?,?,?,?,?,?)`, "ICC_D", "IMSI_D", "+400", 2, now, "x", 1, 0).Error; err != nil {
		t.Fatal(err)
	}

	contacts, err := GetSMSContactsByICCID("ICC_C", 10, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 || contacts[0].Peer != "+300" {
		t.Fatalf("ICCID 联系人过滤错: %+v", contacts)
	}
}

func TestGetSMSByICCIDAndPeer(t *testing.T) {
	openTestDB(t)
	now := time.Now()
	for _, peer := range []string{"+111", "+222"} {
		if err := DB.Exec("INSERT INTO sms (iccid, imsi, peer, content, timestamp) VALUES (?,?,?,?,?)",
			"ICCE", "IMSIE", peer, "msg", now).Error; err != nil {
			t.Fatal(err)
		}
	}

	list, err := GetSMSByICCIDAndPeer("ICCE", "+111", 10, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Peer != "+111" {
		t.Fatalf("ICCID+peer 过滤错: %+v", list)
	}
}

// 回归：新收短信必须带 iccid，否则 ICCID 维度查询全部落空。
func TestSaveSMSPopulatesICCID(t *testing.T) {
	openTestDB(t)
	if err := DB.Create(&SIMCard{ICCID: "ICC_SAVE", IMSI: "IMSI_SAVE"}).Error; err != nil {
		t.Fatal(err)
	}

	if err := SaveSMS("IMSI_SAVE", "+10086", "", "hello", 1, 0, time.Now()); err != nil {
		t.Fatalf("SaveSMS error=%v", err)
	}

	// SMS 行带真实 iccid，按 ICCID 查得到。
	list, err := GetSMSByICCID("ICC_SAVE", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ICCID != "ICC_SAVE" {
		t.Fatalf("新短信 iccid 未回填: %+v", list)
	}

	// 联系人行也必须带 iccid。
	contacts, err := GetSMSContactsByICCID("ICC_SAVE", 10, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 || contacts[0].ICCID != "ICC_SAVE" {
		t.Fatalf("联系人 iccid 未回填: %+v", contacts)
	}
}

// 无 sim_cards 映射时回退 "imsi:" 前缀合成键，与 P4 回填约定一致。
func TestSaveSMSOrphanICCIDFallback(t *testing.T) {
	openTestDB(t)
	if err := SaveSMS("IMSI_NOMAP", "+10086", "", "hi", 1, 0, time.Now()); err != nil {
		t.Fatalf("SaveSMS error=%v", err)
	}
	list, err := GetSMSByICCID("imsi:IMSI_NOMAP", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("孤儿短信应使用 imsi: 前缀键: %+v", list)
	}
}

// 上行投递记录也要带 iccid，与 sms/sms_contacts 维度一致。
func TestCreateSMSDeliveryPopulatesICCID(t *testing.T) {
	openTestDB(t)
	if err := DB.Create(&SIMCard{ICCID: "ICC_DLV", IMSI: "IMSI_DLV"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := CreateSMSDelivery("msg-1", "IMSI_DLV", "wwan0", "+10086", "hi", 1, time.Now()); err != nil {
		t.Fatalf("CreateSMSDelivery error=%v", err)
	}
	st, err := GetSMSDeliveryStatus("msg-1")
	if err != nil {
		t.Fatal(err)
	}
	if st.ICCID != "ICC_DLV" {
		t.Fatalf("投递记录 iccid 未回填: %+v", st)
	}
}

func TestDeleteSMSByICCIDAndPeer(t *testing.T) {
	openTestDB(t)
	now := time.Now()
	if err := DB.Exec("INSERT INTO sms (iccid, imsi, peer, content, timestamp) VALUES (?,?,?,?,?)",
		"ICCF", "IMSIF", "+500", "bye", now).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Exec(`INSERT INTO sms_contacts (iccid, imsi, peer, last_sms_id, last_timestamp, last_content, last_type, unread_count)
		VALUES (?,?,?,?,?,?,?,?)`, "ICCF", "IMSIF", "+500", 1, now, "bye", 1, 0).Error; err != nil {
		t.Fatal(err)
	}

	deleted, err := DeleteSMSByICCIDAndPeer("ICCF", "+500")
	if err != nil {
		t.Fatalf("删除错: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("删除行数错: %d", deleted)
	}

	var count int64
	DB.Model(&SMS{}).Where("iccid = ? AND peer = ?", "ICCF", "+500").Count(&count)
	if count != 0 {
		t.Fatalf("SMS 行未删除")
	}
}
