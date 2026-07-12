package db

import "testing"

func TestPhoneNumberSurvivesIMSIGap(t *testing.T) {
	initPhoneNumberTestDB(t)
	iccid := "8944000000000000999"
	imsi := "234150000000999"

	if err := RecordVoWiFiPhoneNumber("", iccid, "+447700900999"); err != nil {
		t.Fatalf("stage error=%v", err)
	}
	if p, _ := GetSIMCardPhoneNumberByIMSI(imsi); p != "" {
		t.Fatalf("by-IMSI=%q, want empty before migration", p)
	}
	if p, _ := GetPhoneNumberByIMSIOrICCID("", iccid); p != "+447700900999" {
		t.Fatalf("by-ICCID=%q, want +447700900999", p)
	}
	imei := "860000000000999"
	if err := UpsertSIMCard(iccid, imsi, "", "Op", &imei); err != nil {
		t.Fatalf("UpsertSIMCard error=%v", err)
	}
	if p, _ := GetSIMCardPhoneNumberByIMSI(imsi); p != "+447700900999" {
		t.Fatalf("by-IMSI=%q after migration, want +447700900999", p)
	}
	var cnt int64
	DB.Model(&PendingPhoneNumber{}).Count(&cnt)
	if cnt != 0 {
		t.Fatalf("pending rows=%d, want 0", cnt)
	}
}
