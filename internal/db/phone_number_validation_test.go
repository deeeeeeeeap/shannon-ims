package db

import "testing"

func TestUpdateVoWiFiPhoneRejectsValueEqualToIMSI(t *testing.T) {
	initPhoneNumberTestDB(t)
	imsi := "234150999999999"
	if err := UpdateSIMCardVoWiFiPhoneNumberByIMSI(imsi, "+"+imsi); err != nil {
		t.Fatalf("UpdateSIMCardVoWiFiPhoneNumberByIMSI error=%v", err)
	}
	got, err := GetSIMCardPhoneNumberByIMSI(imsi)
	if err != nil {
		t.Fatalf("GetSIMCardPhoneNumberByIMSI error=%v", err)
	}
	if got != "" {
		t.Fatalf("phone=%q, want empty (IMSI-equal value must be rejected)", got)
	}
}

func TestLooksLikePhoneNumberRejectsOverLongDigits(t *testing.T) {
	if looksLikePhoneNumber("1234567890123456") {
		t.Fatal("16-digit string must not look like a phone number")
	}
	if !looksLikePhoneNumber("+447700900123") {
		t.Fatal("valid E.164 number must pass")
	}
}
