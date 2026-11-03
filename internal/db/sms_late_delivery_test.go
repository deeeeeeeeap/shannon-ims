package db

import (
	"testing"
	"time"
)

func TestLateDeliveredCorrectsSubmissionFailureOnlyWhenComplete(t *testing.T) {
	for _, total := range []int{1, 2} {
		t.Run(string(rune('0'+total)), func(t *testing.T) {
			previous := DB
			DB = newSMSDeliveryStateTestDB(t)
			if err := DB.AutoMigrate(&SMSContact{}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { connection, _ := DB.DB(); _ = connection.Close(); DB = previous })
			at := time.Now().UTC().Truncate(time.Second)
			if err := CreateSMSDelivery("fixture-message", "fixture-sim", "fixture-device", "55501", "fixture", total, at); err != nil {
				t.Fatal(err)
			}
			if err := UpsertSMSDeliveryPart("fixture-message", 1, "fixture-call", 7, SMSDeliveryPartStateFailed, at); err != nil {
				t.Fatal(err)
			}
			if err := RecomputeSMSDelivery("fixture-message", at); err != nil {
				t.Fatal(err)
			}
			if err := SaveVoWiFiSMSWithLocalPhone("fixture-message", "fixture-sim", "", "", "55501", "fixture", 2, 3, at); err != nil {
				t.Fatal(err)
			}
			if _, err := MarkSMSDeliveryPartStatusReport("fixture-sim", "fixture-device", "55501", 7, SMSDeliveryPartStateDelivered, 0, at.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			status, err := GetSMSDeliveryStatus("fixture-message")
			if err != nil {
				t.Fatal(err)
			}
			want := SMSDeliveryStateDelivered
			if total > 1 {
				want = SMSDeliveryStateFailed
			}
			if status.State != want {
				t.Fatalf("aggregate=%s want %s", status.State, want)
			}
			rows, err := GetSMSByIMSI("fixture-sim", 10)
			wantHistory := 5
			if total > 1 {
				wantHistory = 3
			}
			if err != nil || len(rows) != 1 || rows[0].Status != wantHistory {
				t.Fatal("SMS history did not follow the terminal delivery result")
			}
		})
	}
}
