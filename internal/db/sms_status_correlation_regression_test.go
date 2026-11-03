package db

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestStatusReportDoesNotHideAmbiguityBehindCandidateLimit(t *testing.T) {
	previous := DB
	DB = newSMSDeliveryStateTestDB(t)
	t.Cleanup(func() { DB = previous })
	at := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 18; i++ {
		messageID := fmt.Sprintf("candidate-%d", i)
		peer := "55502"
		if i == 0 || i == 17 {
			peer = "55501"
		}
		created := at.Add(time.Duration(i) * time.Second)
		if err := CreateSMSDelivery(messageID, "synthetic-imsi", "synthetic-device", peer, "synthetic", 1, created); err != nil {
			t.Fatal(err)
		}
		if err := UpsertSMSDeliveryPart(messageID, 1, "", 42, SMSDeliveryPartStateAcked, created); err != nil {
			t.Fatal(err)
		}
	}
	_, err := MarkSMSDeliveryPartStatusReport("synthetic-imsi", "synthetic-device", "55501", 42, SMSDeliveryPartStateDelivered, 0, at.Add(time.Minute))
	if !errors.Is(err, ErrSMSDeliveryReportAmbiguous) {
		t.Fatalf("expected ambiguous reference, got %v", err)
	}
	for _, id := range []string{"candidate-0", "candidate-17"} {
		status, err := GetSMSDeliveryStatus(id)
		if err != nil {
			t.Fatal(err)
		}
		if status.Parts[0].State != SMSDeliveryPartStateAcked {
			t.Fatal("ambiguous report changed a submission")
		}
	}
}

func TestStatusReportCanConfirmDeliveryAfterSubmissionFailure(t *testing.T) {
	for _, state := range []string{SMSDeliveryPartStateFailed, SMSDeliveryPartStateTimeout} {
		t.Run(state, func(t *testing.T) {
			previous := DB
			DB = newSMSDeliveryStateTestDB(t)
			t.Cleanup(func() { DB = previous })
			at := time.Now().UTC().Truncate(time.Second)
			if err := CreateSMSDelivery("late-report", "synthetic-imsi", "synthetic-device", "55501", "synthetic", 1, at); err != nil {
				t.Fatal(err)
			}
			if err := UpsertSMSDeliveryPart("late-report", 1, "synthetic-call", 42, state, at); err != nil {
				t.Fatal(err)
			}
			_, err := MarkSMSDeliveryPartStatusReport("synthetic-imsi", "synthetic-device", "55501", 42, SMSDeliveryPartStateDelivered, 0, at.Add(time.Minute))
			if err != nil {
				t.Fatalf("late terminal report was rejected: %v", err)
			}
			status, err := GetSMSDeliveryStatus("late-report")
			if err != nil {
				t.Fatal(err)
			}
			if status.State != SMSDeliveryStateDelivered {
				t.Fatalf("state=%s, want delivered", status.State)
			}
		})
	}
}
