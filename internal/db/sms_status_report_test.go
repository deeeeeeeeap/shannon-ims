package db

import (
	"errors"
	"testing"
	"time"
)

func TestMarkSMSDeliveryPartStatusReportAdvancesAcceptedPartToDelivered(t *testing.T) {
	database := newSMSDeliveryStateTestDB(t)
	previousDB := DB
	DB = database
	t.Cleanup(func() { DB = previousDB })

	at := time.Now().UTC().Truncate(time.Second)
	if err := CreateSMSDelivery("status-report", "synthetic-imsi", "synthetic-device", "+155501", "synthetic", 1, at); err != nil {
		t.Fatalf("CreateSMSDelivery: %v", err)
	}
	if err := UpsertSMSDeliveryPart("status-report", 1, "synthetic-call", 42, SMSDeliveryPartStateAcked, at); err != nil {
		t.Fatalf("UpsertSMSDeliveryPart: %v", err)
	}
	part, err := MarkSMSDeliveryPartStatusReport(
		"synthetic-imsi", "synthetic-device", "+155501", 42,
		SMSDeliveryPartStateDelivered, 0x00, at.Add(time.Second),
	)
	if err != nil {
		t.Fatalf("MarkSMSDeliveryPartStatusReport: %v", err)
	}
	if part.CorrelationMethod != "tp_mr" || part.State != SMSDeliveryPartStateDelivered {
		t.Fatalf("status report match = method %q state %q", part.CorrelationMethod, part.State)
	}
	status, err := GetSMSDeliveryStatus("status-report")
	if err != nil {
		t.Fatalf("GetSMSDeliveryStatus: %v", err)
	}
	if status.State != SMSDeliveryStateDelivered || status.Acks != 1 {
		t.Fatalf("aggregate state=%q acks=%d, want delivered/1", status.State, status.Acks)
	}
}

func TestMarkSMSDeliveryPartStatusReportAllowsTemporaryThenDelivered(t *testing.T) {
	database := newSMSDeliveryStateTestDB(t)
	previousDB := DB
	DB = database
	t.Cleanup(func() { DB = previousDB })

	at := time.Now().UTC().Truncate(time.Second)
	if err := CreateSMSDelivery("temporary-status", "synthetic-imsi", "synthetic-device", "55501", "synthetic", 1, at); err != nil {
		t.Fatal(err)
	}
	if err := UpsertSMSDeliveryPart("temporary-status", 1, "synthetic-call", 43, SMSDeliveryPartStateAcked, at); err != nil {
		t.Fatal(err)
	}
	if _, err := MarkSMSDeliveryPartStatusReport("synthetic-imsi", "synthetic-device", "55501", 43, SMSDeliveryPartStateDeliveryPending, 0x20, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	status, err := GetSMSDeliveryStatus("temporary-status")
	if err != nil || status.State != SMSDeliveryStateDeliveryPending {
		t.Fatalf("temporary status = %#v err=%v", status, err)
	}
	if _, err := MarkSMSDeliveryPartStatusReport("synthetic-imsi", "synthetic-device", "55501", 43, SMSDeliveryPartStateDelivered, 0x00, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	status, err = GetSMSDeliveryStatus("temporary-status")
	if err != nil || status.State != SMSDeliveryStateDelivered {
		t.Fatalf("final status = %#v err=%v", status, err)
	}
}

func TestMarkSMSDeliveryPartStatusReportRejectsAmbiguousReference(t *testing.T) {
	database := newSMSDeliveryStateTestDB(t)
	previousDB := DB
	DB = database
	t.Cleanup(func() { DB = previousDB })

	at := time.Now().UTC().Truncate(time.Second)
	for _, messageID := range []string{"ambiguous-old", "ambiguous-new"} {
		if err := CreateSMSDelivery(messageID, "synthetic-imsi", "synthetic-device", "55501", "synthetic", 1, at); err != nil {
			t.Fatal(err)
		}
		if err := UpsertSMSDeliveryPart(messageID, 1, messageID+"-call", 44, SMSDeliveryPartStateAcked, at); err != nil {
			t.Fatal(err)
		}
		at = at.Add(time.Second)
	}
	_, err := MarkSMSDeliveryPartStatusReport("synthetic-imsi", "synthetic-device", "55501", 44, SMSDeliveryPartStateDelivered, 0x00, at.Add(time.Second))
	if !errors.Is(err, ErrSMSDeliveryReportAmbiguous) {
		t.Fatalf("ambiguous status report error=%v", err)
	}
	for _, messageID := range []string{"ambiguous-old", "ambiguous-new"} {
		status, getErr := GetSMSDeliveryStatus(messageID)
		if getErr != nil || len(status.Parts) != 1 || status.Parts[0].State != SMSDeliveryPartStateAcked {
			t.Fatalf("ambiguous report mutated %s: status=%#v err=%v", messageID, status, getErr)
		}
	}
}
