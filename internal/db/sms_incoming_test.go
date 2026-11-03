package db

import (
	"path/filepath"
	"testing"
	"time"
)

func TestIncomingSMSPersistsOutOfOrderPartsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.db")
	if err := Init(path); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	part := IncomingSMSPart{Fingerprint: "fixture-2", IMSI: "fixture-sim", Sender: "fixture-sender", Content: "world", Timestamp: at, Reference: 4, ReferenceBits: 8, Total: 2, Sequence: 2}
	result, err := StoreIncomingSMSPart(part, 30*time.Minute)
	if err != nil || result.Stored {
		t.Fatalf("first part: stored=%v err=%v", result.Stored, err)
	}
	database, _ := DB.DB()
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Init(path); err != nil {
		t.Fatal(err)
	}
	defer func() { database, _ := DB.DB(); _ = database.Close() }()
	part.Fingerprint, part.Sequence, part.Content = "fixture-1", 1, "hello "
	result, err = StoreIncomingSMSPart(part, 30*time.Minute)
	if err != nil || !result.Stored || result.SMS.Content != "hello world" {
		t.Fatalf("assembly failed: stored=%v err=%v", result.Stored, err)
	}
	result, err = StoreIncomingSMSPart(part, 30*time.Minute)
	if err != nil || result.Stored {
		t.Fatal("retransmitted part produced a duplicate notification")
	}
	rows, err := GetSMSByIMSI("fixture-sim", 10)
	if err != nil || len(rows) != 1 || rows[0].Content != "hello world" {
		t.Fatal("inbox did not contain exactly one assembled SMS")
	}
}

func TestIncomingSMSRollbackAllowsNetworkRetry(t *testing.T) {
	openTestDB(t)
	part := IncomingSMSPart{Fingerprint: "rollback-fixture", IMSI: "fixture-sim", Sender: "fixture-sender", Content: "fixture", Timestamp: time.Now(), Total: 1, Sequence: 1}
	if err := DB.Migrator().DropTable(&SMSContact{}); err != nil {
		t.Fatal(err)
	}
	if _, err := StoreIncomingSMSPart(part, time.Minute); err == nil {
		t.Fatal("inbox contact failure was ignored")
	}
	if err := DB.AutoMigrate(&SMSContact{}); err != nil {
		t.Fatal(err)
	}
	result, err := StoreIncomingSMSPart(part, time.Minute)
	if err != nil || !result.Stored {
		t.Fatal("failed transaction left a duplicate marker and lost the retried SMS")
	}
}

func TestIncomingSMSRejectsConflictingMultipartSequence(t *testing.T) {
	openTestDB(t)
	part := IncomingSMSPart{Fingerprint: "first-fixture", IMSI: "fixture-sim", Sender: "fixture-sender", Content: "first", Timestamp: time.Now(), Total: 2, Sequence: 1, Reference: 7, ReferenceBits: 8}
	if _, err := StoreIncomingSMSPart(part, time.Minute); err != nil {
		t.Fatal(err)
	}
	part.Fingerprint, part.Content = "collision-fixture", "different"
	if _, err := StoreIncomingSMSPart(part, time.Minute); err == nil {
		t.Fatal("ambiguous fragment was accepted")
	}
	part.Fingerprint, part.Content, part.Sequence = "second-fixture", " second", 2
	result, err := StoreIncomingSMSPart(part, time.Minute)
	if err != nil || !result.Stored || result.SMS.Content != "first second" {
		t.Fatal("conflict corrupted the original assembly")
	}
}
