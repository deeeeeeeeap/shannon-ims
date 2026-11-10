package db

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestPurgeIncomingSMSJournalRemovesOnlyOldRows(t *testing.T) {
	openTestDB(t)
	now := time.Now()
	old := now.Add(-40 * 24 * time.Hour)
	rows := []SMSIncomingPartJournal{
		{Fingerprint: "old-completed-1", AssemblyKey: "a", MessageID: "ims-in-old", Sequence: 1, Timestamp: old, CreatedAt: old},
		{Fingerprint: "old-completed-2", AssemblyKey: "a", MessageID: "ims-in-old", Sequence: 2, Timestamp: old, CreatedAt: old},
		{Fingerprint: "old-incomplete", AssemblyKey: "b", Sequence: 1, Content: "never completed", Timestamp: old, CreatedAt: old},
		{Fingerprint: "recent-completed", AssemblyKey: "c", MessageID: "ims-in-recent", Sequence: 1, Timestamp: now, CreatedAt: now},
		{Fingerprint: "recent-incomplete", AssemblyKey: "d", Sequence: 1, Content: "still waiting", Timestamp: now, CreatedAt: now},
	}
	if err := DB.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	before := now.Add(-30 * 24 * time.Hour)

	removed, err := PurgeIncomingSMSJournal(before)
	if err != nil {
		t.Fatalf("PurgeIncomingSMSJournal() error = %v", err)
	}
	if want := (IncomingSMSJournalPurge{Completed: 2, Incomplete: 1}); removed != want {
		t.Fatalf("removed = %+v, want %+v", removed, want)
	}

	var left []SMSIncomingPartJournal
	if err := DB.Find(&left).Error; err != nil {
		t.Fatal(err)
	}
	fingerprints := make([]string, 0, len(left))
	for _, row := range left {
		fingerprints = append(fingerprints, row.Fingerprint)
	}
	sort.Strings(fingerprints)
	if want := []string{"recent-completed", "recent-incomplete"}; !reflect.DeepEqual(fingerprints, want) {
		t.Fatalf("rows left = %v, want %v", fingerprints, want)
	}

	removed, err = PurgeIncomingSMSJournal(before)
	if err != nil || removed != (IncomingSMSJournalPurge{}) {
		t.Fatalf("second purge removed %+v, error %v; want nothing", removed, err)
	}
}

func TestPurgeIncomingSMSJournalNeedsADatabase(t *testing.T) {
	previous := DB
	DB = nil
	t.Cleanup(func() { DB = previous })

	if _, err := PurgeIncomingSMSJournal(time.Now()); err == nil {
		t.Fatal("PurgeIncomingSMSJournal() without a database succeeded")
	}
}

func TestIncomingSMSMessageIDNamesTheChannel(t *testing.T) {
	openTestDB(t)
	at := time.Now()
	overIMS := IncomingSMSPart{Fingerprint: "fixture-ims", IMSI: "fixture-sim", Sender: "fixture-sender",
		Content: "over IMS", Timestamp: at, Total: 1, Sequence: 1}
	fromModem := IncomingSMSPart{Fingerprint: "fixture-cell", IMSI: "fixture-sim", Sender: "fixture-sender",
		Content: "from the modem", Timestamp: at, Total: 1, Sequence: 1, MessageIDPrefix: IncomingSMSMessageIDPrefixCellular}

	result, err := StoreIncomingSMSPart(overIMS, time.Minute)
	if err != nil || !result.Stored || result.SMS.MessageID != "ims-in-fixture-ims" {
		t.Fatalf("over IMS: stored=%v message ID=%q error=%v", result.Stored, result.SMS.MessageID, err)
	}
	result, err = StoreIncomingSMSPart(fromModem, time.Minute)
	if err != nil || !result.Stored || result.SMS.MessageID != "cell-in-fixture-cell" {
		t.Fatalf("from the modem: stored=%v message ID=%q error=%v", result.Stored, result.SMS.MessageID, err)
	}
}
