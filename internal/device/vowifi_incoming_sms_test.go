package device

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/db"
)

func TestVoWiFiIncomingSMSDecodesPersistsAndNotifiesOnce(t *testing.T) {
	if err := db.Init(filepath.Join(t.TempDir(), "inbox.db")); err != nil {
		t.Fatal(err)
	}
	defer func() { database, _ := db.DB.DB(); _ = database.Close() }()
	pool := NewPool(nil)
	notifier := &countingVoWiFiNotifier{}
	pool.SetNotifier(notifier)
	store := vowifiDeliveryStore{pool: pool}
	// Synthetic UCS2 SMS-DELIVER, with a service-centre timestamp and short code.
	tpdu := []byte{0, 5, 0x81, 0x55, 0x05, 0xf1, 0, 8, 0x62, 0x11, 0x30, 0x01, 0, 0, 0, 4, 0, 'H', 0, 'i'}
	for i := 0; i < 2; i++ {
		if err := store.StoreIncomingSMS("fixture-sim", "fixture-device", tpdu, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.GetSMSByIMSI("fixture-sim", 10)
	if err != nil || len(rows) != 1 || rows[0].Content != "Hi" || notifier.smsCount != 1 {
		t.Fatalf("inbox=%d notifications=%d err=%v", len(rows), notifier.smsCount, err)
	}
}

func TestVoWiFiIncomingMultipartSMSNotifiesOnlyAfterAssembly(t *testing.T) {
	if err := db.Init(filepath.Join(t.TempDir(), "inbox.db")); err != nil {
		t.Fatal(err)
	}
	defer func() { database, _ := db.DB.DB(); _ = database.Close() }()
	pool := NewPool(nil)
	notifier := &countingVoWiFiNotifier{}
	pool.SetNotifier(notifier)
	store := vowifiDeliveryStore{pool: pool}
	for _, seq := range []byte{2, 1, 2} {
		tpdu := []byte{0x40, 5, 0x81, 0x55, 0x05, 0xf1, 0, 8, 0x62, 0x11, 0x30, 0x01, 0, 0, 0, 8, 5, 0, 3, 7, 2, seq, 0, 'A' + seq - 1}
		if err := store.StoreIncomingSMS("fixture-sim", "fixture-device", tpdu, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.GetSMSByIMSI("fixture-sim", 10)
	if err != nil || len(rows) != 1 || rows[0].Content != "AB" || notifier.smsCount != 1 {
		t.Fatal("multipart SMS was lost or notified more than once")
	}
}
