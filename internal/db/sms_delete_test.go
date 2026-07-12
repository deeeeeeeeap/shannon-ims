package db

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func initSMSDeleteTestDB(t *testing.T) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "sms_delete.db")
	if err := Init(dbPath); err != nil {
		t.Fatalf("Init() error=%v", err)
	}
	t.Cleanup(func() { DB = nil })
}

func TestDeleteSMSByIDRebuildsContact(t *testing.T) {
	initSMSDeleteTestDB(t)

	base := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	if err := SaveSMS("imsi-1", "+10086", "+86138", "first", 1, 0, base); err != nil {
		t.Fatalf("SaveSMS(first) error=%v", err)
	}
	if err := SaveSMS("imsi-1", "me", "+10086", "second", 2, 2, base.Add(time.Second)); err != nil {
		t.Fatalf("SaveSMS(second) error=%v", err)
	}

	var latest SMS
	if err := DB.Where("imsi = ? AND peer = ?", "imsi-1", "+10086").Order("timestamp desc, id desc").First(&latest).Error; err != nil {
		t.Fatalf("First(latest) error=%v", err)
	}

	threadEmpty, imsi, peer, err := DeleteSMSByID(latest.ID)
	if err != nil {
		t.Fatalf("DeleteSMSByID() error=%v", err)
	}
	if threadEmpty {
		t.Fatal("threadEmpty=true want=false")
	}
	if imsi != "imsi-1" || peer != "+10086" {
		t.Fatalf("unexpected scope imsi=%q peer=%q", imsi, peer)
	}

	var contact SMSContact
	if err := DB.Where("imsi = ? AND peer = ?", "imsi-1", "+10086").First(&contact).Error; err != nil {
		t.Fatalf("First(contact) error=%v", err)
	}
	if contact.LastContent != "first" {
		t.Fatalf("LastContent=%q want=first", contact.LastContent)
	}
	if contact.UnreadCount != 1 {
		t.Fatalf("UnreadCount=%d want=1", contact.UnreadCount)
	}
}

func TestDeleteSMSByIMSIAndPeerDeletesThreadAndContact(t *testing.T) {
	initSMSDeleteTestDB(t)

	base := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	if err := SaveSMS("imsi-2", "+20086", "+86139", "one", 1, 0, base); err != nil {
		t.Fatalf("SaveSMS(one) error=%v", err)
	}
	if err := SaveSMS("imsi-2", "me", "+20086", "two", 2, 2, base.Add(time.Second)); err != nil {
		t.Fatalf("SaveSMS(two) error=%v", err)
	}

	deleted, err := DeleteSMSByIMSIAndPeer("imsi-2", "+20086")
	if err != nil {
		t.Fatalf("DeleteSMSByIMSIAndPeer() error=%v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted=%d want=2", deleted)
	}

	var smsCount int64
	if err := DB.Model(&SMS{}).Where("imsi = ? AND peer = ?", "imsi-2", "+20086").Count(&smsCount).Error; err != nil {
		t.Fatalf("Count(sms) error=%v", err)
	}
	if smsCount != 0 {
		t.Fatalf("smsCount=%d want=0", smsCount)
	}

	var contactCount int64
	if err := DB.Model(&SMSContact{}).Where("imsi = ? AND peer = ?", "imsi-2", "+20086").Count(&contactCount).Error; err != nil {
		t.Fatalf("Count(contact) error=%v", err)
	}
	if contactCount != 0 {
		t.Fatalf("contactCount=%d want=0", contactCount)
	}
}

func TestDeleteSMSNotFound(t *testing.T) {
	initSMSDeleteTestDB(t)

	if _, _, _, err := DeleteSMSByID(999); !errors.Is(err, ErrSMSNotFound) {
		t.Fatalf("DeleteSMSByID() err=%v want ErrSMSNotFound", err)
	}
	if _, err := DeleteSMSByIMSIAndPeer("missing", "+000"); !errors.Is(err, ErrSMSNotFound) {
		t.Fatalf("DeleteSMSByIMSIAndPeer() err=%v want ErrSMSNotFound", err)
	}
}
