package db

import (
	"path/filepath"
	"testing"
)

func initIPv6TestDB(t *testing.T) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "ipv6.db")
	if err := Init(dbPath); err != nil {
		t.Fatalf("Init() error=%v", err)
	}
	t.Cleanup(func() { DB = nil })
}

func TestUpdateDeviceIPsV6(t *testing.T) {
	initIPv6TestDB(t)

	if err := DB.Create(&Device{IMEI: "imei-1"}).Error; err != nil {
		t.Fatalf("seed device error=%v", err)
	}

	if err := UpdateDeviceIPsV6("imei-1", "1.2.3.4", "2001:db8::1", "10.0.0.2", "fe80::2"); err != nil {
		t.Fatal(err)
	}

	var d Device
	if err := DB.Where("imei = ?", "imei-1").First(&d).Error; err != nil {
		t.Fatal(err)
	}
	if d.PublicIP != "1.2.3.4" || d.PublicIPv6 != "2001:db8::1" {
		t.Fatalf("public v4/v6 = %q / %q", d.PublicIP, d.PublicIPv6)
	}
	if d.PrivateIP != "10.0.0.2" || d.PrivateIPv6 != "fe80::2" {
		t.Fatalf("private v4/v6 = %q / %q", d.PrivateIP, d.PrivateIPv6)
	}
}
