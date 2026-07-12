package device

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectMBIMUSBCapability(t *testing.T) {
	root := t.TempDir()
	usb := filepath.Join(root, "1-1")
	iface := filepath.Join(usb, "1-1:1.0")
	if err := os.MkdirAll(filepath.Join(iface, "net", "wwan0"), 0o755); err != nil {
		t.Fatal(err)
	}
	drv := filepath.Join(root, "drv", "cdc_mbim")
	if err := os.MkdirAll(drv, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(drv, filepath.Join(iface, "driver")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(iface, "usbmisc", "cdc-wdm0"), 0o755); err != nil {
		t.Fatal(err)
	}

	capability, ok := detectMBIMUSBCapability(usb)
	if !ok {
		t.Fatal("expected MBIM capability")
	}
	if capability.DriverName != "cdc_mbim" {
		t.Fatalf("driver = %q", capability.DriverName)
	}
	if capability.ControlPath == "" {
		t.Fatal("expected cdc-wdm control path")
	}
}
