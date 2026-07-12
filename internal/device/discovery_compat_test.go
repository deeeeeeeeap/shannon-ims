package device

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverCompatibleModemsFromQMI_MergeAndDedupByUSB(t *testing.T) {
	orig := discoverFallbackModemsFn
	t.Cleanup(func() { discoverFallbackModemsFn = orig })

	discoverFallbackModemsFn = func() ([]CompatibleModem, error) {
		return []CompatibleModem{
			{
				USBPath:      "/sys/bus/usb/devices/1-1",
				ATPort:       "/dev/ttyUSB9",
				Mode:         "ecm",
				DriverName:   "cdc_ether",
				NetInterface: "enx1",
			},
			{
				USBPath:      "/sys/bus/usb/devices/1-2",
				ATPort:       "/dev/ttyUSB4",
				Mode:         "ecm",
				DriverName:   "cdc_ether",
				NetInterface: "enx2",
			},
		}, nil
	}

	qmiList := []QMIDevice{
		{
			USBPath:      "/sys/bus/usb/devices/1-1",
			ATPort:       "/dev/ttyUSB2",
			ATPorts:      []string{"/dev/ttyUSB2", "/dev/ttyUSB3"},
			ControlPath:  "/dev/cdc-wdm0",
			DriverName:   "qmi_wwan",
			NetInterface: "wwan0",
		},
	}

	got, err := DiscoverCompatibleModemsFromQMI(qmiList)
	if err != nil {
		t.Fatalf("DiscoverCompatibleModemsFromQMI() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(got))
	}

	if got[0].USBPath != "/sys/bus/usb/devices/1-1" || got[0].Mode != "qmi" {
		t.Fatalf("expected first device to be qmi USB 1-1, got %+v", got[0])
	}

	foundFallback := false
	for _, d := range got {
		if d.USBPath == "/sys/bus/usb/devices/1-2" {
			foundFallback = true
			break
		}
	}
	if !foundFallback {
		t.Fatalf("expected fallback device USB 1-2 to be included, got %+v", got)
	}
}

func TestDiscoverCompatibleModemsFromQMI_FallbackErrorWithQMIStillSucceeds(t *testing.T) {
	orig := discoverFallbackModemsFn
	t.Cleanup(func() { discoverFallbackModemsFn = orig })

	discoverFallbackModemsFn = func() ([]CompatibleModem, error) {
		return nil, errors.New("fallback failed")
	}

	qmiList := []QMIDevice{
		{
			USBPath:      "/sys/bus/usb/devices/2-1",
			ATPort:       "/dev/ttyUSB2",
			ControlPath:  "/dev/cdc-wdm1",
			DriverName:   "qmi_wwan",
			NetInterface: "wwan1",
		},
	}

	got, err := DiscoverCompatibleModemsFromQMI(qmiList)
	if err != nil {
		t.Fatalf("DiscoverCompatibleModemsFromQMI() unexpected error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 qmi device, got %d", len(got))
	}
}

func TestDiscoverCompatibleModemsFromQMI_DoesNotInventATPortOrIMEI(t *testing.T) {
	orig := discoverFallbackModemsFn
	t.Cleanup(func() { discoverFallbackModemsFn = orig })

	discoverFallbackModemsFn = func() ([]CompatibleModem, error) {
		return nil, nil
	}

	qmiList := []QMIDevice{
		{
			USBPath:      "/sys/bus/usb/devices/3-1",
			ATPorts:      []string{"/dev/ttyUSB6", "/dev/ttyUSB7"},
			ATPort:       "",
			ControlPath:  "/dev/cdc-wdm3",
			DriverName:   "qmi_wwan",
			NetInterface: "wwan3",
		},
	}

	got, err := DiscoverCompatibleModemsFromQMI(qmiList)
	if err != nil {
		t.Fatalf("DiscoverCompatibleModemsFromQMI() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 qmi device, got %d", len(got))
	}
	if got[0].ATPort != "" {
		t.Fatalf("expected ATPort to stay empty, got %q", got[0].ATPort)
	}
	if got[0].IMEI != "" {
		t.Fatalf("expected IMEI to stay empty, got %q", got[0].IMEI)
	}
}

func TestDiscoverCompatibleModemsFromQMI_NoQMIAndFallbackError(t *testing.T) {
	orig := discoverFallbackModemsFn
	t.Cleanup(func() { discoverFallbackModemsFn = orig })

	discoverFallbackModemsFn = func() ([]CompatibleModem, error) {
		return nil, errors.New("fallback failed")
	}

	_, err := DiscoverCompatibleModemsFromQMI(nil)
	if err == nil {
		t.Fatal("expected error when qmi list empty and fallback failed")
	}
}

func TestCompatibleModemsFromQMIIncludesWWANFallbackWhenQMIListEmpty(t *testing.T) {
	orig := discoverFallbackModemsFn
	t.Cleanup(func() { discoverFallbackModemsFn = orig })

	discoverFallbackModemsFn = func() ([]CompatibleModem, error) {
		return []CompatibleModem{
			{
				ControlPath:    "/dev/wwan0qmi0",
				NetInterface:   "wwan0",
				USBPath:        "/sys/class/wwan/wwan0",
				DriverName:     "wwan_qmi",
				ATPorts:        []string{"/dev/wwan0at0", "/dev/wwan0at1"},
				ATPort:         "/dev/wwan0at0",
				Mode:           "qmi",
				NetworkCapable: true,
			},
		}, nil
	}

	got, err := DiscoverCompatibleModemsFromQMI(nil)
	if err != nil {
		t.Fatalf("DiscoverCompatibleModemsFromQMI(nil) error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d want 1 (%+v)", len(got), got)
	}
	if got[0].ControlPath != "/dev/wwan0qmi0" || got[0].Mode != "qmi" {
		t.Fatalf("unexpected WWAN fallback result: %+v", got[0])
	}
}

func TestCompatibleModemDiscoveryKey(t *testing.T) {
	m := CompatibleModem{USBPath: "/sys/bus/usb/devices/1-1", ATPort: "/dev/ttyUSB2"}
	if got := m.DiscoveryKey(); got != "/sys/bus/usb/devices/1-1|/dev/ttyUSB2" {
		t.Fatalf("unexpected key: %q", got)
	}
}

func TestDiscoverFallbackOneAcceptsVendorAgnosticQMIWithoutAT(t *testing.T) {
	usbPath := t.TempDir()
	usbName := filepath.Base(usbPath)

	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(usbPath, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	write("idVendor", "1199\n")
	write("idProduct", "9077\n")

	ifacePath := filepath.Join(usbPath, usbName+":1.8")
	if err := os.MkdirAll(filepath.Join(ifacePath, "net", "wwan5"), 0o755); err != nil {
		t.Fatalf("mkdir net iface: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(ifacePath, "usbmisc", "cdc-wdm5"), 0o755); err != nil {
		t.Fatalf("mkdir cdc-wdm tree: %v", err)
	}
	if err := os.Symlink("/tmp/qmi_wwan", filepath.Join(ifacePath, "driver")); err != nil {
		t.Fatalf("symlink driver: %v", err)
	}

	got, ok := discoverFallbackOne(usbPath)
	if !ok {
		t.Fatal("discoverFallbackOne() rejected vendor-agnostic QMI device")
	}
	if got.ControlPath != "/dev/cdc-wdm5" {
		t.Fatalf("ControlPath=%q want /dev/cdc-wdm5", got.ControlPath)
	}
	if got.NetInterface != "wwan5" {
		t.Fatalf("NetInterface=%q want wwan5", got.NetInterface)
	}
	if got.Mode != "qmi" || !got.NetworkCapable {
		t.Fatalf("mode=%q networkCapable=%v, want qmi true", got.Mode, got.NetworkCapable)
	}
	if got.ATPort != "" || len(got.ATPorts) != 0 {
		t.Fatalf("expected pure QMI without AT, got ATPort=%q ports=%v", got.ATPort, got.ATPorts)
	}
}

func TestDiscoverFallbackOneRejectsUnknownVendorWithoutNetworkCapability(t *testing.T) {
	usbPath := t.TempDir()
	usbName := filepath.Base(usbPath)

	if err := os.WriteFile(filepath.Join(usbPath, "idVendor"), []byte("1199\n"), 0o644); err != nil {
		t.Fatalf("write idVendor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(usbPath, "idProduct"), []byte("9077\n"), 0o644); err != nil {
		t.Fatalf("write idProduct: %v", err)
	}
	ifacePath := filepath.Join(usbPath, usbName+":1.8")
	if err := os.MkdirAll(filepath.Join(ifacePath, "net", "wwan5"), 0o755); err != nil {
		t.Fatalf("mkdir net iface: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(ifacePath, "usbmisc", "cdc-wdm5"), 0o755); err != nil {
		t.Fatalf("mkdir cdc-wdm tree: %v", err)
	}
	if err := os.Symlink("/tmp/cdc_ncm", filepath.Join(ifacePath, "driver")); err != nil {
		t.Fatalf("symlink driver: %v", err)
	}

	got, ok := discoverFallbackOne(usbPath)
	if ok {
		t.Fatalf("expected rejection for unknown non-QMI/non-MBIM device, got %+v", got)
	}
}

func TestDiscoverFallbackOneRejectsQMIWithoutControlPath(t *testing.T) {
	usbPath := t.TempDir()
	usbName := filepath.Base(usbPath)

	if err := os.WriteFile(filepath.Join(usbPath, "idVendor"), []byte("1199\n"), 0o644); err != nil {
		t.Fatalf("write idVendor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(usbPath, "idProduct"), []byte("9077\n"), 0o644); err != nil {
		t.Fatalf("write idProduct: %v", err)
	}

	ifacePath := filepath.Join(usbPath, usbName+":1.8")
	if err := os.MkdirAll(filepath.Join(ifacePath, "net", "wwan5"), 0o755); err != nil {
		t.Fatalf("mkdir net iface: %v", err)
	}
	if err := os.Symlink("/tmp/qmi_wwan", filepath.Join(ifacePath, "driver")); err != nil {
		t.Fatalf("symlink driver: %v", err)
	}

	got, ok := discoverFallbackOne(usbPath)
	if ok {
		t.Fatalf("expected rejection without cdc-wdm, got %+v", got)
	}
}

func TestClassifyMode(t *testing.T) {
	cases := []struct {
		name       string
		control    string
		driver     string
		expectMode string
	}{
		{name: "qmi", control: "/dev/cdc-wdm0", driver: "qmi_wwan", expectMode: "qmi"},
		{name: "wwan qmi control path", control: "/dev/wwan0qmi0", driver: "wwan_qmi", expectMode: "qmi"},
		{name: "mbim", control: "/dev/cdc-wdm2", driver: "cdc_mbim", expectMode: "mbim"},
		{name: "ecm", driver: "cdc_ether", expectMode: "ecm"},
		{name: "rndis", driver: "rndis_host", expectMode: "rndis"},
		{name: "ncm", driver: "cdc_ncm", expectMode: "ncm"},
		{name: "unknown", driver: "usbserial", expectMode: "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyMode(tc.control, tc.driver); got != tc.expectMode {
				t.Fatalf("classifyMode()=%q, want %q", got, tc.expectMode)
			}
		})
	}
}

func TestDedupSortedNonEmpty(t *testing.T) {
	in := []string{" /dev/ttyUSB3 ", "/dev/ttyUSB2", "", "/dev/ttyUSB2"}
	got := dedupSortedNonEmpty(in)
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2", len(got))
	}
	if got[0] != "/dev/ttyUSB2" || got[1] != "/dev/ttyUSB3" {
		t.Fatalf("unexpected result: %#v", got)
	}
}

func TestFindCDCWDMInUSBPath_AllowsUSBMiscSymlink(t *testing.T) {
	usbPath := t.TempDir()
	ifacePath := filepath.Join(usbPath, "1-2:1.4")
	if err := os.MkdirAll(ifacePath, 0o755); err != nil {
		t.Fatalf("mkdir interface path: %v", err)
	}

	realUSBMisc := filepath.Join(ifacePath, "usbmisc-real")
	if err := os.MkdirAll(realUSBMisc, 0o755); err != nil {
		t.Fatalf("mkdir real usbmisc path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realUSBMisc, "cdc-wdm7"), []byte{}, 0o644); err != nil {
		t.Fatalf("create cdc-wdm file: %v", err)
	}
	if err := os.Symlink("usbmisc-real", filepath.Join(ifacePath, "usbmisc")); err != nil {
		t.Fatalf("create usbmisc symlink: %v", err)
	}

	got := findCDCWDMInUSBPath(usbPath)
	if got != "/dev/cdc-wdm7" {
		t.Fatalf("findCDCWDMInUSBPath()=%q, want %q", got, "/dev/cdc-wdm7")
	}
}

func TestFindCDCWDMInUSBPath_FollowsUSBPathSymlink(t *testing.T) {
	realUSBPath := t.TempDir()
	ifacePath := filepath.Join(realUSBPath, "1-4:1.4")
	if err := os.MkdirAll(filepath.Join(ifacePath, "usbmisc", "cdc-wdm9"), 0o755); err != nil {
		t.Fatalf("mkdir cdc-wdm tree: %v", err)
	}

	linkParent := t.TempDir()
	linkUSBPath := filepath.Join(linkParent, "1-4")
	if err := os.Symlink(realUSBPath, linkUSBPath); err != nil {
		t.Fatalf("create usb path symlink: %v", err)
	}

	got := findCDCWDMInUSBPath(linkUSBPath)
	if got != "/dev/cdc-wdm9" {
		t.Fatalf("findCDCWDMInUSBPath(symlink-root)=%q, want %q", got, "/dev/cdc-wdm9")
	}
}

func TestFindATPortsInUSBPathCollectsTTYUSBandTTYACM(t *testing.T) {
	usbPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(usbPath, "1-2:1.2", "ttyUSB6"), 0o755); err != nil {
		t.Fatalf("mkdir direct ttyUSB layout: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(usbPath, "1-2:1.3", "tty", "ttyUSB7"), 0o755); err != nil {
		t.Fatalf("mkdir nested ttyUSB layout: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(usbPath, "1-2:1.4", "ttyACM0"), 0o755); err != nil {
		t.Fatalf("mkdir direct ttyACM layout: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(usbPath, "1-2:1.5", "tty", "ttyACM1"), 0o755); err != nil {
		t.Fatalf("mkdir nested ttyACM layout: %v", err)
	}

	got := findATPortsInUSBPath(usbPath)
	want := []string{"/dev/ttyUSB6", "/dev/ttyUSB7", "/dev/ttyACM0", "/dev/ttyACM1"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want=%d got=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q want=%q all=%v", i, got[i], want[i], got)
		}
	}
}
