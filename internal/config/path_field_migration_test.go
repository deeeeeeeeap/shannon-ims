package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 旧文件/手改 YAML 里仍写了运行时路径键时,Load() 绝不能把它们读进内存。
// 仅保留身份与意图字段。
func TestLoadIgnoresLegacyRuntimePathFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := "" +
		"devices:\n" +
		"- id: wwan0\n" +
		"  name: 主卡\n" +
		"  modem_imei: \"863212060398051\"\n" +
		"  device_backend: qmi\n" +
		"  vowifi_enabled: true\n" +
		"  usb_path: /sys/bus/usb/devices/1-4\n" +
		"  at_port: /dev/ttyUSB2\n" +
		"  manage_port: /dev/ttyUSB2\n" +
		"  interface: wwan0\n" +
		"  qmi_device: /dev/cdc-wdm0\n" +
		"  control_device: /dev/cdc-wdm0\n" +
		"  audio_device: hw:1,0\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(cfg.Devices))
	}
	d := cfg.Devices[0]
	if d.ID != "wwan0" || d.Name != "主卡" || d.ModemIMEI != "863212060398051" ||
		d.DeviceBackend != "qmi" {
		t.Fatalf("identity/intent fields lost: %+v", d)
	}
	if d.USBPath != "" || d.ATPort != "" || d.ManagePort != "" || d.Interface != "" ||
		d.QMIDevice != "" || d.ControlDevice != "" || d.AudioDevice != "" {
		t.Fatalf("runtime path fields must not be read from file, got: %+v", d)
	}
}

// 迁移应把磁盘上的死路径键物理删除,身份与意图字段保持不变。
func TestMigrateDeprecatedRuntimePathFieldsScrubsDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := "" +
		"devices:\n" +
		"- id: wwan0\n" +
		"  name: 主卡\n" +
		"  modem_imei: \"863212060398051\"\n" +
		"  device_backend: qmi\n" +
		"  at_port: /dev/ttyUSB2\n" +
		"  control_device: /dev/cdc-wdm0\n" +
		"  interface: wwan0\n" +
		"  usb_path: /sys/bus/usb/devices/1-4\n" +
		"  qmi_device: /dev/cdc-wdm0\n" +
		"  manage_port: /dev/ttyUSB2\n" +
		"  audio_device: hw:1,0\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read config: %v", err)
	}
	s := string(out)
	for _, key := range []string{
		"at_port", "control_device", "interface", "usb_path",
		"qmi_device", "manage_port", "audio_device",
	} {
		if strings.Contains(s, key+":") {
			t.Fatalf("deprecated key %q still on disk:\n%s", key, s)
		}
	}
	if !strings.Contains(s, "modem_imei:") || !strings.Contains(s, "device_backend:") {
		t.Fatalf("identity/intent keys were lost:\n%s", s)
	}
}
