package config

import (
	"os"
	"strings"
	"testing"
)

// The settings page has an SSL switch for SMTP. It used to be applied to the
// running process but never written to disk, so implicit-TLS mail silently
// stopped working after the next restart.
func TestUpdateNotificationInFilePersistsEmailUseSSL(t *testing.T) {
	path := writeTempConfig(t, "email:\n  enabled: false\n")
	email := EmailConfig{
		Enabled:     true,
		UseSSL:      true,
		SMTPHost:    "smtp.example.test",
		SMTPPort:    465,
		FromAddress: "alerts@example.test",
		ToAddresses: []string{"ops@example.test"},
	}
	if err := UpdateNotificationInFile(path, TelegramConfig{}, FeishuConfig{}, QQConfig{}, WebhookConfig{}, BarkConfig{}, email, PushplusConfig{}); err != nil {
		t.Fatalf("UpdateNotificationInFile() error = %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Email.UseSSL {
		t.Fatal("email.use_ssl was not persisted")
	}
	if cfg.Email.SMTPPort != 465 || cfg.Email.SMTPHost != "smtp.example.test" {
		t.Fatalf("email section corrupted: %+v", cfg.Email)
	}

	email.UseSSL = false
	if err := UpdateNotificationInFile(path, TelegramConfig{}, FeishuConfig{}, QQConfig{}, WebhookConfig{}, BarkConfig{}, email, PushplusConfig{}); err != nil {
		t.Fatalf("UpdateNotificationInFile() error = %v", err)
	}
	cfg, _ = Load(path)
	if cfg.Email.UseSSL {
		t.Fatal("email.use_ssl could not be switched off again")
	}
}

// A manual operator selection is re-applied from the config file at startup.
// The API handler asked for it to be persisted, but the writer dropped it.
func TestUpdateDeviceInFilePersistsOperatorSelection(t *testing.T) {
	path := writeTempConfig(t, "devices:\n- id: dev1\n  device_backend: qmi\n  esim_switch:\n    radio_cycle: true\n")

	manual := DeviceConfig{
		ID:                    "dev1",
		DeviceBackend:         "qmi",
		OperatorSelectionMode: "manual",
		OperatorSelectionPLMN: "310260",
		OperatorSelectionRAT:  "lte",
	}
	if err := UpdateDeviceInFile(path, "dev1", manual); err != nil {
		t.Fatalf("UpdateDeviceInFile(manual) error = %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	d := cfg.Devices[0]
	if d.OperatorSelectionMode != "manual" || d.OperatorSelectionPLMN != "310260" || d.OperatorSelectionRAT != "lte" {
		t.Fatalf("manual operator selection not persisted: %+v", d)
	}
	if !d.ESIMSwitch.RadioCycle {
		t.Fatal("unrelated device keys must survive the update")
	}

	// Without a RAT the stale key must go away, not linger from the last choice.
	manual.OperatorSelectionRAT = ""
	if err := UpdateDeviceInFile(path, "dev1", manual); err != nil {
		t.Fatalf("UpdateDeviceInFile(manual without rat) error = %v", err)
	}
	cfg, _ = Load(path)
	if got := cfg.Devices[0].OperatorSelectionRAT; got != "" {
		t.Fatalf("stale operator_selection_rat kept: %q", got)
	}

	automatic := DeviceConfig{ID: "dev1", DeviceBackend: "qmi", OperatorSelectionMode: "automatic", OperatorSelectionPLMN: "310260"}
	if err := UpdateDeviceInFile(path, "dev1", automatic); err != nil {
		t.Fatalf("UpdateDeviceInFile(automatic) error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(raw), "operator_selection") {
		t.Fatalf("automatic selection must clear the persisted manual choice:\n%s", raw)
	}
}

func TestAddDeviceInFilePersistsManualOperatorSelection(t *testing.T) {
	path := writeTempConfig(t, "devices: []\n")
	dev := DeviceConfig{ID: "dev9", DeviceBackend: "mbim", OperatorSelectionMode: "manual", OperatorSelectionPLMN: "23415"}
	if err := AddDeviceInFile(path, dev); err != nil {
		t.Fatalf("AddDeviceInFile() error = %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if d := cfg.Devices[0]; d.OperatorSelectionMode != "manual" || d.OperatorSelectionPLMN != "23415" {
		t.Fatalf("operator selection not persisted on add: %+v", d)
	}
}

// `proxy:` with no value parses as a null scalar. The writer must replace it
// with a mapping instead of silently discarding the new instance.
func TestAddProxyInstanceInFileHandlesNullProxySection(t *testing.T) {
	path := writeTempConfig(t, "proxy:\ndevices: []\n")
	inst := ProxyInstance{ID: "p1", Mode: "socks5", ListenAddr: "127.0.0.1", ListenPort: 1080, Enabled: true}
	if err := AddProxyInstanceInFile(path, inst); err != nil {
		t.Fatalf("AddProxyInstanceInFile() error = %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Proxy.Instances) != 1 || cfg.Proxy.Instances[0].ID != "p1" {
		t.Fatalf("proxy instance lost: %+v", cfg.Proxy.Instances)
	}
}

// Saving notification or Web settings must be visible through the in-memory
// configuration right away, like device and proxy updates already were.
func TestRootSectionWritersRefreshInMemoryConfig(t *testing.T) {
	t.Cleanup(func() {
		configMu.Lock()
		globalConfig, globalIssues, configPath, secureWeb = nil, nil, "", false
		configMu.Unlock()
	})

	path := writeTempConfig(t, "web:\n  username: admin\n  password: initialised-secret\n")
	if err := InitGlobalManager(path); err != nil {
		t.Fatalf("InitGlobalManager() error = %v", err)
	}

	pushplus := PushplusConfig{Enabled: true, Token: "token-for-test"}
	if err := UpdateNotificationInFile(path, TelegramConfig{}, FeishuConfig{}, QQConfig{}, WebhookConfig{}, BarkConfig{}, EmailConfig{}, pushplus); err != nil {
		t.Fatalf("UpdateNotificationInFile() error = %v", err)
	}
	if got := GetConfig().Pushplus; !got.Enabled || got.Token != "token-for-test" {
		t.Fatalf("in-memory notification config is stale: %+v", got)
	}

	if err := UpdateWebCredentialsInFile(path, "operator", "hashed-credential"); err != nil {
		t.Fatalf("UpdateWebCredentialsInFile() error = %v", err)
	}
	if got := GetConfig().Web.Username; got != "operator" {
		t.Fatalf("in-memory web config is stale: username=%q", got)
	}
}
