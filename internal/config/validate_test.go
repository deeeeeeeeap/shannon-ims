package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func findIssue(issues []Issue, path string) (Issue, bool) {
	for _, issue := range issues {
		if issue.Path == path {
			return issue, true
		}
	}
	return Issue{}, false
}

func issuePaths(issues []Issue) []string {
	paths := make([]string, 0, len(issues))
	for _, issue := range issues {
		paths = append(paths, issue.Path)
	}
	return paths
}

func TestValidateAcceptsShippedExampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config", "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load(example) error = %v", err)
	}
	if issues := Validate(cfg); len(issues) != 0 {
		t.Fatalf("the shipped example must validate cleanly, got %v", issues)
	}
}

func TestValidateNilAndEmptyConfig(t *testing.T) {
	if issues := Validate(nil); issues != nil {
		t.Fatalf("Validate(nil) = %v, want nil", issues)
	}
	if issues := Validate(&Config{}); len(issues) != 0 {
		t.Fatalf("Validate(empty) = %v, want no findings", issues)
	}
}

func TestValidateServerPort(t *testing.T) {
	cases := []struct {
		port    string
		wantErr bool
	}{
		{":7575", false},
		{"127.0.0.1:7575", false},
		{"[::1]:7575", false},
		{":0", false},
		{":65535", false},
		{":65536", true},
		{":-1", true},
		{":http", true},
		{"7575:", true},
		{"a:b:c", true},
	}
	for _, tc := range cases {
		issues := Validate(&Config{Server: ServerConfig{Port: tc.port}})
		issue, found := findIssue(issues, "server.port")
		if found != tc.wantErr {
			t.Errorf("port %q: finding=%v, want %v (%v)", tc.port, found, tc.wantErr, issues)
			continue
		}
		if found && issue.Severity != SeverityError {
			t.Errorf("port %q: severity = %s, want error because the API cannot listen", tc.port, issue.Severity)
		}
	}
}

func TestValidateDeviceFindingsAreWarnings(t *testing.T) {
	cfg := &Config{Devices: []DeviceConfig{
		{ID: "dev1", ModemIMEI: "860000000000011", DeviceBackend: "qmi"},
		{ID: "dev1", ModemIMEI: "860000000000011", DeviceBackend: "qmii", MBIMTransport: "usb", ESIMTransport: "spi"},
		{ID: " ", ModemIMEI: "12345", ProxyPort: 70000},
		{
			ID: "dev4", BaudRate: -1, DataBits: 9, StopBits: 3, Parity: "X",
			OperatorSelectionMode: "manual",
			ESIMSwitch:            ESIMSwitchConfig{ReinitWindowMS: 500},
		},
		{ID: "dev5", OperatorSelectionMode: "roaming", OperatorSelectionPLMN: "46A01", ESIMSwitch: ESIMSwitchConfig{ReinitWindowMS: -1, NASAttachTimeoutMS: -1}},
	}}
	issues := Validate(cfg)

	want := []string{
		"devices[1].id",
		"devices[1].modem_imei",
		"devices[1].device_backend",
		"devices[1].mbim_transport",
		"devices[1].esim_transport",
		"devices[2].id",
		"devices[2].modem_imei",
		"devices[2].proxy_port",
		"devices[3].baud_rate",
		"devices[3].data_bits",
		"devices[3].stop_bits",
		"devices[3].parity",
		"devices[3].operator_selection_plmn",
		"devices[3].esim_switch.reinit_window_ms",
		"devices[4].operator_selection_mode",
		"devices[4].operator_selection_plmn",
		"devices[4].esim_switch.reinit_window_ms",
		"devices[4].esim_switch.nas_attach_timeout_ms",
	}
	for _, path := range want {
		issue, ok := findIssue(issues, path)
		if !ok {
			t.Errorf("missing finding for %s; got %v", path, issuePaths(issues))
			continue
		}
		if issue.Severity != SeverityWarning {
			t.Errorf("%s severity = %s, want warning so existing deployments still start", path, issue.Severity)
		}
	}
	if HasErrors(issues) {
		t.Fatalf("device findings must not block startup: %v", issues)
	}
	if _, ok := findIssue(issues, "devices[0].device_backend"); ok {
		t.Fatalf("valid device reported: %v", issues)
	}
}

func TestValidateAcceptsEveryDocumentedDeviceValue(t *testing.T) {
	cfg := &Config{Devices: []DeviceConfig{
		{ID: "a", DeviceBackend: "AT", MBIMTransport: "Direct", ESIMTransport: "QMI", BaudRate: 9600, DataBits: 7, StopBits: 2, Parity: "e"},
		{ID: "b", DeviceBackend: " mbim ", MBIMTransport: "proxy", OperatorSelectionMode: "Manual", OperatorSelectionPLMN: "310260", OperatorSelectionRAT: "lte"},
		{ID: "c", OperatorSelectionMode: "automatic", ESIMSwitch: ESIMSwitchConfig{EventGatedConverge: true, ReinitWindowMS: 3000}},
	}}
	if issues := Validate(cfg); len(issues) != 0 {
		t.Fatalf("documented values rejected: %v", issues)
	}
}

func TestValidateProxyInstances(t *testing.T) {
	cfg := &Config{
		Devices: []DeviceConfig{{ID: "dev1"}},
		Proxy: ProxyConfig{Instances: []ProxyInstance{
			{ID: "p1", Enabled: true, Mode: "socks5", ListenAddr: "0.0.0.0", ListenPort: 1080, DeviceID: "dev1"},
			{ID: "p1", Enabled: true, Mode: "quic", ListenAddr: "127.0.0.1", ListenPort: 1080},
			{ID: "p3", Enabled: true, Mode: "http", ListenAddr: "localhost", ListenPort: 0, AuthEnabled: true, Username: "user", DeviceID: "gone"},
			{ID: "p4", Enabled: false, ListenPort: 1080, Mode: "http"},
			{ID: "p5", Enabled: true, Mode: "http", ListenAddr: "127.0.0.2", ListenPort: 8080},
			{ID: "p6", Enabled: true, Mode: "http", ListenAddr: "127.0.0.3", ListenPort: 8080},
		}},
	}
	issues := Validate(cfg)

	for _, path := range []string{
		"proxy.instances[1].id",
		"proxy.instances[1].mode",
		"proxy.instances[1].listen_port",
		"proxy.instances[2].listen_port",
		"proxy.instances[2].listen_addr",
		"proxy.instances[2].auth_enabled",
		"proxy.instances[2].device_id",
	} {
		if _, ok := findIssue(issues, path); !ok {
			t.Errorf("missing finding for %s; got %v", path, issuePaths(issues))
		}
	}
	for _, issue := range issues {
		for _, clean := range []string{"proxy.instances[0]", "proxy.instances[3]", "proxy.instances[4]", "proxy.instances[5]"} {
			if strings.HasPrefix(issue.Path, clean) {
				t.Errorf("unexpected finding %v", issue)
			}
		}
	}
}

func TestValidateNotificationChannels(t *testing.T) {
	cfg := &Config{
		Telegram: TelegramConfig{Enabled: true, Proxy: "127.0.0.1:7890"},
		Feishu:   FeishuConfig{Enabled: true, AppID: "cli_x"},
		QQ:       QQConfig{Enabled: true},
		Webhook:  WebhookConfig{Enabled: true, TimeoutMs: -1, RetryMax: -1},
		Bark:     BarkConfig{Enabled: true, URLs: []string{"ftp://bark.example.test/key"}},
		Email:    EmailConfig{Enabled: true, SMTPHost: "smtp.example.test"},
		Pushplus: PushplusConfig{Enabled: true},
	}
	issues := Validate(cfg)
	for _, path := range []string{
		"telegram", "telegram.proxy", "feishu", "qq",
		"webhook.urls", "webhook.timeout_ms", "webhook.retry_max",
		"bark.urls[0]", "email", "email.smtp_port", "pushplus.token",
	} {
		if _, ok := findIssue(issues, path); !ok {
			t.Errorf("missing finding for %s; got %v", path, issuePaths(issues))
		}
	}

	disabled := &Config{Webhook: WebhookConfig{TimeoutMs: 5000, RetryMax: 3}}
	if issues := Validate(disabled); len(issues) != 0 {
		t.Fatalf("disabled channels must not be reported: %v", issues)
	}
}

// Findings are shown in logs and in the diagnostics API, so they must describe
// the problem without repeating the secret that was configured.
func TestValidateMessagesNeverEchoCredentials(t *testing.T) {
	const secret = "s3cr3t-value-that-must-not-leak"
	cfg := &Config{
		Telegram: TelegramConfig{Enabled: true, BotToken: secret},
		Feishu:   FeishuConfig{Enabled: true, AppSecret: secret},
		QQ:       QQConfig{Enabled: true, AppSecret: secret},
		Webhook:  WebhookConfig{Enabled: true, Secret: secret, URLs: []string{"not a url " + secret}},
		Email:    EmailConfig{Enabled: true, Password: secret},
		Pushplus: PushplusConfig{Enabled: true},
		Proxy: ProxyConfig{Instances: []ProxyInstance{
			{ID: "p", Enabled: true, AuthEnabled: true, Password: secret, ListenPort: 99999},
		}},
	}
	cfg.VoWiFi.VoiceGateway.SIP.Listen = "bad"
	cfg.VoWiFi.VoiceGateway.Users = []VoWiFiVoiceUserConfig{{Username: "", Password: secret}}

	issues := Validate(cfg)
	if len(issues) == 0 {
		t.Fatal("expected findings")
	}
	for _, issue := range issues {
		if strings.Contains(issue.String(), secret) {
			t.Fatalf("finding leaks a credential: %s", issue.Path)
		}
	}
}

func TestValidateVoiceGateway(t *testing.T) {
	cfg := &Config{}
	gw := &cfg.VoWiFi.VoiceGateway
	gw.SIP.Listen = "0.0.0.0"
	gw.SIP.Transport = "sctp"
	gw.SIP.ExternalIP = "not-an-ip"
	gw.Media.RTPPortMin = 20000
	gw.Media.RTPPortMax = 10000
	gw.Users = []VoWiFiVoiceUserConfig{
		{Username: "alice", Password: "pw"},
		{Username: "alice", Password: "pw"},
		{Username: "bob"},
		{Password: "pw"},
	}
	issues := Validate(cfg)
	for _, path := range []string{
		"vowifi.voice_gateway.sip.listen",
		"vowifi.voice_gateway.sip.transport",
		"vowifi.voice_gateway.sip.external_ip",
		"vowifi.voice_gateway.media",
		"vowifi.voice_gateway.users[1].username",
		"vowifi.voice_gateway.users[2].password",
		"vowifi.voice_gateway.users[3].username",
	} {
		if _, ok := findIssue(issues, path); !ok {
			t.Errorf("missing finding for %s; got %v", path, issuePaths(issues))
		}
	}

	off := &Config{}
	off.VoWiFi.VoiceGateway.SIP.Transport = "sctp"
	if issues := Validate(off); len(issues) != 0 {
		t.Fatalf("gateway without sip.listen is disabled and must not be reported: %v", issues)
	}
}

func TestSerialSettingsDefaultsAndOverrides(t *testing.T) {
	def := DeviceConfig{}.SerialSettings()
	if def != (SerialSettings{BaudRate: 115200, DataBits: 8, StopBits: 1, Parity: "N"}) {
		t.Fatalf("defaults = %+v, want 115200 8N1", def)
	}

	custom := DeviceConfig{BaudRate: 9600, DataBits: 7, StopBits: 2, Parity: " e "}.SerialSettings()
	if custom != (SerialSettings{BaudRate: 9600, DataBits: 7, StopBits: 2, Parity: "E"}) {
		t.Fatalf("custom = %+v", custom)
	}

	invalid := DeviceConfig{BaudRate: -5, DataBits: 12, StopBits: 9, Parity: "mark"}.SerialSettings()
	if invalid != def {
		t.Fatalf("unsupported values must fall back to defaults, got %+v", invalid)
	}
}

func TestValidateDeviceBackendAndMBIMTransport(t *testing.T) {
	for _, ok := range []string{"", "at", "QMI", " mbim "} {
		if err := ValidateDeviceBackend(ok); err != nil {
			t.Errorf("ValidateDeviceBackend(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"auto", "qmii", "serial"} {
		if err := ValidateDeviceBackend(bad); err == nil {
			t.Errorf("ValidateDeviceBackend(%q) = nil, want error", bad)
		}
	}
	for _, ok := range []string{"", "auto", "Proxy", "direct"} {
		if err := ValidateMBIMTransport(ok); err != nil {
			t.Errorf("ValidateMBIMTransport(%q) = %v, want nil", ok, err)
		}
	}
	if err := ValidateMBIMTransport("usb"); err == nil {
		t.Error("ValidateMBIMTransport(usb) = nil, want error")
	}
}

func TestLoadForStartupRejectsUnusableServerPort(t *testing.T) {
	path := writeTempConfig(t, "server:\n  port: 70000\nweb:\n  username: admin\n  password: initialised-secret\n")
	_, err := LoadForStartup(path)
	if err == nil || !strings.Contains(err.Error(), "server.port") {
		t.Fatalf("LoadForStartup() error = %v, want a server.port failure", err)
	}
}

func TestLoadForStartupToleratesWarnings(t *testing.T) {
	path := writeTempConfig(t, "web:\n  username: admin\n  password: initialised-secret\ndevices:\n- id: dev1\n  device_backend: qmii\n")
	cfg, err := LoadForStartup(path)
	if err != nil {
		t.Fatalf("LoadForStartup() error = %v; warnings must not block startup", err)
	}
	if len(cfg.Devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(cfg.Devices))
	}
}

func TestValidationIssuesFollowTheLoadedConfig(t *testing.T) {
	t.Cleanup(func() {
		configMu.Lock()
		globalConfig, globalIssues, configPath, secureWeb = nil, nil, "", false
		configMu.Unlock()
	})

	path := writeTempConfig(t, "web:\n  username: admin\n  password: initialised-secret\ndevices:\n- id: dev1\n  device_backend: qmii\n")
	if err := InitGlobalManagerForStartup(path); err != nil {
		t.Fatalf("InitGlobalManagerForStartup() error = %v", err)
	}
	issues := ValidationIssues()
	if _, ok := findIssue(issues, "devices[0].device_backend"); !ok {
		t.Fatalf("startup findings not recorded: %v", issues)
	}

	// The accessor hands out a copy.
	issues[0].Path = "mutated"
	if again := ValidationIssues(); again[0].Path == "mutated" {
		t.Fatal("ValidationIssues() exposes internal state")
	}

	if err := UpdateDeviceInFile(path, "dev1", DeviceConfig{ID: "dev1", DeviceBackend: "qmi"}); err != nil {
		t.Fatalf("UpdateDeviceInFile() error = %v", err)
	}
	if issues := ValidationIssues(); len(issues) != 0 {
		t.Fatalf("findings not refreshed after the config was fixed: %v", issues)
	}
}
