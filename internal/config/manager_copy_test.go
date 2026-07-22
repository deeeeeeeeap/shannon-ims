package config

import "testing"

func TestConfigAccessorsReturnDeepCopies(t *testing.T) {
	usbNetMode := 7
	original := &Config{
		Devices: []DeviceConfig{{ID: "device-a", USBNetMode: &usbNetMode}},
		Proxy:   ProxyConfig{Instances: []ProxyInstance{{ID: "proxy-a"}}},
		Feishu:  FeishuConfig{ChatIDs: []string{"chat-a"}},
		Webhook: WebhookConfig{
			URLs:    []string{"https://synthetic.invalid/hook"},
			Headers: map[string]string{"X-Synthetic": "value-a"},
		},
		Bark:  BarkConfig{URLs: []string{"https://synthetic.invalid/bark"}},
		Email: EmailConfig{ToAddresses: []string{"synthetic@example.invalid"}},
	}
	original.VoWiFi.VoiceGateway.Users = []VoWiFiVoiceUserConfig{{Username: "voice-a"}}
	original.VoWiFi.VoiceGateway.Media.Codecs = []string{"codec-a"}

	configMu.Lock()
	previous := globalConfig
	globalConfig = original
	configMu.Unlock()
	t.Cleanup(func() {
		configMu.Lock()
		globalConfig = previous
		configMu.Unlock()
	})

	fromConfig := GetConfig()
	fromConfig.Devices[0].ID = "mutated-config-device"
	*fromConfig.Devices[0].USBNetMode = 9
	fromConfig.Proxy.Instances[0].ID = "mutated-proxy"
	fromConfig.Feishu.ChatIDs[0] = "mutated-chat"
	fromConfig.Webhook.URLs[0] = "https://mutated.invalid/hook"
	fromConfig.Webhook.Headers["X-Synthetic"] = "mutated-header"
	fromConfig.Bark.URLs[0] = "https://mutated.invalid/bark"
	fromConfig.Email.ToAddresses[0] = "mutated@example.invalid"
	fromConfig.VoWiFi.VoiceGateway.Users[0].Username = "mutated-voice"
	fromConfig.VoWiFi.VoiceGateway.Media.Codecs[0] = "mutated-codec"

	devices := ListDevices()
	devices[0].ID = "mutated-list-device"
	device, err := GetDeviceByID("device-a")
	if err != nil {
		t.Fatalf("GetDeviceByID() error=%v", err)
	}
	if device == nil {
		t.Fatal("GetDeviceByID() returned nil")
	}
	device.ID = "mutated-returned-device"
	*device.USBNetMode = 11

	got := GetConfig()
	if got.Devices[0].ID != "device-a" || got.Devices[0].USBNetMode == nil || *got.Devices[0].USBNetMode != 7 {
		t.Fatalf("device snapshot was mutated: %+v", got.Devices[0])
	}
	if got.Proxy.Instances[0].ID != "proxy-a" {
		t.Fatalf("proxy snapshot was mutated: %+v", got.Proxy.Instances[0])
	}
	if got.Feishu.ChatIDs[0] != "chat-a" || got.Webhook.URLs[0] != "https://synthetic.invalid/hook" || got.Webhook.Headers["X-Synthetic"] != "value-a" {
		t.Fatal("notification slice or map snapshot was mutated")
	}
	if got.Bark.URLs[0] != "https://synthetic.invalid/bark" || got.Email.ToAddresses[0] != "synthetic@example.invalid" {
		t.Fatal("notification address snapshot was mutated")
	}
	if got.VoWiFi.VoiceGateway.Users[0].Username != "voice-a" || got.VoWiFi.VoiceGateway.Media.Codecs[0] != "codec-a" {
		t.Fatal("VoWiFi voice gateway snapshot was mutated")
	}
}
