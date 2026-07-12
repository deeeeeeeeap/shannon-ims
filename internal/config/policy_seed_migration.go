package config

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// LegacyDevicePolicy 是从旧 config.yaml 读出的 per-device 策略快照。
type LegacyDevicePolicy struct {
	ICCID          string
	NetworkEnabled bool
	VoWiFiEnabled  bool
	IPVersion      string
	APN            string
}

// SeedLegacyDevicePolicies 把带 ICCID 的旧策略逐条 upsert 到 card_policies。
// upsert 由调用方注入（cmd/vohive 传 db 适配器），无 ICCID 的条目跳过。返回种子条数。
func SeedLegacyDevicePolicies(items []LegacyDevicePolicy, upsert func(iccid string, p LegacyDevicePolicy) error) (int, error) {
	n := 0
	for _, it := range items {
		iccid := strings.TrimSpace(it.ICCID)
		if iccid == "" {
			continue
		}
		if err := upsert(iccid, it); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// ReadLegacyDevicePoliciesFromYAML 直接从原始 yaml 读取旧 per-device 策略字段
// （绕过 DeviceConfig 的 mapstructure:"-"），并用 iccidFor 把 device id 映射到 ICCID。
func ReadLegacyDevicePoliciesFromYAML(path string, iccidFor func(deviceID string) string) ([]LegacyDevicePolicy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root struct {
		Devices []struct {
			ID             string `yaml:"id"`
			NetworkEnabled bool   `yaml:"network_enabled"`
			VoWiFiEnabled  bool   `yaml:"vowifi_enabled"`
			IPVersion      string `yaml:"ip_version"`
			APN            string `yaml:"apn"`
		} `yaml:"devices"`
	}
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	var out []LegacyDevicePolicy
	for _, d := range root.Devices {
		out = append(out, LegacyDevicePolicy{
			ICCID:          iccidFor(d.ID),
			NetworkEnabled: d.NetworkEnabled,
			VoWiFiEnabled:  d.VoWiFiEnabled,
			IPVersion:      d.IPVersion,
			APN:            d.APN,
		})
	}
	return out, nil
}
