package config

import "testing"

func TestSeedLegacyDevicePolicy(t *testing.T) {
	seen := map[string]LegacyDevicePolicy{}
	upsert := func(iccid string, pol LegacyDevicePolicy) error {
		seen[iccid] = pol
		return nil
	}
	legacy := []LegacyDevicePolicy{
		{ICCID: "8986001", NetworkEnabled: true, VoWiFiEnabled: true, IPVersion: "v4v6", APN: "ims"},
		{ICCID: "", NetworkEnabled: true}, // 无 ICCID → 跳过
	}
	n, err := SeedLegacyDevicePolicies(legacy, upsert)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if n != 1 {
		t.Fatalf("应种子 1 条，得 %d", n)
	}
	got := seen["8986001"]
	if !got.NetworkEnabled || !got.VoWiFiEnabled || got.IPVersion != "v4v6" {
		t.Fatalf("种子内容错: %+v", got)
	}
}
