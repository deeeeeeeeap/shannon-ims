package carrier

import (
	"os"
	"testing"
)

func TestResolveIMSPcscfAddr(t *testing.T) {
	t.Cleanup(ClearCarrierOverrides)
	path := t.TempDir() + "/carrier_overrides.json"
	payload := `[{"mcc":"234","mnc":"10","ims_pcscf_addr":"[2a03:dd00:1f81:3810::4]:5060"}]`
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatalf("write overrides: %v", err)
	}
	if _, err := LoadCarrierOverrides(path); err != nil {
		t.Fatalf("LoadCarrierOverrides() error = %v", err)
	}
	got := ResolveIMSPcscfAddr("234", "10")
	want := "[2a03:dd00:1f81:3810::4]:5060"
	if got != want {
		t.Fatalf("ResolveIMSPcscfAddr() = %q, want %q", got, want)
	}
}