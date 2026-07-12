package carrier

import "testing"

func TestDefaultUTRANCellIDSuffixGiffgaffBuiltin(t *testing.T) {
	got := DefaultUTRANCellIDSuffix("234", "10")
	want := "70010BC614E"
	if got != want {
		t.Fatalf("DefaultUTRANCellIDSuffix(234,10) = %q, want %q", got, want)
	}
}

func TestIMSCellIDModeNormalization(t *testing.T) {
	t.Cleanup(ClearCarrierOverrides)
	mu.Lock()
	presets = map[string]Preset{
		"234-10": {MCC: "234", MNC: "10", IMSCellIDMode: "carrier_only"},
	}
	mu.Unlock()

	if got := IMSCellIDMode("234", "10"); got != "carrier_only" {
		t.Fatalf("IMSCellIDMode() = %q, want carrier_only", got)
	}
	if got := IMSCellIDMode("234", "33"); got != "qmi_first" {
		t.Fatalf("IMSCellIDMode() = %q, want qmi_first", got)
	}
}

func TestDefaultUTRANCellIDSuffixFromOverrides(t *testing.T) {
	t.Cleanup(ClearCarrierOverrides)
	mu.Lock()
	presets = map[string]Preset{
		"234-10": {MCC: "234", MNC: "10", IMSTAC: 12345, IMSCellID: 12345678},
	}
	mu.Unlock()

	got := DefaultUTRANCellIDSuffix("234", "010")
	want := "30390BC614E"
	if got != want {
		t.Fatalf("DefaultUTRANCellIDSuffix() = %q, want %q", got, want)
	}
}