package voiceclient

import "testing"

func TestFormatUTRANCellIDSuffix(t *testing.T) {
	got := FormatUTRANCellIDSuffix(0x1A2B, 0x254AF11)
	want := "1A2B254AF11"
	if got != want {
		t.Fatalf("FormatUTRANCellIDSuffix() = %q, want %q", got, want)
	}
}

func TestFormatUTRANCellIDSuffixEmpty(t *testing.T) {
	if got := FormatUTRANCellIDSuffix(0, 0); got != "" {
		t.Fatalf("FormatUTRANCellIDSuffix(0,0) = %q, want empty", got)
	}
}

func TestBuildCellularNetworkInfoWithLiveCellID(t *testing.T) {
	got := buildCellularNetworkInfo("23410", FormatUTRANCellIDSuffix(0x1A2B, 0x254AF11))
	want := "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=234101A2B254AF11;cell-info-age=0"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}