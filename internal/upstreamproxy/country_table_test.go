package upstreamproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const countryFixture = `[
  {"mcc":"310","mnc":"260","iso":"us","country":"United States","country_code":"US","network":"T-Mobile"},
  {"mcc":"311","mnc":"480","iso":"us","country":"United States","country_code":"US","network":"Verizon"},
  {"mcc":"312","mnc":"530","iso":"us","country":"United States","country_code":"US","network":"Sprint"},
  {"mcc":"313","mnc":"100","iso":"us","country":"United States","country_code":"US","network":"FirstNet"},
  {"mcc":"314","mnc":"100","iso":"us","country":"United States","country_code":"US","network":"Reserved"},
  {"mcc":"315","mnc":"010","iso":"us","country":"United States","country_code":"US","network":"CBRS"},
  {"mcc":"316","mnc":"010","iso":"us","country":"United States","country_code":"US","network":"Nextel"},
  {"mcc":"262","mnc":"01","iso":"de","country":"Germany","country_code":"DE","network":"Telekom"}
]`

func TestDefaultCountryTableCachePathUsesLocalDataDirectory(t *testing.T) {
	if filepath.IsAbs(DefaultCountryTableCachePath) {
		t.Fatalf("DefaultCountryTableCachePath=%q, want relative data directory path", DefaultCountryTableCachePath)
	}
	if DefaultCountryTableCachePath != filepath.Join("data", "mcc-mnc-table.json") {
		t.Fatalf("DefaultCountryTableCachePath=%q, want data/mcc-mnc-table.json", DefaultCountryTableCachePath)
	}
}

func writeCountryFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error=%v", err)
	}
	if err := os.WriteFile(path, []byte(countryFixture), 0o644); err != nil {
		t.Fatalf("WriteFile() error=%v", err)
	}
}

func TestInitCountryTableLoadsCacheWithoutNetwork(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "data", "mcc-mnc-table.json")
	writeCountryFixture(t, cachePath)
	hitNetwork := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitNetwork = true
		t.Fatalf("unexpected network request")
	}))
	defer srv.Close()

	result := InitCountryTable(context.Background(), CountryTableOptions{
		CachePath: cachePath,
		SourceURL: srv.URL,
	})
	if result.Err != nil || result.Source != "cache" || result.RowCount != 8 || hitNetwork {
		t.Fatalf("InitCountryTable()=%+v hitNetwork=%v, want cache rows without network", result, hitNetwork)
	}
	if !CountryTableReady() {
		t.Fatalf("CountryTableReady()=false, want true")
	}
}

func TestInitCountryTableDownloadsAndWritesCacheWhenMissing(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "data", "mcc-mnc-table.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(countryFixture))
	}))
	defer srv.Close()

	result := InitCountryTable(context.Background(), CountryTableOptions{
		CachePath: cachePath,
		SourceURL: srv.URL,
	})
	if result.Err != nil || result.Source != "download" || result.RowCount != 8 {
		t.Fatalf("InitCountryTable()=%+v, want download rows", result)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("download did not write cache %s: %v", cachePath, err)
	}
	got, ok := CountryCodeFromHomeMCC("310")
	if !ok || got != "US" {
		t.Fatalf("CountryCodeFromHomeMCC(310)=(%q,%v), want US,true", got, ok)
	}
}

func TestInitCountryTableFallsBackAcrossSourceURLs(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "data", "mcc-mnc-table.json")
	primaryHits := 0
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits++
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer primary.Close()
	fallbackHits := 0
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(countryFixture))
	}))
	defer fallback.Close()

	result := InitCountryTable(context.Background(), CountryTableOptions{
		CachePath:  cachePath,
		SourceURLs: []string{primary.URL, fallback.URL},
	})
	if result.Err != nil || result.Source != "download" || result.SourceURL != fallback.URL || result.RowCount != 8 {
		t.Fatalf("InitCountryTable()=%+v, want fallback download from second URL", result)
	}
	if primaryHits != 1 || fallbackHits != 1 {
		t.Fatalf("hits primary=%d fallback=%d, want 1/1", primaryHits, fallbackHits)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("fallback download did not write cache %s: %v", cachePath, err)
	}
}

func TestInitCountryTableEmptyWhenCacheAndDownloadUnavailable(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "data", "mcc-mnc-table.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusBadGateway)
	}))
	defer srv.Close()

	result := InitCountryTable(context.Background(), CountryTableOptions{
		CachePath: cachePath,
		SourceURL: srv.URL,
	})
	if result.Err == nil || result.Source != "empty" || CountryTableReady() {
		t.Fatalf("InitCountryTable()=%+v ready=%v, want empty with error", result, CountryTableReady())
	}
	got, ok := CountryCodeFromHomeMCC("310")
	if ok || got != "" {
		t.Fatalf("CountryCodeFromHomeMCC unavailable=(%q,%v), want empty,false", got, ok)
	}
}

func TestCountryCodeFromHomeMCCUSRangeFromLoadedTable(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "mcc-mnc-table.json")
	writeCountryFixture(t, cachePath)
	result := InitCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath, SourceURL: "http://127.0.0.1:1/missing"})
	if result.Err != nil {
		t.Fatalf("InitCountryTable() error=%v", result.Err)
	}
	for _, mcc := range []string{"310", "311", "312", "313", "314", "315", "316"} {
		got, ok := CountryCodeFromHomeMCC(mcc)
		if !ok || got != "US" {
			t.Fatalf("CountryCodeFromHomeMCC(%q)=(%q,%v), want US,true", mcc, got, ok)
		}
	}
}

func TestCountryTableUsesISOCodeWhenSourceCountryCodeIsDialingPrefix(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "mcc-mnc-table.json")
	rows := `[
  {"mcc":"302","mnc":"720","iso":"ca","country":"Canada","country_code":"1","network":"Rogers"},
  {"mcc":"310","mnc":"260","iso":"us","country":"United States of America","country_code":"1","network":"T-Mobile"},
  {"mcc":"311","mnc":"480","iso":"us","country":"United States of America","country_code":"1","network":"Verizon"}
]`
	if err := os.WriteFile(cachePath, []byte(rows), 0o644); err != nil {
		t.Fatalf("WriteFile() error=%v", err)
	}
	result := InitCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath})
	if result.Err != nil {
		t.Fatalf("InitCountryTable() error=%v", result.Err)
	}

	got, ok := CountryCodeFromHomeMCC("310")
	if !ok || got != "US" {
		t.Fatalf("CountryCodeFromHomeMCC(310)=(%q,%v), want US,true", got, ok)
	}
	got, ok = CountryCodeFromHomeMCC("302")
	if !ok || got != "CA" {
		t.Fatalf("CountryCodeFromHomeMCC(302)=(%q,%v), want CA,true", got, ok)
	}
	us := CountryRuleDisplay("US")
	if !reflect.DeepEqual(us.MCCs, []string{"310", "311"}) {
		t.Fatalf("CountryRuleDisplay(US).MCCs=%v, want 310/311", us.MCCs)
	}
	ca := CountryRuleDisplay("CA")
	if !reflect.DeepEqual(ca.MCCs, []string{"302"}) {
		t.Fatalf("CountryRuleDisplay(CA).MCCs=%v, want 302", ca.MCCs)
	}
}

func TestCountryCodeFromHomeMCCNormalizesWhitespace(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "mcc-mnc-table.json")
	writeCountryFixture(t, cachePath)
	InitCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath})
	got, ok := CountryCodeFromHomeMCC(" 310 ")
	if !ok || got != "US" {
		t.Fatalf("CountryCodeFromHomeMCC()=(%q,%v), want US,true", got, ok)
	}
}

func TestCountryCodeFromHomeMCCUnknownRoutesDirect(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "mcc-mnc-table.json")
	writeCountryFixture(t, cachePath)
	InitCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath})
	got, ok := CountryCodeFromHomeMCC("404")
	if ok || got != "" {
		t.Fatalf("CountryCodeFromHomeMCC(404)=(%q,%v), want empty,false", got, ok)
	}
}

func TestMCCsForCountryCodeUS(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "mcc-mnc-table.json")
	writeCountryFixture(t, cachePath)
	InitCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath})
	got, ok := MCCsForCountryCode(" us ")
	want := []string{"310", "311", "312", "313", "314", "315", "316"}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("MCCsForCountryCode(US)=(%v,%v), want %v,true", got, ok, want)
	}
	got[0] = "999"
	got2, _ := MCCsForCountryCode("US")
	if got2[0] != "310" {
		t.Fatalf("MCCsForCountryCode returned mutable backing slice: %v", got2)
	}
}

func TestCountryRuleDisplayKnownAndUnknown(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "mcc-mnc-table.json")
	writeCountryFixture(t, cachePath)
	InitCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath})
	known := CountryRuleDisplay("us")
	if known.CountryCode != "US" || known.CountryName != "United States" || len(known.MCCs) != 7 {
		t.Fatalf("CountryRuleDisplay(US)=%+v", known)
	}
	unknown := CountryRuleDisplay("zz")
	if unknown.CountryCode != "ZZ" || unknown.CountryName != "ZZ" || len(unknown.MCCs) != 0 {
		t.Fatalf("CountryRuleDisplay(ZZ)=%+v", unknown)
	}
}

func TestListCountryDisplaysSorted(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "mcc-mnc-table.json")
	writeCountryFixture(t, cachePath)
	InitCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath})
	got := ListCountryDisplays()
	if len(got) != 2 || got[0].CountryCode != "DE" || got[1].CountryCode != "US" {
		t.Fatalf("ListCountryDisplays()=%+v, want DE then US", got)
	}
}
