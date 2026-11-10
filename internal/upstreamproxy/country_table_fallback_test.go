package upstreamproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sharedMCCFixture has MCCs used by more than one territory: 234 with three
// United Kingdom networks and one each for Jersey, Guernsey and the Isle of
// Man, and 310 with two United States networks and one for Guam.
var sharedMCCFixture = []MCCMNCRow{
	{MCC: "234", MNC: "10", ISO: "gb", Country: "United Kingdom"},
	{MCC: "234", MNC: "50", ISO: "je", Country: "Jersey"},
	{MCC: "234", MNC: "15", ISO: "gb", Country: "United Kingdom"},
	{MCC: "234", MNC: "55", ISO: "gg", Country: "Guernsey"},
	{MCC: "234", MNC: "30", ISO: "gb", Country: "United Kingdom"},
	{MCC: "234", MNC: "58", ISO: "im", Country: "Isle of Man"},
	{MCC: "310", MNC: "260", ISO: "us", Country: "United States"},
	{MCC: "310", MNC: "470", ISO: "gu", Country: "Guam"},
	{MCC: "310", MNC: "410", ISO: "us", Country: "United States"},
	{MCC: "262", MNC: "01", ISO: "de", Country: "Germany"},
}

func reversedRows(rows []MCCMNCRow) []MCCMNCRow {
	out := make([]MCCMNCRow, len(rows))
	for i, row := range rows {
		out[len(rows)-1-i] = row
	}
	return out
}

// failingTableServer answers every request with a server error and counts
// the requests.
func failingTableServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func fixtureTableServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(countryFixture))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func missingCachePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "data", "mcc-mnc-table.json")
}

func TestBuiltinCountryTableIsWellFormed(t *testing.T) {
	seenMCC := map[string]bool{}
	usedCodes := map[string]bool{}
	for _, entry := range builtinMCCCountries {
		if NormalizeMCC(entry.mcc) != entry.mcc {
			t.Errorf("MCC %q is not three digits", entry.mcc)
		}
		if seenMCC[entry.mcc] {
			t.Errorf("MCC %s is listed twice", entry.mcc)
		}
		seenMCC[entry.mcc] = true

		seenCode := map[string]bool{}
		for _, code := range strings.Split(entry.codes, ",") {
			if NormalizeCountryCode(code) != code {
				t.Errorf("MCC %s: %q is not an upper-case two-letter country code", entry.mcc, code)
			}
			if seenCode[code] {
				t.Errorf("MCC %s lists %s twice", entry.mcc, code)
			}
			seenCode[code] = true
			usedCodes[code] = true
			if strings.TrimSpace(builtinCountryNames[code]) == "" {
				t.Errorf("country %s (MCC %s) has no name", code, entry.mcc)
			}
		}
	}
	for code := range builtinCountryNames {
		if !usedCodes[code] {
			t.Errorf("country name for %s is not used by any MCC", code)
		}
	}

	tbl := builtinCountryTable()
	if !tbl.ready || tbl.source != CountryTableSourceBuiltin {
		t.Fatalf("built-in table ready=%v source=%q", tbl.ready, tbl.source)
	}
	if len(tbl.networks) != 0 {
		t.Fatalf("built-in table claims to know %d networks", len(tbl.networks))
	}
	if len(tbl.mccCountries) != len(builtinMCCCountries) || len(tbl.countries) != len(builtinCountryNames) {
		t.Fatalf("built-in table has %d MCCs and %d countries, want %d and %d",
			len(tbl.mccCountries), len(tbl.countries), len(builtinMCCCountries), len(builtinCountryNames))
	}

	// Home networks this project is known to be used with, plus a spread
	// over the regions.
	wantMain := map[string]string{
		"310": "US", "311": "US", "316": "US", "234": "GB", "235": "GB", "262": "DE",
		"208": "FR", "460": "CN", "454": "HK", "440": "JP", "450": "KR", "404": "IN",
		"505": "AU", "302": "CA", "724": "BR", "655": "ZA", "425": "IL", "525": "SG",
	}
	for mcc, want := range wantMain {
		if codes := tbl.mccCountries[mcc]; len(codes) == 0 || codes[0] != want {
			t.Errorf("MCC %s resolves to %v, want %s first", mcc, codes, want)
		}
	}
}

func TestInitCountryTableFallsBackToBuiltinOnlyWhenAskedTo(t *testing.T) {
	srv, _ := failingTableServer(t)
	cachePath := missingCachePath(t)

	result := InitCountryTable(context.Background(), CountryTableOptions{
		CachePath:       cachePath,
		SourceURL:       srv.URL,
		BuiltinFallback: true,
	})
	if result.Err == nil {
		t.Fatal("the failed download is not reported")
	}
	if result.Source != CountryTableSourceBuiltin || result.Countries != len(builtinCountryNames) || result.RowCount != 0 {
		t.Fatalf("result=%+v, want the built-in table", result)
	}
	if !CountryTableReady() || CountryTableSource() != CountryTableSourceBuiltin {
		t.Fatalf("ready=%v source=%q, want a ready built-in table", CountryTableReady(), CountryTableSource())
	}
	if code, ok := CountryCodeFromHomeMCC("310"); !ok || code != "US" {
		t.Fatalf("CountryCodeFromHomeMCC(310)=%q,%v, want US", code, ok)
	}
	// The built-in table cannot tell networks apart: every territory on
	// the MCC is a candidate, the main country first.
	if got, want := CountryCodesForHomeNetwork("234", "15"), []string{"GB", "GG", "IM", "JE"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CountryCodesForHomeNetwork(234, 15)=%v, want %v", got, want)
	}
	if mccs, ok := MCCsForCountryCode("us"); !ok || !reflect.DeepEqual(mccs, []string{"310", "311", "312", "313", "314", "315", "316"}) {
		t.Fatalf("MCCsForCountryCode(US)=%v,%v", mccs, ok)
	}
	if display := CountryRuleDisplay("JE"); display.CountryName != "Jersey" || !reflect.DeepEqual(display.MCCs, []string{"234"}) {
		t.Fatalf("CountryRuleDisplay(JE)=%+v", display)
	}
	if len(ListCountryDisplays()) != len(builtinCountryNames) {
		t.Fatalf("ListCountryDisplays() has %d countries, want %d", len(ListCountryDisplays()), len(builtinCountryNames))
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("the built-in table was written to the cache (stat err=%v)", err)
	}

	// Without the option nothing changes for existing callers.
	result = InitCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath, SourceURL: srv.URL})
	if result.Err == nil || result.Source != CountryTableSourceEmpty {
		t.Fatalf("result=%+v, want an empty table and an error", result)
	}
	if CountryTableReady() || CountryTableSource() != CountryTableSourceEmpty {
		t.Fatalf("ready=%v source=%q, want no table", CountryTableReady(), CountryTableSource())
	}
	if codes := CountryCodesForHomeNetwork("310", "260"); len(codes) != 0 {
		t.Fatalf("CountryCodesForHomeNetwork(310, 260)=%v with no table", codes)
	}
}

func TestLoadedCountryTableIsNotMixedWithBuiltinData(t *testing.T) {
	cases := []struct {
		name       string
		prepare    func(t *testing.T) CountryTableOptions
		wantSource string
	}{
		{"cache", func(t *testing.T) CountryTableOptions {
			srv, _ := failingTableServer(t)
			cachePath := missingCachePath(t)
			writeCountryFixture(t, cachePath)
			return CountryTableOptions{CachePath: cachePath, SourceURL: srv.URL}
		}, CountryTableSourceCache},
		{"download", func(t *testing.T) CountryTableOptions {
			return CountryTableOptions{CachePath: missingCachePath(t), SourceURL: fixtureTableServer(t).URL}
		}, CountryTableSourceDownload},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.prepare(t)
			opts.BuiltinFallback = true
			result := InitCountryTable(context.Background(), opts)
			if result.Err != nil || result.Source != tc.wantSource || result.RowCount != 8 {
				t.Fatalf("result=%+v, want 8 rows from %s", result, tc.wantSource)
			}
			if CountryTableSource() != tc.wantSource {
				t.Fatalf("CountryTableSource()=%q, want %q", CountryTableSource(), tc.wantSource)
			}
			// 404 (India) is in the built-in table but not in the fixture.
			if code, ok := CountryCodeFromHomeMCC("404"); ok {
				t.Fatalf("CountryCodeFromHomeMCC(404)=%q: built-in data leaked into the loaded table", code)
			}
			if got := len(ListCountryDisplays()); got != 2 {
				t.Fatalf("%d countries listed, want the 2 of the fixture", got)
			}
		})
	}
}

func TestSharedMCCStandsForTheCountryWithMostNetworks(t *testing.T) {
	for name, rows := range map[string][]MCCMNCRow{
		"source order":   sharedMCCFixture,
		"reversed order": reversedRows(sharedMCCFixture),
	} {
		t.Run(name, func(t *testing.T) {
			tbl := buildCountryTable(rows)
			tbl.source = CountryTableSourceCache
			installCountryTable(tbl)

			for mcc, want := range map[string]string{"234": "GB", "310": "US", "262": "DE"} {
				if code, ok := CountryCodeFromHomeMCC(mcc); !ok || code != want {
					t.Errorf("CountryCodeFromHomeMCC(%s)=%q,%v, want %s", mcc, code, ok, want)
				}
			}
			candidates := CountryCodesForHomeNetwork("234", "")
			if len(candidates) != 4 || candidates[0] != "GB" {
				t.Fatalf("candidates for 234 = %v, want GB first of four", candidates)
			}
			for _, code := range []string{"JE", "GG", "IM"} {
				if !containsString(candidates, code) {
					t.Errorf("candidates for 234 = %v, missing %s", candidates, code)
				}
				// A territory sharing an MCC still lists it, so a rule
				// can be configured for it.
				if mccs, ok := MCCsForCountryCode(code); !ok || !reflect.DeepEqual(mccs, []string{"234"}) {
					t.Errorf("MCCsForCountryCode(%s)=%v,%v, want [234]", code, mccs, ok)
				}
			}
			if got, want := CountryCodesForHomeNetwork("310", ""), []string{"US", "GU"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("candidates for 310 = %v, want %v", got, want)
			}
		})
	}
}

func TestEquallyCommonCountriesKeepSourceOrder(t *testing.T) {
	rows := []MCCMNCRow{
		{MCC: "425", MNC: "05", ISO: "ps", Country: "Palestine"},
		{MCC: "425", MNC: "01", ISO: "il", Country: "Israel"},
	}
	installCountryTable(buildCountryTable(rows))
	if got, want := CountryCodesForHomeNetwork("425", ""), []string{"PS", "IL"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	installCountryTable(buildCountryTable(reversedRows(rows)))
	if got, want := CountryCodesForHomeNetwork("425", ""), []string{"IL", "PS"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}

func TestHomeNetworkResolvesToItsOwnCountryWhenListed(t *testing.T) {
	installCountryTable(buildCountryTable(sharedMCCFixture))

	cases := []struct {
		mcc, mnc string
		want     []string
	}{
		{"234", "50", []string{"JE"}},
		{"234", "55", []string{"GG"}},
		{"234", "58", []string{"IM"}},
		{"234", "15", []string{"GB"}},
		{" 234 ", " 15 ", []string{"GB"}},
		{"310", "470", []string{"GU"}},
		{"310", "260", []string{"US"}},
		// Not a listed network: every country on the MCC, main one first.
		{"234", "99", []string{"GB", "JE", "GG", "IM"}},
		{"234", "", []string{"GB", "JE", "GG", "IM"}},
		{"234", "1x", []string{"GB", "JE", "GG", "IM"}},
		// The MNC length is part of the network identity.
		{"310", "26", []string{"US", "GU"}},
		{"234", "015", []string{"GB", "JE", "GG", "IM"}},
		{"262", "01", []string{"DE"}},
		{"262", "77", []string{"DE"}},
		{"999", "01", nil},
		{"", "01", nil},
		{"31", "260", nil},
	}
	for _, tc := range cases {
		if got := CountryCodesForHomeNetwork(tc.mcc, tc.mnc); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("CountryCodesForHomeNetwork(%q, %q)=%v, want %v", tc.mcc, tc.mnc, got, tc.want)
		}
	}

	// The result is the caller's to keep.
	candidates := CountryCodesForHomeNetwork("234", "")
	candidates[0] = "ZZ"
	if code, _ := CountryCodeFromHomeMCC("234"); code != "GB" {
		t.Fatalf("modifying a result changed the table: 234 is now %q", code)
	}
}

func TestNormalizeMNC(t *testing.T) {
	for in, want := range map[string]string{
		"01": "01", "260": "260", " 15 ": "15", "001": "001",
		"": "", "1": "", "1234": "", "1a": "", "-1": "", "１２": "",
	} {
		if got := NormalizeMNC(in); got != want {
			t.Errorf("NormalizeMNC(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestRefreshCountryTableReplacesBuiltinAndSurvivesFailure(t *testing.T) {
	failing, _ := failingTableServer(t)
	cachePath := missingCachePath(t)
	InitCountryTable(context.Background(), CountryTableOptions{
		CachePath: cachePath, SourceURL: failing.URL, BuiltinFallback: true,
	})
	if CountryTableSource() != CountryTableSourceBuiltin {
		t.Fatalf("source=%q, want the built-in table to start from", CountryTableSource())
	}

	// A failed refresh reports the failure and leaves the table alone.
	result := RefreshCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath, SourceURL: failing.URL})
	if result.Err == nil || result.Downloaded || result.Source != CountryTableSourceBuiltin {
		t.Fatalf("failed refresh result=%+v, want an error and the built-in table kept", result)
	}
	if code, ok := CountryCodeFromHomeMCC("404"); !ok || code != "IN" {
		t.Fatalf("after a failed refresh 404 resolves to %q,%v, want IN", code, ok)
	}

	// A successful one replaces it and fills the cache.
	result = RefreshCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath, SourceURL: fixtureTableServer(t).URL})
	if result.Err != nil || !result.Downloaded || result.Source != CountryTableSourceDownload || result.RowCount != 8 || result.Countries != 2 {
		t.Fatalf("refresh result=%+v, want 8 downloaded rows", result)
	}
	if CountryTableSource() != CountryTableSourceDownload {
		t.Fatalf("source=%q after a successful refresh", CountryTableSource())
	}
	if _, ok := CountryCodeFromHomeMCC("404"); ok {
		t.Fatal("the built-in table is still in use after a successful refresh")
	}
	if got, want := CountryCodesForHomeNetwork("310", "260"), []string{"US"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CountryCodesForHomeNetwork(310, 260)=%v, want %v", got, want)
	}

	// The next start finds the cache and needs no network.
	result = InitCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath, SourceURL: failing.URL})
	if result.Err != nil || result.Source != CountryTableSourceCache || result.RowCount != 8 {
		t.Fatalf("restart result=%+v, want the cached table", result)
	}

	// A failed refresh keeps a downloaded table too.
	result = RefreshCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath, SourceURL: failing.URL})
	// The kept table is a loaded one, which must not read as a success.
	if result.Err == nil || result.Downloaded || result.Source != CountryTableSourceCache || !CountryTableReady() {
		t.Fatalf("failed refresh result=%+v ready=%v, want the cached table kept", result, CountryTableReady())
	}
}

func TestKeepRefreshingCountryTableStopsAfterTheFirstSuccess(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) < 3 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(countryFixture))
	}))
	defer srv.Close()
	opts := CountryTableOptions{CachePath: missingCachePath(t), SourceURL: srv.URL, BuiltinFallback: true}
	InitCountryTable(context.Background(), opts) // request 1 fails

	var mu sync.Mutex
	var sources []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		KeepRefreshingCountryTable(context.Background(), opts, []time.Duration{time.Millisecond}, func(result CountryTableInitResult) {
			mu.Lock()
			defer mu.Unlock()
			sources = append(sources, result.Source)
		})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("KeepRefreshingCountryTable did not return after a successful download")
	}

	mu.Lock()
	defer mu.Unlock()
	if want := []string{CountryTableSourceBuiltin, CountryTableSourceDownload}; !reflect.DeepEqual(sources, want) {
		t.Fatalf("reported sources = %v, want %v", sources, want)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("%d requests were made, want 3", got)
	}
	if CountryTableSource() != CountryTableSourceDownload {
		t.Fatalf("source=%q, want the downloaded table", CountryTableSource())
	}
}

func TestKeepRefreshingCountryTableStopsWhenCancelled(t *testing.T) {
	// Start from a downloaded table: a failed attempt keeps it, and that
	// must not be taken for a successful download.
	InitCountryTable(context.Background(), CountryTableOptions{
		CachePath: missingCachePath(t), SourceURL: fixtureTableServer(t).URL,
	})
	if CountryTableSource() != CountryTableSourceDownload {
		t.Fatalf("source=%q, want a downloaded table to start from", CountryTableSource())
	}
	srv, hits := failingTableServer(t)
	opts := CountryTableOptions{CachePath: missingCachePath(t), SourceURL: srv.URL}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		KeepRefreshingCountryTable(ctx, opts, []time.Duration{time.Millisecond}, nil)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for hits.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d attempts were made", hits.Load())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("KeepRefreshingCountryTable did not return after cancellation")
	}

	// While waiting for the first attempt it must not need the network to
	// notice a cancellation.
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	before := hits.Load()
	KeepRefreshingCountryTable(ctx, opts, []time.Duration{time.Hour}, nil)
	if hits.Load() != before {
		t.Fatal("a download was attempted after cancellation")
	}
}

func TestInitCountryTableDoesNotOutliveItsDeadline(t *testing.T) {
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer stalled.Close()
	second, secondHits := failingTableServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	result := InitCountryTable(ctx, CountryTableOptions{
		CachePath:       missingCachePath(t),
		SourceURLs:      []string{stalled.URL, second.URL},
		BuiltinFallback: true,
	})
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("InitCountryTable took %v with a 150ms deadline", elapsed)
	}
	if result.Err == nil || result.Source != CountryTableSourceBuiltin {
		t.Fatalf("result=%+v, want the built-in table and the download error", result)
	}
	if secondHits.Load() != 0 {
		t.Fatal("the next source was tried after the deadline had passed")
	}
}

func TestCountryTableCacheIsReplacedWithoutLeftovers(t *testing.T) {
	cachePath := missingCachePath(t)
	srv := fixtureTableServer(t)
	for i := 0; i < 3; i++ {
		result := RefreshCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath, SourceURL: srv.URL})
		if result.Err != nil || result.Source != CountryTableSourceDownload {
			t.Fatalf("refresh %d result=%+v", i, result)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(cachePath))
	if err != nil {
		t.Fatalf("ReadDir() error=%v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(cachePath) {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("cache directory holds %v, want only the cache file", names)
	}
	rows, err := readMCCMNCCache(cachePath)
	if err != nil || len(rows) != 8 {
		t.Fatalf("cache holds %d rows (err=%v), want 8", len(rows), err)
	}
}

func TestCountryTableIsUsableWhenTheCacheCannotBeWritten(t *testing.T) {
	// The cache directory cannot be created: its parent is a file.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile() error=%v", err)
	}
	result := InitCountryTable(context.Background(), CountryTableOptions{
		CachePath: filepath.Join(blocker, "data", "mcc-mnc-table.json"),
		SourceURL: fixtureTableServer(t).URL,
	})
	if result.Err == nil {
		t.Fatal("the cache write failure is not reported")
	}
	if result.Source != CountryTableSourceDownload || !CountryTableReady() {
		t.Fatalf("result=%+v ready=%v, want the downloaded table in use", result, CountryTableReady())
	}
	if code, ok := CountryCodeFromHomeMCC("262"); !ok || code != "DE" {
		t.Fatalf("CountryCodeFromHomeMCC(262)=%q,%v, want DE", code, ok)
	}
}

func TestDownloadRejectsAnOversizedTable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Valid JSON of unbounded size: an array that never ends.
		chunk := []byte("[" + strings.Repeat(" ", 64<<10))
		for written := 0; written <= maxMCCMNCTableBytes+len(chunk); written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			chunk = chunk[:64<<10]
			for i := range chunk {
				chunk[i] = ' '
			}
		}
	}))
	defer srv.Close()

	cachePath := missingCachePath(t)
	result := InitCountryTable(context.Background(), CountryTableOptions{CachePath: cachePath, SourceURL: srv.URL})
	if result.Err == nil || !strings.Contains(result.Err.Error(), "larger than") {
		t.Fatalf("result.Err=%v, want the size limit to be reported", result.Err)
	}
	if result.Source != CountryTableSourceEmpty || CountryTableReady() {
		t.Fatalf("result=%+v ready=%v, want no table", result, CountryTableReady())
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("an oversized table reached the cache (stat err=%v)", err)
	}
}
