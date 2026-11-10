package upstreamproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultMCCMNCTableURL        = "https://cdn.jsdelivr.net/npm/mcc-mnc@latest/src/database/mcc-mnc-table.json"
	DefaultCountryTableCachePath = "data/mcc-mnc-table.json"
)

var DefaultMCCMNCTableURLs = []string{
	"https://cdn.jsdelivr.net/npm/mcc-mnc@latest/src/database/mcc-mnc-table.json",
	"https://fastly.jsdelivr.net/npm/mcc-mnc@latest/src/database/mcc-mnc-table.json",
	"https://gcore.jsdelivr.net/npm/mcc-mnc@latest/src/database/mcc-mnc-table.json",
	"https://cdn.jsdelivr.net/gh/musalbas/mcc-mnc-table@master/mcc-mnc-table.json",
	"https://raw.githubusercontent.com/musalbas/mcc-mnc-table/refs/heads/master/mcc-mnc-table.json",
}

// Where the country table in use came from.
const (
	CountryTableSourceCache    = "cache"
	CountryTableSourceDownload = "download"
	// CountryTableSourceBuiltin: the table compiled into the program. It maps
	// MCCs to countries but knows no individual networks.
	CountryTableSourceBuiltin = "builtin"
	// CountryTableSourceEmpty: no table; no country can be derived.
	CountryTableSourceEmpty = "empty"
)

// maxMCCMNCTableBytes bounds a download. The real table is well under 1 MiB.
const maxMCCMNCTableBytes = 16 << 20

type CountryDisplay struct {
	CountryCode string   `json:"country_code"`
	CountryName string   `json:"country_name"`
	MCCs        []string `json:"mccs"`
}

type MCCMNCRow struct {
	MCC         string `json:"mcc"`
	MNC         string `json:"mnc"`
	ISO         string `json:"iso"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Network     string `json:"network"`
}

type CountryTableOptions struct {
	CachePath  string
	SourceURL  string
	SourceURLs []string
	HTTPClient *http.Client
	// BuiltinFallback installs the built-in table when neither the cache nor
	// a download yields one, so that country rules keep working offline.
	// Without it an unavailable table leaves every home network without a
	// country, which routes it directly.
	BuiltinFallback bool
}

type CountryTableInitResult struct {
	CachePath string
	SourceURL string
	// Source is where the table now in use came from. After a failed
	// refresh that is the table that was kept.
	Source    string
	RowCount  int
	Countries int
	// Downloaded: this call downloaded a table and put it into use.
	Downloaded bool
	Err        error
}

type countryTable struct {
	ready  bool
	source string
	// mccCountries lists the countries using an MCC, the main one first.
	mccCountries map[string][]string
	// networks maps "MCC-MNC" to the country of that network, for sources
	// that list networks.
	networks  map[string]string
	countries map[string]CountryDisplay
}

var countryTableState = struct {
	sync.RWMutex
	table countryTable
}{}

// InitCountryTable installs the country table: from the cache file when it
// is usable, otherwise from a download, which is then cached. When both fail
// the result carries the error and the table is the built-in one if
// opts.BuiltinFallback is set, or empty.
//
// A download is tried against every source in turn, so ctx should carry a
// deadline when the caller must not wait for all of them.
func InitCountryTable(ctx context.Context, opts CountryTableOptions) CountryTableInitResult {
	cachePath := countryTableCachePath(opts)
	sourceURLs := countryTableSourceURLs(opts)
	result := CountryTableInitResult{CachePath: cachePath}
	if len(sourceURLs) > 0 {
		result.SourceURL = sourceURLs[0]
	}

	if rows, err := readMCCMNCCache(cachePath); err == nil && len(rows) > 0 {
		tbl := buildCountryTable(rows)
		if tbl.ready {
			tbl.source = CountryTableSourceCache
			installCountryTable(tbl)
			result.Source = CountryTableSourceCache
			result.RowCount = len(rows)
			result.Countries = len(tbl.countries)
			return result
		}
	}

	downloaded := downloadCountryTable(ctx, opts, &result)
	if downloaded {
		return result
	}
	if opts.BuiltinFallback {
		tbl := builtinCountryTable()
		installCountryTable(tbl)
		result.Source = CountryTableSourceBuiltin
		result.Countries = len(tbl.countries)
		return result
	}
	installCountryTable(emptyCountryTable())
	result.Source = CountryTableSourceEmpty
	return result
}

// RefreshCountryTable downloads the table and, when that succeeds, installs
// it and updates the cache. A failed download is reported in the result and
// leaves the table in use as it is.
func RefreshCountryTable(ctx context.Context, opts CountryTableOptions) CountryTableInitResult {
	result := CountryTableInitResult{CachePath: countryTableCachePath(opts)}
	if !downloadCountryTable(ctx, opts, &result) {
		result.Source = CountryTableSource()
	}
	return result
}

// defaultCountryTableRetrySchedule spaces background downloads. The last
// entry repeats.
var defaultCountryTableRetrySchedule = []time.Duration{
	time.Minute, 5 * time.Minute, 30 * time.Minute, 6 * time.Hour,
}

// KeepRefreshingCountryTable retries the download until one succeeds or ctx
// ends, waiting schedule[i] before attempt i (the last entry repeats; nil
// selects the default schedule). It is how a program that started on the
// built-in table moves to the full one once the network allows. report, if
// set, receives the result of every attempt.
func KeepRefreshingCountryTable(ctx context.Context, opts CountryTableOptions, schedule []time.Duration, report func(CountryTableInitResult)) {
	if len(schedule) == 0 {
		schedule = defaultCountryTableRetrySchedule
	}
	for attempt := 0; ; attempt++ {
		wait := schedule[len(schedule)-1]
		if attempt < len(schedule) {
			wait = schedule[attempt]
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		result := RefreshCountryTable(ctx, opts)
		if ctx.Err() != nil {
			return
		}
		if report != nil {
			report(result)
		}
		if result.Downloaded {
			return
		}
	}
}

// downloadCountryTable fetches, installs and caches the table. It fills
// result and reports whether a downloaded table is now installed.
func downloadCountryTable(ctx context.Context, opts CountryTableOptions, result *CountryTableInitResult) bool {
	rows, sourceURL, err := downloadMCCMNCTableFromSources(ctx, countryTableSourceURLs(opts), opts.HTTPClient)
	result.SourceURL = sourceURL
	if err != nil {
		result.Err = err
		return false
	}
	tbl := buildCountryTable(rows)
	if !tbl.ready {
		result.RowCount = len(rows)
		result.Err = errors.New("mcc-mnc table has no valid country rows")
		return false
	}
	if err := writeMCCMNCCache(result.CachePath, rows); err != nil {
		// The table is usable; only the next start has to download again.
		result.Err = err
	}
	tbl.source = CountryTableSourceDownload
	installCountryTable(tbl)
	result.Source = CountryTableSourceDownload
	result.RowCount = len(rows)
	result.Countries = len(tbl.countries)
	result.Downloaded = true
	return true
}

func countryTableCachePath(opts CountryTableOptions) string {
	if cachePath := strings.TrimSpace(opts.CachePath); cachePath != "" {
		return cachePath
	}
	return DefaultCountryTableCachePath
}

func countryTableSourceURLs(opts CountryTableOptions) []string {
	var raw []string
	if len(opts.SourceURLs) > 0 {
		raw = opts.SourceURLs
	} else if strings.TrimSpace(opts.SourceURL) != "" {
		raw = []string{opts.SourceURL}
	} else {
		raw = DefaultMCCMNCTableURLs
	}
	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, sourceURL := range raw {
		sourceURL = strings.TrimSpace(sourceURL)
		if sourceURL == "" || seen[sourceURL] {
			continue
		}
		seen[sourceURL] = true
		out = append(out, sourceURL)
	}
	if len(out) == 0 {
		out = append(out, DefaultMCCMNCTableURL)
	}
	return out
}

func readMCCMNCCache(path string) ([]MCCMNCRow, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeMCCMNCRows(b)
}

func downloadMCCMNCTable(ctx context.Context, sourceURL string, client *http.Client) ([]MCCMNCRow, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("mcc-mnc table fetch failed: status %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxMCCMNCTableBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMCCMNCTableBytes {
		return nil, fmt.Errorf("mcc-mnc table is larger than %d bytes", maxMCCMNCTableBytes)
	}
	return decodeMCCMNCRows(body)
}

func downloadMCCMNCTableFromSources(ctx context.Context, sourceURLs []string, client *http.Client) ([]MCCMNCRow, string, error) {
	var errs []error
	for _, sourceURL := range sourceURLs {
		rows, err := downloadMCCMNCTable(ctx, sourceURL, client)
		if err == nil {
			return rows, sourceURL, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", sourceURL, err))
		if ctx.Err() != nil {
			// Out of time: the remaining sources would fail the same way.
			break
		}
	}
	if len(errs) == 0 {
		return nil, "", errors.New("mcc-mnc table has no source URLs")
	}
	return nil, firstNonEmptyString(sourceURLs...), errors.Join(errs...)
}

func decodeMCCMNCRows(b []byte) ([]MCCMNCRow, error) {
	var rows []MCCMNCRow
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// writeMCCMNCCache replaces the cache file atomically. Each writer uses its
// own temporary file, so concurrent writers cannot corrupt one another.
func writeMCCMNCCache(path string, rows []MCCMNCRow) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_, err = tmp.Write(b)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(tmpPath, 0o644)
	}
	if err == nil {
		err = os.Rename(tmpPath, path)
	}
	if err != nil {
		_ = os.Remove(tmpPath)
	}
	return err
}

// buildCountryTable derives the table from MCC/MNC rows.
//
// Some MCCs are shared by several territories (234 by the United Kingdom,
// Guernsey, Jersey and the Isle of Man; 310 by the United States, Guam and
// the Northern Mariana Islands). The territory with the most networks on an
// MCC is the one the MCC stands for when the network itself is unknown; the
// row order of the source does not matter.
func buildCountryTable(rows []MCCMNCRow) countryTable {
	tbl := emptyCountryTable()
	networksPerCountry := map[string]map[string]int{}
	for _, row := range rows {
		mcc := NormalizeMCC(row.MCC)
		countryCode := rowCountryCode(row)
		if mcc == "" || countryCode == "" {
			continue
		}
		tbl.addCountryMCC(countryCode, mcc, row.Country)

		counts := networksPerCountry[mcc]
		if counts == nil {
			counts = map[string]int{}
			networksPerCountry[mcc] = counts
		}
		if counts[countryCode] == 0 {
			tbl.mccCountries[mcc] = append(tbl.mccCountries[mcc], countryCode)
		}
		counts[countryCode]++

		if mnc := NormalizeMNC(row.MNC); mnc != "" {
			key := networkKey(mcc, mnc)
			if _, known := tbl.networks[key]; !known {
				tbl.networks[key] = countryCode
			}
		}
	}
	for mcc, codes := range tbl.mccCountries {
		counts := networksPerCountry[mcc]
		// Stable: equally common countries keep the order of the source.
		sort.SliceStable(codes, func(i, j int) bool { return counts[codes[i]] > counts[codes[j]] })
	}
	tbl.finish()
	return tbl
}

func (t *countryTable) addCountryMCC(countryCode, mcc, countryName string) {
	display := t.countries[countryCode]
	display.CountryCode = countryCode
	if display.CountryName == "" {
		display.CountryName = strings.TrimSpace(countryName)
	}
	if !containsString(display.MCCs, mcc) {
		display.MCCs = append(display.MCCs, mcc)
	}
	t.countries[countryCode] = display
}

func (t *countryTable) finish() {
	for code, display := range t.countries {
		if display.CountryName == "" {
			display.CountryName = code
		}
		sort.Strings(display.MCCs)
		t.countries[code] = display
	}
	t.ready = len(t.mccCountries) > 0 && len(t.countries) > 0
}

func rowCountryCode(row MCCMNCRow) string {
	if code := NormalizeCountryCode(row.ISO); code != "" {
		return code
	}
	return NormalizeCountryCode(row.CountryCode)
}

func emptyCountryTable() countryTable {
	return countryTable{
		mccCountries: map[string][]string{},
		networks:     map[string]string{},
		countries:    map[string]CountryDisplay{},
	}
}

func installCountryTable(tbl countryTable) {
	countryTableState.Lock()
	defer countryTableState.Unlock()
	countryTableState.table = tbl
}

func CountryTableReady() bool {
	countryTableState.RLock()
	defer countryTableState.RUnlock()
	return countryTableState.table.ready
}

// CountryTableSource reports where the table in use came from: one of the
// CountryTableSource constants.
func CountryTableSource() string {
	countryTableState.RLock()
	defer countryTableState.RUnlock()
	if !countryTableState.table.ready || countryTableState.table.source == "" {
		return CountryTableSourceEmpty
	}
	return countryTableState.table.source
}

func NormalizeCountryCode(countryCode string) string {
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if len(countryCode) != 2 {
		return ""
	}
	for _, r := range countryCode {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return countryCode
}

func NormalizeMCC(mcc string) string {
	mcc = strings.TrimSpace(mcc)
	if len(mcc) != 3 {
		return ""
	}
	for _, r := range mcc {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return mcc
}

// NormalizeMNC returns a two or three digit MNC, or "" for anything else.
// The length is significant: 01 and 001 are different networks.
func NormalizeMNC(mnc string) string {
	mnc = strings.TrimSpace(mnc)
	if len(mnc) != 2 && len(mnc) != 3 {
		return ""
	}
	for _, r := range mnc {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return mnc
}

func networkKey(mcc, mnc string) string {
	return mcc + "-" + mnc
}

// CountryCodeFromHomeMCC returns the country an MCC stands for; for an MCC
// shared by several territories that is the main one.
func CountryCodeFromHomeMCC(mcc string) (string, bool) {
	codes := CountryCodesForHomeNetwork(mcc, "")
	if len(codes) == 0 {
		return "", false
	}
	return codes[0], true
}

// CountryCodesForHomeNetwork returns the countries a home network can belong
// to, most likely first.
//
// A network the table lists by MCC and MNC belongs to exactly one country.
// Otherwise (the MNC is not given, is not in the table, or the table is the
// built-in one) the result is every country using the MCC, the main one
// first. Nothing is returned for an MCC the table does not know.
func CountryCodesForHomeNetwork(mcc, mnc string) []string {
	mcc = NormalizeMCC(mcc)
	if mcc == "" {
		return nil
	}
	countryTableState.RLock()
	defer countryTableState.RUnlock()
	if mnc = NormalizeMNC(mnc); mnc != "" {
		if countryCode, ok := countryTableState.table.networks[networkKey(mcc, mnc)]; ok {
			return []string{countryCode}
		}
	}
	codes := countryTableState.table.mccCountries[mcc]
	if len(codes) == 0 {
		return nil
	}
	return append([]string(nil), codes...)
}

func MCCsForCountryCode(countryCode string) ([]string, bool) {
	countryCode = NormalizeCountryCode(countryCode)
	countryTableState.RLock()
	defer countryTableState.RUnlock()
	display, ok := countryTableState.table.countries[countryCode]
	if !ok {
		return nil, false
	}
	out := append([]string(nil), display.MCCs...)
	return out, true
}

func CountryRuleDisplay(countryCode string) CountryDisplay {
	countryCode = NormalizeCountryCode(countryCode)
	if countryCode == "" {
		return CountryDisplay{}
	}
	countryTableState.RLock()
	defer countryTableState.RUnlock()
	display, ok := countryTableState.table.countries[countryCode]
	if !ok {
		return CountryDisplay{CountryCode: countryCode, CountryName: countryCode}
	}
	display.MCCs = append([]string(nil), display.MCCs...)
	return display
}

func ListCountryDisplays() []CountryDisplay {
	countryTableState.RLock()
	defer countryTableState.RUnlock()
	out := make([]CountryDisplay, 0, len(countryTableState.table.countries))
	for _, display := range countryTableState.table.countries {
		display.MCCs = append([]string(nil), display.MCCs...)
		out = append(out, display)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CountryCode < out[j].CountryCode })
	return out
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func firstNonEmptyString(items ...string) string {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			return item
		}
	}
	return ""
}
