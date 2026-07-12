package upstreamproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
}

type CountryTableInitResult struct {
	CachePath string
	SourceURL string
	Source    string
	RowCount  int
	Countries int
	Err       error
}

type countryTable struct {
	ready        bool
	mccToCountry map[string]string
	countries    map[string]CountryDisplay
}

var countryTableState = struct {
	sync.RWMutex
	table countryTable
}{}

func InitCountryTable(ctx context.Context, opts CountryTableOptions) CountryTableInitResult {
	cachePath := strings.TrimSpace(opts.CachePath)
	if cachePath == "" {
		cachePath = DefaultCountryTableCachePath
	}
	sourceURLs := countryTableSourceURLs(opts)
	result := CountryTableInitResult{CachePath: cachePath}
	if len(sourceURLs) > 0 {
		result.SourceURL = sourceURLs[0]
	}

	if rows, err := readMCCMNCCache(cachePath); err == nil && len(rows) > 0 {
		tbl := buildCountryTable(rows)
		if tbl.ready {
			installCountryTable(tbl)
			result.Source = "cache"
			result.RowCount = len(rows)
			result.Countries = len(tbl.countries)
			return result
		}
	}

	rows, sourceURL, err := downloadMCCMNCTableFromSources(ctx, sourceURLs, opts.HTTPClient)
	result.SourceURL = sourceURL
	if err != nil {
		installCountryTable(emptyCountryTable())
		result.Source = "empty"
		result.Err = err
		return result
	}
	tbl := buildCountryTable(rows)
	if !tbl.ready {
		installCountryTable(tbl)
		result.Source = "empty"
		result.RowCount = len(rows)
		result.Err = errors.New("mcc-mnc table has no valid country rows")
		return result
	}
	if err := writeMCCMNCCache(cachePath, rows); err != nil {
		result.Err = err
	}
	installCountryTable(tbl)
	result.Source = "download"
	result.RowCount = len(rows)
	result.Countries = len(tbl.countries)
	return result
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
	var rows []MCCMNCRow
	if err := json.NewDecoder(res.Body).Decode(&rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func downloadMCCMNCTableFromSources(ctx context.Context, sourceURLs []string, client *http.Client) ([]MCCMNCRow, string, error) {
	var errs []error
	for _, sourceURL := range sourceURLs {
		rows, err := downloadMCCMNCTable(ctx, sourceURL, client)
		if err == nil {
			return rows, sourceURL, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", sourceURL, err))
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

func writeMCCMNCCache(path string, rows []MCCMNCRow) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func buildCountryTable(rows []MCCMNCRow) countryTable {
	tbl := emptyCountryTable()
	for _, row := range rows {
		mcc := NormalizeMCC(row.MCC)
		countryCode := rowCountryCode(row)
		if mcc == "" || countryCode == "" {
			continue
		}
		tbl.mccToCountry[mcc] = countryCode
		display := tbl.countries[countryCode]
		display.CountryCode = countryCode
		if display.CountryName == "" {
			display.CountryName = strings.TrimSpace(row.Country)
		}
		if !containsString(display.MCCs, mcc) {
			display.MCCs = append(display.MCCs, mcc)
		}
		tbl.countries[countryCode] = display
	}
	for code, display := range tbl.countries {
		if display.CountryName == "" {
			display.CountryName = code
		}
		sort.Strings(display.MCCs)
		tbl.countries[code] = display
	}
	tbl.ready = len(tbl.mccToCountry) > 0 && len(tbl.countries) > 0
	return tbl
}

func rowCountryCode(row MCCMNCRow) string {
	if code := NormalizeCountryCode(row.ISO); code != "" {
		return code
	}
	return NormalizeCountryCode(row.CountryCode)
}

func emptyCountryTable() countryTable {
	return countryTable{
		mccToCountry: map[string]string{},
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

func CountryCodeFromHomeMCC(mcc string) (string, bool) {
	mcc = NormalizeMCC(mcc)
	if mcc == "" {
		return "", false
	}
	countryTableState.RLock()
	defer countryTableState.RUnlock()
	countryCode, ok := countryTableState.table.mccToCountry[mcc]
	return countryCode, ok
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
