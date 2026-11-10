package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/1239t/vohive/internal/upstreamproxy"
)

// sharedMCCRows: MCC 234 is used by the United Kingdom (most networks) and
// by Jersey and Guernsey.
const sharedMCCRows = `[
  {"mcc":"234","mnc":"10","iso":"gb","country":"United Kingdom"},
  {"mcc":"234","mnc":"50","iso":"je","country":"Jersey"},
  {"mcc":"234","mnc":"15","iso":"gb","country":"United Kingdom"},
  {"mcc":"234","mnc":"55","iso":"gg","country":"Guernsey"},
  {"mcc":"234","mnc":"30","iso":"gb","country":"United Kingdom"}
]`

func openTestDBWithCountryRows(t *testing.T, rows string) {
	t.Helper()
	if err := Init(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("Init() error=%v", err)
	}
	cachePath := filepath.Join(t.TempDir(), "mcc-mnc-table.json")
	if err := os.WriteFile(cachePath, []byte(rows), 0o644); err != nil {
		t.Fatalf("WriteFile() error=%v", err)
	}
	result := upstreamproxy.InitCountryTable(context.Background(), upstreamproxy.CountryTableOptions{
		CachePath: cachePath,
		SourceURL: "http://127.0.0.1:1/missing",
	})
	if result.Err != nil {
		t.Fatalf("InitCountryTable() error=%v", result.Err)
	}
}

func addCountryProxy(t *testing.T, countryCode, proxyID string) {
	t.Helper()
	if err := UpsertUpstreamProxy(UpstreamProxy{ID: proxyID, Name: proxyID, Addr: "127.0.0.1:1080", Enabled: true}); err != nil {
		t.Fatalf("UpsertUpstreamProxy(%s) error=%v", proxyID, err)
	}
	if err := UpsertUpstreamProxyCountryRule(UpstreamProxyCountryRule{CountryCode: countryCode, UpstreamProxyID: proxyID, Enabled: true}); err != nil {
		t.Fatalf("UpsertUpstreamProxyCountryRule(%s) error=%v", countryCode, err)
	}
}

type homeNetworkCase struct {
	mcc, mnc    string
	wantProxy   string // "" for a direct route
	wantCountry string
}

func checkHomeNetworkCases(t *testing.T, cases []homeNetworkCase) {
	t.Helper()
	for _, tc := range cases {
		proxy, country, err := GetHomeNetworkUpstreamProxy(tc.mcc, tc.mnc)
		if err != nil {
			t.Errorf("GetHomeNetworkUpstreamProxy(%q, %q) error=%v", tc.mcc, tc.mnc, err)
			continue
		}
		gotProxy := ""
		if proxy != nil {
			gotProxy = proxy.ID
		}
		if gotProxy != tc.wantProxy || country != tc.wantCountry {
			t.Errorf("GetHomeNetworkUpstreamProxy(%q, %q) = proxy %q, country %q; want proxy %q, country %q",
				tc.mcc, tc.mnc, gotProxy, country, tc.wantProxy, tc.wantCountry)
		}
	}
}

func TestHomeNetworkProxyFollowsTheNetworksOwnCountry(t *testing.T) {
	openTestDBWithCountryRows(t, sharedMCCRows)
	addCountryProxy(t, "GB", "proxy-gb")
	addCountryProxy(t, "JE", "proxy-je")

	checkHomeNetworkCases(t, []homeNetworkCase{
		{"234", "15", "proxy-gb", "GB"},
		{"234", "50", "proxy-je", "JE"},
		// Guernsey has no rule, and a Guernsey network does not borrow one.
		{"234", "55", "", "GG"},
		// Unlisted network, or no MNC at all: the main country of the MCC.
		{"234", "99", "proxy-gb", "GB"},
		{"234", "", "proxy-gb", "GB"},
		{"999", "01", "", ""},
		{"", "", "", ""},
	})

	proxy, country, err := GetHomeMCCUpstreamProxy("234")
	if err != nil || proxy == nil || proxy.ID != "proxy-gb" || country != "GB" {
		t.Fatalf("GetHomeMCCUpstreamProxy(234) = %+v, %q, %v; want proxy-gb/GB", proxy, country, err)
	}
}

func TestHomeNetworkProxyReachesATerritoryRuleOnASharedMCC(t *testing.T) {
	openTestDBWithCountryRows(t, sharedMCCRows)
	addCountryProxy(t, "JE", "proxy-je")

	checkHomeNetworkCases(t, []homeNetworkCase{
		{"234", "50", "proxy-je", "JE"},
		// Networks known to belong elsewhere stay direct.
		{"234", "15", "", "GB"},
		{"234", "55", "", "GG"},
		// The network cannot be placed: the only rule among the countries
		// sharing the MCC applies rather than none.
		{"234", "99", "proxy-je", "JE"},
		{"234", "", "proxy-je", "JE"},
	})

	// A disabled rule is passed over like a missing one.
	if err := UpsertUpstreamProxyCountryRule(UpstreamProxyCountryRule{CountryCode: "JE", UpstreamProxyID: "proxy-je", Enabled: false}); err != nil {
		t.Fatalf("UpsertUpstreamProxyCountryRule() error=%v", err)
	}
	checkHomeNetworkCases(t, []homeNetworkCase{
		{"234", "50", "", "JE"},
		{"234", "99", "", "GB"},
	})
}

func TestHomeNetworkProxyWorksFromTheBuiltinCountryTable(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("Init() error=%v", err)
	}
	result := upstreamproxy.InitCountryTable(context.Background(), upstreamproxy.CountryTableOptions{
		CachePath:       filepath.Join(t.TempDir(), "missing", "mcc-mnc-table.json"),
		SourceURL:       "http://127.0.0.1:1/missing",
		BuiltinFallback: true,
	})
	if result.Source != upstreamproxy.CountryTableSourceBuiltin {
		t.Fatalf("InitCountryTable() source=%q, want the built-in table", result.Source)
	}
	addCountryProxy(t, "US", "proxy-us")
	addCountryProxy(t, "JE", "proxy-je")

	checkHomeNetworkCases(t, []homeNetworkCase{
		{"310", "240", "proxy-us", "US"},
		{"311", "480", "proxy-us", "US"},
		{"310", "", "proxy-us", "US"},
		// The built-in table knows no networks, so the Jersey rule is the
		// one found for any 234 network while the United Kingdom has none.
		{"234", "50", "proxy-je", "JE"},
		{"262", "01", "", "DE"},
		{"999", "01", "", ""},
	})
}
