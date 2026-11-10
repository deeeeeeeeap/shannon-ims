package device

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/internal/upstreamproxy"
	"github.com/1239t/vowifi-go/runtimehost"
	"github.com/1239t/vowifi-go/runtimehost/transport/socks5sim"
)

// The proxy part of a VoWiFi start, run against a simulated SOCKS5 proxy.

const (
	probeTestDevice   = "dev-probe"
	probeTestUser     = "sim-user"
	probeTestPassword = "sim-pass"
)

func startProbeTestProxy(t *testing.T) *socks5sim.Server {
	t.Helper()
	srv, err := socks5sim.Start(socks5sim.Config{
		Auth: socks5sim.AuthUserPass, Username: probeTestUser, Password: probeTestPassword,
	})
	if err != nil {
		t.Fatalf("start simulated proxy: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

// useFastProxyProbeRetry keeps the number of attempts and removes the waits
// between them.
func useFastProxyProbeRetry(t *testing.T) {
	t.Helper()
	previous := voWiFiProxyProbeRetry
	voWiFiProxyProbeRetry = upstreamproxy.ProbeRetryPolicy{Attempts: 3, Backoff: time.Millisecond}
	t.Cleanup(func() { voWiFiProxyProbeRetry = previous })
}

// startingPool returns a pool whose test device is being started, which is
// when the startup state is recorded.
func startingPool(t *testing.T) *Pool {
	t.Helper()
	pool := &Pool{}
	if claim := pool.voWiFiHost().BeginStart(probeTestDevice); !claim.Accepted {
		t.Fatalf("BeginStart() = %+v, want accepted", claim)
	}
	return pool
}

func runBeforeVoWiFiStart(pool *Pool, proxy *runtimehost.ProxyConfig) error {
	hook := pool.beforeVoWiFiStart(probeTestDevice, vowifiIdentityTestModem{}, proxy)
	return hook(context.Background(), runtimehost.SessionConfig{DeviceID: probeTestDevice, DataplaneMode: "userspace"})
}

func probeTestProxyConfig(sim *socks5sim.Server) *runtimehost.ProxyConfig {
	return &runtimehost.ProxyConfig{
		ID: "proxy-sim", Addr: sim.Addr(), Username: probeTestUser, Password: probeTestPassword, Enabled: true,
	}
}

func startupStateOf(t *testing.T, pool *Pool) runtimehost.State {
	t.Helper()
	state, ok := pool.GetVoWiFiRuntimeState(probeTestDevice)
	if !ok {
		t.Fatal("no startup state was recorded")
	}
	return state
}

func TestBeforeVoWiFiStartAcceptsAWorkingProxy(t *testing.T) {
	useFastProxyProbeRetry(t)
	sim := startProbeTestProxy(t)
	pool := startingPool(t)

	if err := runBeforeVoWiFiStart(pool, probeTestProxyConfig(sim)); err != nil {
		t.Fatalf("beforeVoWiFiStart() error=%v", err)
	}
	if got := sim.Stats().Connections; got != 1 {
		t.Fatalf("the proxy saw %d connections, want one probe", got)
	}
	if state := startupStateOf(t, pool); state.LastErrorClass != "" || state.LastError != "" {
		t.Fatalf("startup state reports an error after a clean probe: %+v", state)
	}
}

func TestBeforeVoWiFiStartRidesOutAProxyRestart(t *testing.T) {
	useFastProxyProbeRetry(t)
	sim := startProbeTestProxy(t)
	sim.SetFaults(func(f *socks5sim.Faults) { f.DropConnections = 2 })
	pool := startingPool(t)

	if err := runBeforeVoWiFiStart(pool, probeTestProxyConfig(sim)); err != nil {
		t.Fatalf("beforeVoWiFiStart() error=%v, want the start to continue once the proxy answers", err)
	}
	if got := sim.Stats().Connections; got != 3 {
		t.Fatalf("the proxy saw %d connections, want two dropped and one served", got)
	}
	if state := startupStateOf(t, pool); state.LastErrorClass != "" {
		t.Fatalf("startup state keeps an error from an attempt that was retried: %+v", state)
	}
}

func TestBeforeVoWiFiStartFailsWhenTheProxyStaysDown(t *testing.T) {
	useFastProxyProbeRetry(t)
	sim := startProbeTestProxy(t)
	sim.SetFaults(func(f *socks5sim.Faults) { f.DropConnections = 1000 })
	pool := startingPool(t)

	err := runBeforeVoWiFiStart(pool, probeTestProxyConfig(sim))
	if err == nil || !strings.Contains(err.Error(), "前置代理自检失败") {
		t.Fatalf("beforeVoWiFiStart() error=%v, want the proxy self-check failure", err)
	}
	if got := sim.Stats().Connections; got != 3 {
		t.Fatalf("the proxy saw %d connections, want the three attempts and no more", got)
	}
	state := startupStateOf(t, pool)
	if state.LastErrorClass != "proxy" || state.LastError == "" {
		t.Fatalf("startup state = %+v, want a proxy error", state)
	}
	if !strings.Contains(state.LastReason, "代理在 SOCKS5 握手阶段直接断开了连接") {
		t.Fatalf("LastReason=%q, want the diagnosis of the last attempt", state.LastReason)
	}
}

func TestBeforeVoWiFiStartDoesNotRetryRejectedCredentials(t *testing.T) {
	useFastProxyProbeRetry(t)
	sim := startProbeTestProxy(t)
	pool := startingPool(t)
	proxy := probeTestProxyConfig(sim)
	proxy.Password = "not-the-password"

	err := runBeforeVoWiFiStart(pool, proxy)
	if err == nil {
		t.Fatal("beforeVoWiFiStart() passed with a wrong password")
	}
	if got := sim.Stats().Connections; got != 1 {
		t.Fatalf("the proxy saw %d connections, want a single attempt", got)
	}
	state := startupStateOf(t, pool)
	if state.LastErrorClass != "proxy" || !strings.Contains(state.LastReason, "代理用户名或密码错误") {
		t.Fatalf("startup state = %+v, want the credentials diagnosis", state)
	}
	for _, text := range []string{err.Error(), state.LastError, state.LastReason} {
		if strings.Contains(text, proxy.Password) || strings.Contains(text, probeTestPassword) {
			t.Fatalf("a password appears in %q", text)
		}
	}
}

func TestBeforeVoWiFiStartSkipsTheProbeWithoutAProxy(t *testing.T) {
	useFastProxyProbeRetry(t)
	sim := startProbeTestProxy(t)
	disabled := probeTestProxyConfig(sim)
	disabled.Enabled = false
	noAddress := probeTestProxyConfig(sim)
	noAddress.Addr = "  "

	for name, proxy := range map[string]*runtimehost.ProxyConfig{
		"direct route":    nil,
		"disabled proxy":  disabled,
		"proxy sans addr": noAddress,
	} {
		if err := runBeforeVoWiFiStart(startingPool(t), proxy); err != nil {
			t.Fatalf("%s: beforeVoWiFiStart() error=%v", name, err)
		}
	}
	if got := sim.Stats().Connections; got != 0 {
		t.Fatalf("the proxy saw %d connections, want none", got)
	}
}

func TestResolveVoWiFiHomeNetworkProxyPlacesTheNetworkByItsMNC(t *testing.T) {
	openDeviceTestDB(t)
	cachePath := filepath.Join(t.TempDir(), "mcc-mnc-table.json")
	rows := `[
	  {"mcc":"234","mnc":"10","iso":"gb","country":"United Kingdom"},
	  {"mcc":"234","mnc":"15","iso":"gb","country":"United Kingdom"},
	  {"mcc":"234","mnc":"50","iso":"je","country":"Jersey"}
	]`
	if err := os.WriteFile(cachePath, []byte(rows), 0o644); err != nil {
		t.Fatalf("WriteFile() error=%v", err)
	}
	if result := upstreamproxy.InitCountryTable(context.Background(), upstreamproxy.CountryTableOptions{CachePath: cachePath}); result.Err != nil {
		t.Fatalf("InitCountryTable() error=%v", result.Err)
	}
	for country, id := range map[string]string{"GB": "proxy-gb", "JE": "proxy-je"} {
		if err := db.UpsertUpstreamProxy(db.UpstreamProxy{
			ID: id, Addr: "127.0.0.1:1080", Username: "user-" + id, Password: "secret-" + id, Enabled: true,
		}); err != nil {
			t.Fatalf("UpsertUpstreamProxy(%s) error=%v", id, err)
		}
		if err := db.UpsertUpstreamProxyCountryRule(db.UpstreamProxyCountryRule{CountryCode: country, UpstreamProxyID: id, Enabled: true}); err != nil {
			t.Fatalf("UpsertUpstreamProxyCountryRule(%s) error=%v", country, err)
		}
	}

	for _, tc := range []struct{ mcc, mnc, want string }{
		{"234", "15", "proxy-gb"},
		{"234", "50", "proxy-je"},
		{"234", "99", "proxy-gb"},
		{"234", "", "proxy-gb"},
	} {
		got := resolveVoWiFiHomeNetworkProxy(tc.mcc, tc.mnc, "trace-1", "dev-1")
		if got == nil || got.ID != tc.want || !got.Enabled {
			t.Fatalf("resolveVoWiFiHomeNetworkProxy(%s, %s)=%+v, want %s", tc.mcc, tc.mnc, got, tc.want)
		}
		if got.Username != "user-"+tc.want || got.Password != "secret-"+tc.want || got.Addr != "127.0.0.1:1080" {
			t.Fatalf("resolveVoWiFiHomeNetworkProxy(%s, %s) lost the proxy's settings: %+v", tc.mcc, tc.mnc, got.ID)
		}
	}
	if got := resolveVoWiFiHomeNetworkProxy("999", "01", "trace-1", "dev-1"); got != nil {
		t.Fatalf("resolveVoWiFiHomeNetworkProxy(999, 01)=%+v, want a direct route", got.ID)
	}
	// The MCC-only entry point still answers, with the main country.
	if got := resolveVoWiFiCountryProxy("234", "trace-1", "dev-1"); got == nil || got.ID != "proxy-gb" {
		t.Fatalf("resolveVoWiFiCountryProxy(234) did not select proxy-gb")
	}
}
