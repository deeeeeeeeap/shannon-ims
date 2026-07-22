package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/data/repo"
	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/internal/device"

	"github.com/gin-gonic/gin"
)

type staticProxyInstanceRepo struct {
	instances []config.ProxyInstance
}

func (r staticProxyInstanceRepo) List(context.Context) ([]config.ProxyInstance, error) {
	out := append([]config.ProxyInstance(nil), r.instances...)
	return out, nil
}

func (r staticProxyInstanceRepo) Get(_ context.Context, id string) (*config.ProxyInstance, error) {
	for _, inst := range r.instances {
		if inst.ID == id {
			instCopy := inst
			return &instCopy, nil
		}
	}
	return nil, nil
}

func (r staticProxyInstanceRepo) ReplaceAll(_ context.Context, instances []config.ProxyInstance) error {
	r.instances = append([]config.ProxyInstance(nil), instances...)
	return nil
}

func TestProxyInstanceGetReportsPasswordStateWithoutPassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{
		proxyRepo: staticProxyInstanceRepo{instances: []config.ProxyInstance{{
			ID:          "proxy-synthetic",
			DeviceID:    "device-synthetic",
			ListenPort:  1080,
			AuthEnabled: true,
			Username:    "synthetic-user",
			Password:    "synthetic-existing-password",
		}}},
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Params = gin.Params{{Key: "instance_id", Value: "proxy-synthetic"}}
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/proxy-instances/proxy-synthetic", nil)
	server.handleProxyInstanceGet(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET proxy instance status=%d want %d", rec.Code, http.StatusOK)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode proxy instance response: %v", err)
	}
	if _, exists := payload["password"]; exists {
		t.Fatal("GET proxy instance returned a password field")
	}
	if payload["password_set"] != true {
		t.Fatal("GET proxy instance did not report password_set=true")
	}
	if strings.Contains(rec.Body.String(), "synthetic-existing-password") {
		t.Fatal("GET proxy instance exposed the stored password")
	}
}

func initProxyTestConfig(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := config.InitGlobalManager(path); err != nil {
		t.Fatalf("InitGlobalManager() error = %v", err)
	}
}

func TestNormalizeProxyInstanceForSaveValidation(t *testing.T) {
	_, err := normalizeProxyInstanceForSave(config.ProxyInstance{
		ID:         "inst-1",
		DeviceID:   "",
		ListenAddr: "0.0.0.0",
		ListenPort: 1080,
	}, nil)
	if err == nil {
		t.Fatalf("expected device_id validation error")
	}

	_, err = normalizeProxyInstanceForSave(config.ProxyInstance{
		ID:          "inst-2",
		DeviceID:    "dev-1",
		ListenAddr:  "0.0.0.0",
		ListenPort:  1080,
		Mode:        "socks5",
		AuthEnabled: true,
		Username:    "",
		Password:    "pass",
	}, nil)
	if err == nil {
		t.Fatalf("expected auth credential validation error")
	}

	_, err = normalizeProxyInstanceForSave(config.ProxyInstance{
		ID:         "inst-3",
		DeviceID:   "dev-1",
		ListenAddr: "0.0.0.0",
		ListenPort: 8080,
		Mode:       "ftp",
	}, nil)
	if err == nil {
		t.Fatalf("expected mode validation error")
	}
}

func TestNormalizeProxyInstanceForSaveAuthOffClearsCredentials(t *testing.T) {
	out, err := normalizeProxyInstanceForSave(config.ProxyInstance{
		ID:          "inst-1",
		DeviceID:    "dev-1",
		ListenAddr:  "",
		ListenPort:  1080,
		Mode:        "",
		AuthEnabled: false,
		Username:    "abc",
		Password:    "def",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.ListenAddr != "127.0.0.1" {
		t.Fatalf("listen_addr default mismatch: got=%q want=127.0.0.1", out.ListenAddr)
	}
	if out.Mode != "socks5" {
		t.Fatalf("mode default mismatch: got=%q want=socks5", out.Mode)
	}
	if out.Username != "" || out.Password != "" {
		t.Fatalf("expected credentials cleared when auth disabled")
	}
}

func TestNormalizeProxyInstanceForSavePreservesExistingPasswordWhenOmittedOrLegacyMasked(t *testing.T) {
	for _, tt := range []struct {
		name     string
		password string
	}{
		{name: "omitted", password: ""},
		{name: "legacy masked", password: "******"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old := &config.ProxyInstance{Password: "secret-pass"}
			out, err := normalizeProxyInstanceForSave(config.ProxyInstance{
				ID:          "inst-1",
				DeviceID:    "dev-1",
				ListenAddr:  "0.0.0.0",
				ListenPort:  1080,
				Mode:        "http",
				AuthEnabled: true,
				Username:    "user",
				Password:    tt.password,
			}, old)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if out.Password != "secret-pass" {
				t.Fatal("existing password was not preserved")
			}
		})
	}
}

func TestProxyUpdateWarnsOnExplicitLANExposure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{proxyRepo: staticProxyInstanceRepo{}}
	body := `{"instances":[{
		"id":"proxy-lan",
		"device_id":"device-synthetic",
		"enabled":false,
		"mode":"socks5",
		"listen_addr":"0.0.0.0",
		"listen_port":1080,
		"auth_enabled":false
	}]}`

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/proxy-instances/config", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	server.handleProxyUpdateConfig(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT proxy config status=%d want %d", rec.Code, http.StatusOK)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode proxy update response: %v", err)
	}
	warning, _ := payload["warning"].(string)
	if !strings.Contains(warning, "defaults to 127.0.0.1") ||
		!strings.Contains(warning, "explicit") ||
		!strings.Contains(warning, "LAN exposure is enabled") {
		t.Fatal("explicit LAN exposure response lacked a clear loopback/LAN warning")
	}
	if strings.Contains(warning, "???") {
		t.Fatal("explicit LAN exposure response contained a corrupted warning")
	}
}

func TestProxyOverviewReadsInstancesFromDatabaseAcrossServerInstances(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "proxy_overview.db")
	if err := db.Init(dbPath); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	t.Cleanup(func() {
		db.DB = nil
	})

	saveServer := &Server{
		fullCfg:      &config.Config{},
		proxyRepo:    repo.NewDBRepo(),
		loginLimiter: newLoginRateLimiter(0, 0, 0),
	}

	body := `{"instances":[{"id":"proxy-db-1","name":"DB Proxy","device_id":"dev-1","enabled":true,"mode":"socks5","listen_addr":"127.0.0.1","listen_port":10800,"auth_enabled":false}]}`
	saveRecorder := httptest.NewRecorder()
	saveCtx, _ := gin.CreateTestContext(saveRecorder)
	saveCtx.Request = httptest.NewRequest(http.MethodPut, "/api/proxy-instances/config", strings.NewReader(body))
	saveCtx.Request.Header.Set("Content-Type", "application/json")

	saveServer.handleProxyUpdateConfig(saveCtx)

	if saveRecorder.Code != http.StatusOK {
		t.Fatalf("save status code mismatch: got=%d want=%d body=%s", saveRecorder.Code, http.StatusOK, saveRecorder.Body.String())
	}

	overviewServer := &Server{
		fullCfg:      &config.Config{},
		proxyRepo:    repo.NewDBRepo(),
		loginLimiter: newLoginRateLimiter(0, 0, 0),
	}

	overviewRecorder := httptest.NewRecorder()
	overviewCtx, _ := gin.CreateTestContext(overviewRecorder)
	overviewCtx.Request = httptest.NewRequest(http.MethodGet, "/api/proxy-instances/overview", nil)

	overviewServer.handleProxyOverview(overviewCtx)

	if overviewRecorder.Code != http.StatusOK {
		t.Fatalf("overview status code mismatch: got=%d want=%d body=%s", overviewRecorder.Code, http.StatusOK, overviewRecorder.Body.String())
	}

	var payload struct {
		Instances []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			DeviceID   string `json:"device_id"`
			ListenPort int    `json:"listen_port"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(overviewRecorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal overview response failed: %v", err)
	}
	if len(payload.Instances) != 1 {
		t.Fatalf("instances count mismatch: got=%d want=1", len(payload.Instances))
	}
	inst := payload.Instances[0]
	if inst.ID != "proxy-db-1" || inst.Name != "DB Proxy" || inst.DeviceID != "dev-1" || inst.ListenPort != 10800 {
		t.Fatalf("unexpected instance payload: %+v", inst)
	}
}

func TestBuildProxyConfigsAllowsInterfaceWithoutGlobalIPv4(t *testing.T) {
	initProxyTestConfig(t, `devices:
  - id: dev-lo
    name: Loopback
`)
	// 零路径架构: interface 由运行时解析并存在 worker.Config.Interface 里,不从文件读取。
	p := device.NewPool(&config.Config{})
	setNestedPrivateField(t, p, []string{"workers"}, map[string]*device.Worker{
		"dev-lo": {ID: "dev-lo", Config: config.DeviceConfig{ID: "dev-lo", Interface: "lo"}},
	})
	s := &Server{
		pool: p,
		proxyRepo: staticProxyInstanceRepo{instances: []config.ProxyInstance{
			{
				ID:         "proxy-lo",
				DeviceID:   "dev-lo",
				Enabled:    true,
				Mode:       "socks5",
				ListenAddr: "127.0.0.1",
				ListenPort: 10801,
			},
		}},
	}

	cfgs, err := s.buildProxyConfigs(context.Background())
	if err != nil {
		t.Fatalf("buildProxyConfigs() error = %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("config count mismatch: got=%d want=1", len(cfgs))
	}
	if cfgs[0].Interface != "lo" {
		t.Fatalf("interface mismatch: got=%q want=lo", cfgs[0].Interface)
	}
}

func TestBuildProxyConfigsDefaultsEmptyListenAddressToLoopback(t *testing.T) {
	initProxyTestConfig(t, `devices:
  - id: dev-loopback-default
    name: Loopback Default
`)
	pool := device.NewPool(&config.Config{})
	setNestedPrivateField(t, pool, []string{"workers"}, map[string]*device.Worker{
		"dev-loopback-default": {
			ID: "dev-loopback-default",
			Config: config.DeviceConfig{
				ID:        "dev-loopback-default",
				Interface: "lo",
			},
		},
	})
	server := &Server{
		pool: pool,
		proxyRepo: staticProxyInstanceRepo{instances: []config.ProxyInstance{{
			ID:         "proxy-loopback-default",
			DeviceID:   "dev-loopback-default",
			Enabled:    true,
			Mode:       "socks5",
			ListenAddr: "",
			ListenPort: 10803,
		}}},
	}

	cfgs, err := server.buildProxyConfigs(context.Background())
	if err != nil {
		t.Fatalf("buildProxyConfigs() error=%v", err)
	}
	if len(cfgs) != 1 || cfgs[0].ListenAddr != "127.0.0.1" {
		t.Fatalf("runtime listen_addr=%q want=127.0.0.1", cfgs[0].ListenAddr)
	}
}

func TestBuildProxyConfigsAllowsMissingRuntimeInterface(t *testing.T) {
	const missingIface = "vohive-missing-proxy-iface"
	initProxyTestConfig(t, `devices:
  - id: dev-missing
    name: Missing Interface
`)
	// 零路径架构: interface 由运行时解析并存在 worker.Config.Interface 里,不从文件读取。
	// 即使接口不存在于系统(如测试环境),buildProxyConfigs 只需能查到 interface 名即可。
	p := device.NewPool(&config.Config{})
	setNestedPrivateField(t, p, []string{"workers"}, map[string]*device.Worker{
		"dev-missing": {ID: "dev-missing", Config: config.DeviceConfig{ID: "dev-missing", Interface: missingIface}},
	})
	s := &Server{
		pool: p,
		proxyRepo: staticProxyInstanceRepo{instances: []config.ProxyInstance{
			{
				ID:         "proxy-missing-iface",
				DeviceID:   "dev-missing",
				Enabled:    true,
				Mode:       "http",
				ListenAddr: "127.0.0.1",
				ListenPort: 10802,
			},
		}},
	}

	cfgs, err := s.buildProxyConfigs(context.Background())
	if err != nil {
		t.Fatalf("buildProxyConfigs() error = %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("config count mismatch: got=%d want=1", len(cfgs))
	}
	if cfgs[0].Interface != missingIface {
		t.Fatalf("interface mismatch: got=%q want=%s", cfgs[0].Interface, missingIface)
	}
}
