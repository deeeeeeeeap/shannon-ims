package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1239t/vohive/internal/db"
	"github.com/gin-gonic/gin"
)

func TestNormalizeUpstreamProxyPayloadPreservesExistingPasswordWhenOmitted(t *testing.T) {
	existing := &db.UpstreamProxy{Password: "synthetic-existing-password"}
	got := normalizeUpstreamProxyPayload(existing, db.UpstreamProxy{Password: ""})
	if got.Password != existing.Password {
		t.Fatal("existing upstream proxy password was not preserved")
	}
}

func TestListUpstreamProxiesReportsPasswordStateWithoutPassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	if err := db.Init(filepath.Join(t.TempDir(), "upstream-proxy.db")); err != nil {
		t.Fatalf("db.Init() error=%v", err)
	}
	t.Cleanup(func() { db.DB = nil })
	if err := db.UpsertUpstreamProxy(db.UpstreamProxy{
		ID:       "upstream-synthetic",
		Addr:     "127.0.0.1:1080",
		Username: "synthetic-user",
		Password: "synthetic-existing-password",
		Enabled:  true,
	}); err != nil {
		t.Fatalf("UpsertUpstreamProxy() error=%v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/upstream-proxies", nil)
	(&Server{}).handleListUpstreamProxies(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET upstream proxies status=%d want %d", rec.Code, http.StatusOK)
	}
	var payload []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode upstream proxy response: %v", err)
	}
	if len(payload) != 1 {
		t.Fatalf("upstream proxy count=%d want 1", len(payload))
	}
	if _, exists := payload[0]["password"]; exists {
		t.Fatal("GET upstream proxies returned a password field")
	}
	if payload[0]["password_set"] != true {
		t.Fatal("GET upstream proxies did not report password_set=true")
	}
	if strings.Contains(rec.Body.String(), "synthetic-existing-password") {
		t.Fatal("GET upstream proxies exposed the stored password")
	}
}
