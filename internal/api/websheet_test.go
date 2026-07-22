package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/websheet"
)

func TestRespondWebsheetErrorMapsStatuses(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{err: websheet.ErrNotFound, want: http.StatusNotFound},
		{err: websheet.ErrExpired, want: http.StatusGone},
		{err: websheet.ErrUnsafeURL, want: http.StatusBadRequest},
		{err: websheet.ErrUnauthorized, want: http.StatusUnauthorized},
		{err: errors.New("boom"), want: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		respondWebsheetError(c, tt.err)
		if rec.Code != tt.want {
			t.Fatalf("respondWebsheetError(%v)=%d want %d", tt.err, rec.Code, tt.want)
		}
	}
}

func TestWebsheetRoutesFailClosedWhenDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := &Server{}
	router := gin.New()
	api := router.Group("/api")
	server.registerWebsheetRoutes(api)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/websheets/untrusted-session", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled websheet status=%d want %d body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"websheet_disabled"`) {
		t.Fatalf("disabled websheet response missing stable code: %s", rec.Body.String())
	}
}

func TestNewRequiresExplicitWebsheetEnable(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(configPath, []byte("web: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfg := &config.Config{Web: config.WebConfig{
		Username: "admin",
		Password: "synthetic-local-password",
	}}

	disabled, err := New(cfg, nil, nil, nil, nil, nil, configPath)
	if err != nil {
		t.Fatalf("New(disabled) error = %v", err)
	}
	if disabled.websheets != nil {
		t.Fatal("New() initialized Websheet without explicit enable")
	}

	cfg.Server.WebsheetEnabled = true
	enabled, err := New(cfg, nil, nil, nil, nil, nil, configPath)
	if err != nil {
		t.Fatalf("New(enabled) error = %v", err)
	}
	if enabled.websheets == nil {
		t.Fatal("New() did not initialize explicitly enabled Websheet")
	}
}

func TestWebsheetBootstrapUsesOpaqueHandleWithoutQueryCredential(t *testing.T) {
	gin.SetMode(gin.TestMode)

	broker := websheet.New(websheet.Config{AllowPrivateHosts: true})
	session, err := broker.Create(context.Background(), websheet.Request{URL: "https://203.0.113.10/start"})
	if err != nil {
		t.Fatal(err)
	}
	info := session.Info()
	if strings.Contains(info.EmbedURL, "?") || strings.Contains(info.EmbedURL, "token") {
		t.Fatalf("EmbedURL contains a query credential: %q", info.EmbedURL)
	}

	server := &Server{websheets: broker}
	router := gin.New()
	api := router.Group("/api")
	server.registerWebsheetRoutes(api)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, info.EmbedURL, nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("opaque bootstrap status=%d want %d body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	if location := rec.Header().Get("Location"); strings.Contains(location, "token") || strings.Contains(location, "Bearer") {
		t.Fatalf("bootstrap redirect leaked a credential: %q", location)
	}
}

func TestWebsheetBootstrapUsesOpaqueSessionHandleOutsideGlobalAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	broker := websheet.New(websheet.Config{AllowPrivateHosts: true})
	session, err := broker.Create(context.Background(), websheet.Request{URL: "https://203.0.113.10/start"})
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{
		auth:      config.WebConfig{Password: "secret"},
		websheets: broker,
	}
	router := gin.New()
	api := router.Group("/api")
	server.registerWebsheetRoutes(api)
	api.Use(server.authMiddleware())
	api.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	valid := httptest.NewRecorder()
	validReq := httptest.NewRequest(http.MethodGet, session.Info().EmbedURL, nil)
	router.ServeHTTP(valid, validReq)
	if valid.Code == http.StatusUnauthorized {
		t.Fatalf("bootstrap with opaque Websheet handle returned auth 401: %s", valid.Body.String())
	}
	if valid.Code != http.StatusFound {
		t.Fatalf("bootstrap with opaque Websheet handle status=%d want %d body=%s", valid.Code, http.StatusFound, valid.Body.String())
	}

	missing := httptest.NewRecorder()
	missingReq := httptest.NewRequest(http.MethodGet, "/api/websheets/unknown-synthetic-session", nil)
	router.ServeHTTP(missing, missingReq)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown Websheet handle status=%d want %d body=%s", missing.Code, http.StatusNotFound, missing.Body.String())
	}

	protected := httptest.NewRecorder()
	protectedReq := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	router.ServeHTTP(protected, protectedReq)
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("protected route status=%d want %d", protected.Code, http.StatusUnauthorized)
	}
}

func TestWebsheetCallbackRejectsManagementBearerWithoutSessionNonce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	broker := websheet.New(websheet.Config{AllowPrivateHosts: true})
	session, err := broker.Create(context.Background(), websheet.Request{URL: "https://203.0.113.10/start"})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		auth:          config.WebConfig{Username: "admin", Password: "synthetic-password"},
		sessionSecret: bytes.Repeat([]byte{0x42}, sessionSecretSize),
		websheets:     broker,
	}
	bearer, _, err := server.issueSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api := router.Group("/api")
	server.registerWebsheetRoutes(api)

	req := httptest.NewRequest(http.MethodPost, "/api/websheets/"+session.Info().ID+"/callback", strings.NewReader(`{"source":"vowifi","event":"dismissFlow"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("management bearer callback status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), bearer) {
		t.Fatal("callback error echoed the management bearer")
	}
}

func TestWebsheetCallbackRequiresExactSessionNonce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	broker := websheet.New(websheet.Config{AllowPrivateHosts: true})
	session, err := broker.Create(context.Background(), websheet.Request{URL: "https://203.0.113.10/start"})
	if err != nil {
		t.Fatal(err)
	}
	nonce := session.Info().MessageNonce
	if nonce == "" {
		t.Fatal("Websheet message nonce is empty")
	}
	server := &Server{websheets: broker}
	router := gin.New()
	api := router.Group("/api")
	server.registerWebsheetRoutes(api)

	for _, tc := range []struct {
		name  string
		nonce string
		want  int
	}{
		{name: "missing", want: http.StatusUnauthorized},
		{name: "wrong", nonce: "wrong-synthetic-nonce", want: http.StatusUnauthorized},
		{name: "exact", nonce: nonce, want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/websheets/"+session.Info().ID+"/callback", strings.NewReader(`{"source":"vowifi","event":"dismissFlow"}`))
			req.Header.Set("Content-Type", "application/json")
			if tc.nonce != "" {
				req.Header.Set("X-Websheet-Nonce", tc.nonce)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("callback status=%d want %d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestWebsheetCallbackRejectsUnknownFieldsWithoutEcho(t *testing.T) {
	gin.SetMode(gin.TestMode)

	broker := websheet.New(websheet.Config{AllowPrivateHosts: true})
	session, err := broker.Create(context.Background(), websheet.Request{URL: "https://203.0.113.10/start"})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{websheets: broker}
	router := gin.New()
	api := router.Group("/api")
	server.registerWebsheetRoutes(api)

	const syntheticSecret = "synthetic-admin-bearer-must-not-echo"
	req := httptest.NewRequest(http.MethodPost, "/api/websheets/"+session.Info().ID+"/callback", strings.NewReader(`{"source":"vowifi","event":"dismissFlow","token":"`+syntheticSecret+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Websheet-Nonce", session.Info().MessageNonce)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown callback field status=%d want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), syntheticSecret) {
		t.Fatal("callback schema error echoed the unknown field value")
	}
}
func TestWebsheetCallbackMarksTerminalSessionDone(t *testing.T) {
	gin.SetMode(gin.TestMode)

	broker := websheet.New(websheet.Config{AllowPrivateHosts: true})
	session, err := broker.Create(context.Background(), websheet.Request{URL: "https://203.0.113.10/start"})
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{websheets: broker}
	router := gin.New()
	api := router.Group("/api")
	server.registerWebsheetRoutes(api)

	req := httptest.NewRequest(http.MethodPost, "/api/websheets/"+session.Info().ID+"/callback", strings.NewReader(`{
		"source":"vowifi",
		"event":"entitlementChanged",
		"method":"e911AddressValidated",
		"resultCode":"success"
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Websheet-Nonce", session.Info().MessageNonce)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", rec.Code, rec.Body.String())
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := session.WaitDone(waitCtx); err != nil {
		t.Fatalf("session was not marked done after terminal callback: %v", err)
	}
}
