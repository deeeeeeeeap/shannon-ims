package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
	"github.com/gin-gonic/gin"
)

func TestSystemUninstallRequiresAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var uninstallCalled atomic.Bool
	server := newProtectedSystemRouteTestServer(&uninstallCalled)

	req := httptest.NewRequest(http.MethodPost, "/api/system/uninstall", nil)
	recorder := httptest.NewRecorder()
	server.newRouter().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed uninstall status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if uninstallCalled.Load() {
		t.Fatal("unauthed uninstall invoked destructive runner")
	}
}

func TestSystemUninstallRequiresExplicitConfirmation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var uninstallCalled atomic.Bool
	server := newProtectedSystemRouteTestServer(&uninstallCalled)
	router := server.newRouter()
	token := loginProtectedSystemRouteTest(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/system/uninstall", bytes.NewBufferString(`{}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed uninstall status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if uninstallCalled.Load() {
		t.Fatal("unconfirmed uninstall invoked destructive runner")
	}
}

func TestSystemUninstallRejectsAuthenticatedRemoteRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var uninstallCalled atomic.Bool
	server := newProtectedSystemRouteTestServer(&uninstallCalled)
	router := server.newRouter()
	token := loginProtectedSystemRouteTest(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/system/uninstall", bytes.NewBufferString(`{"confirm":"UNINSTALL"}`))
	req.RemoteAddr = "198.51.100.10:4321"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("remote uninstall status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if uninstallCalled.Load() {
		t.Fatal("remote uninstall invoked destructive runner")
	}
}

func TestSystemUninstallRunsAfterAuthenticatedConfirmation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var uninstallCalled atomic.Bool
	server := newProtectedSystemRouteTestServer(&uninstallCalled)
	router := server.newRouter()
	token := loginProtectedSystemRouteTest(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/system/uninstall", bytes.NewBufferString(`{"confirm":"UNINSTALL"}`))
	req.RemoteAddr = "[::1]:1234"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("confirmed uninstall status = %d, want %d", recorder.Code, http.StatusAccepted)
	}
	deadline := time.Now().Add(time.Second)
	for !uninstallCalled.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !uninstallCalled.Load() {
		t.Fatal("confirmed uninstall did not invoke runner")
	}
}

func newProtectedSystemRouteTestServer(called *atomic.Bool) *Server {
	return &Server{
		auth:          config.WebConfig{Username: "admin", Password: "test-password"},
		sessionSecret: bytes.Repeat([]byte{0x5a}, sessionSecretSize),
		loginAttempts: make(map[string]loginAttempt),
		shutdownCh:    make(chan struct{}),
		uninstallRunner: func() {
			called.Store(true)
		},
	}
}

func loginProtectedSystemRouteTest(t *testing.T, router http.Handler) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(`{"username":"admin","password":"test-password"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if payload.Token == "" {
		t.Fatal("login response token is empty")
	}
	return payload.Token
}
