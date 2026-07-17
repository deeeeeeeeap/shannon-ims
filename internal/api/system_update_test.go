package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestApplyUpdateReturnsServiceUnavailableWhenDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var uninstallCalled atomic.Bool
	server := newProtectedSystemRouteTestServer(&uninstallCalled)
	router := server.newRouter()
	token := loginProtectedSystemRouteTest(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/system/update/apply", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled update status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode disabled update response: %v", err)
	}
	if payload.Code != "automatic_update_disabled" {
		t.Fatalf("disabled update code = %q, want automatic_update_disabled", payload.Code)
	}
}

func TestCheckUpdateReportsFailClosedStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var uninstallCalled atomic.Bool
	server := newProtectedSystemRouteTestServer(&uninstallCalled)
	router := server.newRouter()
	token := loginProtectedSystemRouteTest(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/system/update/check", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("disabled update check status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var payload struct {
		Enabled   bool   `json:"enabled"`
		HasUpdate bool   `json:"has_update"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode update check response: %v", err)
	}
	if payload.Enabled || payload.HasUpdate {
		t.Fatalf("update check = enabled:%v has_update:%v, want fail-closed", payload.Enabled, payload.HasUpdate)
	}
	if payload.Reason == "" {
		t.Fatal("disabled update check is missing a reason")
	}
}
