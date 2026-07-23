package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/device"
)

func TestLivenessEndpointReportsOnlyProcessState(t *testing.T) {
	server := &Server{
		pool:       device.NewPool(&config.Config{}),
		shutdownCh: make(chan struct{}),
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/livez", nil)

	server.newRouter().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode liveness response: %v", err)
	}
	if len(body) != 1 || body["status"] != "alive" {
		t.Fatalf("body=%v, want only process liveness status", body)
	}
}

func TestReadinessEndpointFailsClosedWhilePoolInitializes(t *testing.T) {
	server := &Server{
		pool:       device.NewPool(&config.Config{}),
		shutdownCh: make(chan struct{}),
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)

	server.newRouter().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want %d; body=%s", recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}
	var body device.ReadinessSnapshot
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode readiness response: %v", err)
	}
	if body.Ready || body.Initialized || body.Reason != "initializing" {
		t.Fatalf("body=%+v, want initializing fail-closed snapshot", body)
	}
}
