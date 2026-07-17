package api

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
	"github.com/gin-gonic/gin"
)

func TestLoginRateLimitIgnoresSpoofedForwardedAddresses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{
		auth:          config.WebConfig{Username: "admin", Password: "test-password"},
		sessionSecret: bytes.Repeat([]byte{0x5a}, sessionSecretSize),
		loginLimiter:  newLoginRateLimiter(0, 0, 0),
		shutdownCh:    make(chan struct{}),
	}
	router := server.newRouter()

	for attempt := 1; attempt <= 11; attempt++ {
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/auth/login",
			bytes.NewBufferString(`{"username":"admin","password":"wrong-password"}`),
		)
		req.RemoteAddr = "198.51.100.20:4321"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", attempt))
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		want := http.StatusUnauthorized
		if attempt == 11 {
			want = http.StatusTooManyRequests
		}
		if recorder.Code != want {
			t.Fatalf("attempt %d status = %d, want %d", attempt, recorder.Code, want)
		}
	}
}

func TestRouterDoesNotTrustForwardedHeadersByDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := (&Server{shutdownCh: make(chan struct{})}).newRouter()
	router.GET("/test/client-ip", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})

	req := httptest.NewRequest(http.MethodGet, "/test/client-ip", nil)
	req.RemoteAddr = "198.51.100.20:4321"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Body.String(); got != "198.51.100.20" {
		t.Fatalf("ClientIP() = %q, want direct TCP peer", got)
	}
}

func TestLoginRateLimiterPrunesExpiredEntries(t *testing.T) {
	limiter := newLoginRateLimiter(time.Minute, 10, 3)
	now := time.Unix(1_700_000_000, 0)
	for _, peer := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if !limiter.Allow(peer, now) {
			t.Fatalf("Allow(%q) = false, want true", peer)
		}
	}
	if got := limiter.Len(); got != 3 {
		t.Fatalf("Len() = %d, want 3", got)
	}

	if !limiter.Allow("192.0.2.4", now.Add(2*time.Minute)) {
		t.Fatal("Allow(new peer after TTL) = false, want true")
	}
	if got := limiter.Len(); got != 1 {
		t.Fatalf("Len() after TTL cleanup = %d, want 1", got)
	}
}

func TestLoginRateLimiterCapsDistinctPeers(t *testing.T) {
	limiter := newLoginRateLimiter(time.Minute, 10, 2)
	now := time.Unix(1_700_000_000, 0)
	if !limiter.Allow("192.0.2.1", now) || !limiter.Allow("192.0.2.2", now) {
		t.Fatal("initial peers were unexpectedly rejected")
	}
	if limiter.Allow("192.0.2.3", now) {
		t.Fatal("Allow() accepted a new peer beyond the hard capacity")
	}
	if got := limiter.Len(); got != 2 {
		t.Fatalf("Len() = %d, want hard cap 2", got)
	}
}

func TestLoginRateLimiterConcurrentCapacityIsBounded(t *testing.T) {
	const capacity = 16
	limiter := newLoginRateLimiter(time.Minute, 10, capacity)
	now := time.Unix(1_700_000_000, 0)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func(peer int) {
			defer wg.Done()
			if limiter.Allow(fmt.Sprintf("192.0.2.%d", peer), now) {
				accepted.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if got := limiter.Len(); got != capacity {
		t.Fatalf("Len() = %d, want hard cap %d", got, capacity)
	}
	if got := accepted.Load(); got != capacity {
		t.Fatalf("accepted = %d, want %d", got, capacity)
	}
}
