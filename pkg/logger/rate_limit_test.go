package logger

import (
	"testing"
	"time"
)

func TestShouldEmitRateLimited(t *testing.T) {
	resetRateLimiterForTest()

	key := "device-a:register-failed"
	window := 50 * time.Millisecond

	if !shouldEmitRateLimited("warn", key, window) {
		t.Fatalf("first emit should pass")
	}
	if shouldEmitRateLimited("warn", key, window) {
		t.Fatalf("second emit in window should be suppressed")
	}

	time.Sleep(window + 20*time.Millisecond)
	if !shouldEmitRateLimited("warn", key, window) {
		t.Fatalf("emit after window should pass")
	}
}

func TestShouldEmitRateLimitedKeyIsolation(t *testing.T) {
	resetRateLimiterForTest()

	window := time.Second
	if !shouldEmitRateLimited("warn", "k1", window) {
		t.Fatalf("k1 first should pass")
	}
	if !shouldEmitRateLimited("warn", "k2", window) {
		t.Fatalf("k2 first should pass")
	}
	if shouldEmitRateLimited("warn", "k1", window) {
		t.Fatalf("k1 second should be suppressed")
	}
	if shouldEmitRateLimited("warn", "k2", window) {
		t.Fatalf("k2 second should be suppressed")
	}
}
