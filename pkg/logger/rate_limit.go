package logger

import (
	"strings"
	"sync"
	"time"
)

var rateLimiterState = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{
	last: make(map[string]time.Time, 256),
}

// WarnRate 在同一个 key+window 内最多输出一次 Warn 日志。
func WarnRate(key string, window time.Duration, msg string, args ...interface{}) {
	if shouldEmitRateLimited("warn", key, window) {
		Warn(msg, args...)
	}
}

// InfoRate 在同一个 key+window 内最多输出一次 Info 日志。
func InfoRate(key string, window time.Duration, msg string, args ...interface{}) {
	if shouldEmitRateLimited("info", key, window) {
		Info(msg, args...)
	}
}

func shouldEmitRateLimited(level, key string, window time.Duration) bool {
	level = strings.TrimSpace(strings.ToLower(level))
	key = strings.TrimSpace(key)
	if level == "" || key == "" || window <= 0 {
		return true
	}
	now := time.Now()
	fullKey := level + "|" + key

	rateLimiterState.mu.Lock()
	defer rateLimiterState.mu.Unlock()

	if last, ok := rateLimiterState.last[fullKey]; ok && now.Sub(last) < window {
		return false
	}

	rateLimiterState.last[fullKey] = now
	if len(rateLimiterState.last) > 4096 {
		cutoff := now.Add(-24 * time.Hour)
		for k, at := range rateLimiterState.last {
			if at.Before(cutoff) {
				delete(rateLimiterState.last, k)
			}
		}
	}

	return true
}

func resetRateLimiterForTest() {
	rateLimiterState.mu.Lock()
	clear(rateLimiterState.last)
	rateLimiterState.mu.Unlock()
}
