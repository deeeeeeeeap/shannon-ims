package api

import (
	"strings"
	"sync"
	"time"
)

const (
	defaultLoginRateLimitWindow   = 2 * time.Minute
	defaultLoginRateLimitAttempts = 10
	defaultLoginRateLimitCapacity = 4096
)

type loginAttempt struct {
	Count   int
	ResetAt time.Time
}

type loginRateLimiter struct {
	mu         sync.Mutex
	entries    map[string]loginAttempt
	window     time.Duration
	limit      int
	maxEntries int
}

func newLoginRateLimiter(window time.Duration, limit, maxEntries int) *loginRateLimiter {
	if window <= 0 {
		window = defaultLoginRateLimitWindow
	}
	if limit <= 0 {
		limit = defaultLoginRateLimitAttempts
	}
	if maxEntries <= 0 {
		maxEntries = defaultLoginRateLimitCapacity
	}
	return &loginRateLimiter{
		entries:    make(map[string]loginAttempt),
		window:     window,
		limit:      limit,
		maxEntries: maxEntries,
	}
}

func (l *loginRateLimiter) Allow(peer string, now time.Time) bool {
	if l == nil {
		return false
	}
	peer = strings.TrimSpace(peer)
	if peer == "" {
		peer = "unknown"
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	for key, attempt := range l.entries {
		if !now.Before(attempt.ResetAt) {
			delete(l.entries, key)
		}
	}

	cur, exists := l.entries[peer]
	if !exists {
		if len(l.entries) >= l.maxEntries {
			return false
		}
		cur = loginAttempt{ResetAt: now.Add(l.window)}
	}
	if cur.Count >= l.limit {
		return false
	}
	cur.Count++
	l.entries[peer] = cur
	return true
}

func (l *loginRateLimiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
