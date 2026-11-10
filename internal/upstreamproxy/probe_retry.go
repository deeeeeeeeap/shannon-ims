package upstreamproxy

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/transport"
)

// ProbeRetryPolicy bounds how ProbeSOCKS5WithRetry repeats a probe. Zero
// fields select the defaults.
type ProbeRetryPolicy struct {
	// Attempts is the total number of probes, the first included.
	Attempts int
	// Backoff is the wait before the second probe. It doubles for every
	// further one.
	Backoff time.Duration
	// Budget limits the whole sequence, waits included. A probe still
	// running when it ends fails as timed out, and no further one starts.
	Budget time.Duration
}

const (
	defaultProbeAttempts = 3
	defaultProbeBackoff  = 500 * time.Millisecond
	defaultProbeBudget   = 12 * time.Second
)

// socks5ReplyGeneralFailure is the one reply code that says the proxy
// failed rather than that it refuses the request.
const socks5ReplyGeneralFailure = 0x01

// ProbeSOCKS5WithRetry probes like ProbeSOCKS5 and repeats a probe whose
// failure a second try can cure: the proxy could not be reached, did not
// answer in time or dropped the connection. That is how a proxy looks while
// it restarts and a route while it settles, and giving up on the first such
// failure aborts a start that would have worked a moment later.
//
// A failure the proxy states itself is final and returned at once: wrong
// credentials, authentication required, UDP ASSOCIATE refused, not a SOCKS5
// server. Repeating those only delays the answer.
//
// The result is that of the last probe, with Attempts set and DurationMS
// covering the whole sequence.
func ProbeSOCKS5WithRetry(ctx context.Context, cfg ProbeConfig, policy ProbeRetryPolicy) (ProbeResult, error) {
	attempts, backoff, budget := policy.Attempts, policy.Backoff, policy.Budget
	if attempts <= 0 {
		attempts = defaultProbeAttempts
	}
	if backoff <= 0 {
		backoff = defaultProbeBackoff
	}
	if budget <= 0 {
		budget = defaultProbeBudget
	}

	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	for attempt := 1; ; attempt++ {
		result, err := ProbeSOCKS5(ctx, cfg)
		result.Attempts = attempt
		if err == nil || attempt >= attempts || !ProbeFailureIsTransient(err) || !waitForRetry(ctx, backoff) {
			result.DurationMS = time.Since(startedAt).Milliseconds()
			return result, err
		}
		backoff *= 2
	}
}

// ProbeFailureIsTransient reports whether a failed probe may pass when it is
// repeated: it failed without an answer from the proxy, or the proxy
// answered that it failed itself.
func ProbeFailureIsTransient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var se *transport.Socks5Error
	if !errors.As(err, &se) {
		return false
	}
	switch {
	case se.Stage == transport.Socks5StageConnect:
		// Unreachable, refused, timed out, name not resolved: all of them
		// pass. An address that cannot be dialled at all does not.
		var addrErr *net.AddrError
		return !errors.As(err, &addrErr)
	case se.Reason == transport.Socks5ReasonIO:
		return true
	case se.Reason == transport.Socks5ReasonRequestRejected:
		return se.Code == socks5ReplyGeneralFailure
	}
	return false
}

// waitForRetry waits d and reports whether the wait completed; it did not
// if ctx ended first.
func waitForRetry(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
