package upstreamproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/transport"
	"github.com/1239t/vowifi-go/runtimehost/transport/socks5sim"
)

// flakyFront stands in front of a simulated proxy that is having a bad
// moment: the first failFirst connections are closed without an answer, the
// rest are passed through.
type flakyFront struct {
	ln       net.Listener
	accepted atomic.Int64
}

func (f *flakyFront) addr() string { return f.ln.Addr().String() }

func startFlakyFront(t *testing.T, listenAddr, backend string, failFirst int64) *flakyFront {
	t.Helper()
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("listen on %s: %v", listenAddr, err)
	}
	f := &flakyFront{ln: ln}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if f.accepted.Add(1) <= failFirst {
				_ = conn.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				pipeToBackend(conn, backend)
			}()
		}
	}()
	return f
}

func pipeToBackend(client net.Conn, backend string) {
	defer client.Close()
	upstream, err := net.Dial("tcp", backend)
	if err != nil {
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// unusedLoopbackAddr returns a loopback address nothing listens on.
func unusedLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestProbeRetryRecoversWhenTheProxyDropsTheFirstConnections(t *testing.T) {
	sim := startSimProxy(t, socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: simUser, Password: simPassword})
	for _, failFirst := range []int64{1, 2} {
		t.Run(fmt.Sprintf("%d dropped", failFirst), func(t *testing.T) {
			front := startFlakyFront(t, "127.0.0.1:0", sim.Addr(), failFirst)
			cfg := ProbeConfig{ProxyAddr: front.addr(), Username: simUser, Password: simPassword, Timeout: 2 * time.Second}

			// One probe sees the fault and reports it.
			single, err := ProbeSOCKS5(context.Background(), cfg)
			if err == nil || single.Stage != ProbeStageHandshake || single.Attempts != 0 {
				t.Fatalf("single probe = %+v, err=%v; want a handshake failure", single, err)
			}
			if !ProbeFailureIsTransient(err) {
				t.Fatalf("a dropped connection is not treated as transient: %v", err)
			}
			front.accepted.Store(0)

			result, err := ProbeSOCKS5WithRetry(context.Background(), cfg, ProbeRetryPolicy{Backoff: time.Millisecond})
			if err != nil || !result.OK() {
				t.Fatalf("probe with retry = %+v, err=%v; want success", result, err)
			}
			if want := int(failFirst) + 1; result.Attempts != want {
				t.Fatalf("attempts = %d, want %d", result.Attempts, want)
			}
			if result.AuthMethod != "username_password" || result.RelayAddr == "" {
				t.Fatalf("the successful attempt is not what is reported: %+v", result)
			}
		})
	}
}

func TestProbeRetryRecoversWhenTheProxyComesUp(t *testing.T) {
	sim := startSimProxy(t, socks5sim.Config{Auth: socks5sim.AuthNone})
	addr := unusedLoopbackAddr(t)

	type outcome struct {
		result ProbeResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := ProbeSOCKS5WithRetry(context.Background(),
			ProbeConfig{ProxyAddr: addr, Timeout: 2 * time.Second},
			ProbeRetryPolicy{Attempts: 12, Backoff: 5 * time.Millisecond})
		done <- outcome{result, err}
	}()

	// The proxy is down for the first attempts and then starts listening.
	time.Sleep(30 * time.Millisecond)
	startFlakyFront(t, addr, sim.Addr(), 0)

	select {
	case got := <-done:
		if got.err != nil || !got.result.OK() {
			t.Fatalf("probe = %+v, err=%v; want success once the proxy is up", got.result, got.err)
		}
		if got.result.Attempts < 2 {
			t.Fatalf("attempts = %d, want the first one to have failed", got.result.Attempts)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the probe did not finish")
	}
}

func TestProbeRetryDoesNotRepeatAnAnswerFromTheProxy(t *testing.T) {
	cases := []struct {
		name      string
		auth      socks5sim.AuthMode
		faults    func(*socks5sim.Faults)
		username  string
		password  string
		wantStage string
	}{
		{name: "wrong password", auth: socks5sim.AuthUserPass, username: simUser, password: "wrong", wantStage: ProbeStageHandshake},
		{name: "credentials required", auth: socks5sim.AuthUserPass, wantStage: ProbeStageHandshake},
		{name: "udp associate not supported", auth: socks5sim.AuthNone,
			faults: func(f *socks5sim.Faults) { f.AssociateReply = 0x07 }, wantStage: ProbeStageUDPAssociate},
		{name: "not a socks5 server", auth: socks5sim.AuthNone,
			faults: func(f *socks5sim.Faults) { f.WrongVersion = true }, wantStage: ProbeStageHandshake},
		{name: "unusable relay address", auth: socks5sim.AuthNone,
			faults: func(f *socks5sim.Faults) { f.Advertise = socks5sim.AdvertisePortZero }, wantStage: ProbeStageUDPAssociate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sim := startSimProxy(t, socks5sim.Config{Auth: tc.auth, Username: simUser, Password: simPassword})
			if tc.faults != nil {
				sim.SetFaults(tc.faults)
			}
			cfg := ProbeConfig{ProxyAddr: sim.Addr(), Username: tc.username, Password: tc.password, Timeout: 2 * time.Second}

			started := time.Now()
			result, err := ProbeSOCKS5WithRetry(context.Background(), cfg, ProbeRetryPolicy{Attempts: 5, Backoff: 3 * time.Second})
			elapsed := time.Since(started)

			if err == nil || result.OK() || result.Stage != tc.wantStage {
				t.Fatalf("result = %+v, err=%v; want a failure at %s", result, err, tc.wantStage)
			}
			if ProbeFailureIsTransient(err) {
				t.Fatalf("an answer from the proxy is treated as transient: %v", err)
			}
			if result.Attempts != 1 || elapsed >= 2*time.Second {
				t.Fatalf("attempts = %d in %v, want a single probe and no wait", result.Attempts, elapsed)
			}
			// The error reads like the result and still carries its cause.
			if err.Error() != result.Error {
				t.Fatalf("error text %q differs from the result's %q", err.Error(), result.Error)
			}
			var se *transport.Socks5Error
			if !errors.As(err, &se) {
				t.Fatalf("the typed cause is lost: %T", err)
			}
		})
	}
}

func TestProbeRetryRepeatsAGeneralProxyFailure(t *testing.T) {
	sim := startSimProxy(t, socks5sim.Config{Auth: socks5sim.AuthNone})
	sim.SetFaults(func(f *socks5sim.Faults) { f.AssociateReply = 0x01 })

	result, err := ProbeSOCKS5WithRetry(context.Background(),
		ProbeConfig{ProxyAddr: sim.Addr(), Timeout: 2 * time.Second},
		ProbeRetryPolicy{Attempts: 3, Backoff: time.Millisecond})
	if err == nil || result.Stage != ProbeStageUDPAssociate {
		t.Fatalf("result = %+v, err=%v; want the UDP ASSOCIATE failure", result, err)
	}
	if result.Attempts != 3 {
		t.Fatalf("attempts = %d, want all 3 to be used", result.Attempts)
	}
	if got := sim.Stats().Connections; got != 3 {
		t.Fatalf("the proxy saw %d connections, want 3", got)
	}

	// The proxy recovers between attempts: the next sequence passes.
	sim.SetFaults(func(f *socks5sim.Faults) { f.AssociateReply = 0 })
	result, err = ProbeSOCKS5WithRetry(context.Background(),
		ProbeConfig{ProxyAddr: sim.Addr(), Timeout: 2 * time.Second}, ProbeRetryPolicy{})
	if err != nil || !result.OK() || result.Attempts != 1 {
		t.Fatalf("result = %+v, err=%v; want success at the first attempt", result, err)
	}
}

func TestProbeRetryGivesUpAfterItsAttempts(t *testing.T) {
	addr := unusedLoopbackAddr(t)
	started := time.Now()
	result, err := ProbeSOCKS5WithRetry(context.Background(),
		ProbeConfig{ProxyAddr: addr, Timeout: 2 * time.Second},
		ProbeRetryPolicy{Attempts: 4, Backoff: 10 * time.Millisecond})
	elapsed := time.Since(started)

	if err == nil || result.Stage != ProbeStageTCPConnect || result.Reachable {
		t.Fatalf("result = %+v, err=%v; want a connect failure", result, err)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("err = %v, want connection refused", err)
	}
	if result.Attempts != 4 {
		t.Fatalf("attempts = %d, want 4", result.Attempts)
	}
	// Waits of 10, 20 and 40 ms lie between the four attempts.
	if elapsed < 70*time.Millisecond || result.DurationMS < 70 {
		t.Fatalf("sequence took %v (reported %d ms), want the backoff to be honoured and reported", elapsed, result.DurationMS)
	}
	if result.Diagnosis == "" || result.Hint == "" {
		t.Fatalf("the last failure is not explained: %+v", result)
	}
}

func TestProbeRetryStaysWithinItsBudget(t *testing.T) {
	sim := startSimProxy(t, socks5sim.Config{Auth: socks5sim.AuthNone})
	sim.SetFaults(func(f *socks5sim.Faults) { f.StallGreeting = true })

	started := time.Now()
	result, err := ProbeSOCKS5WithRetry(context.Background(),
		ProbeConfig{ProxyAddr: sim.Addr(), Timeout: 5 * time.Second},
		ProbeRetryPolicy{Attempts: 10, Backoff: 10 * time.Millisecond, Budget: 300 * time.Millisecond})
	elapsed := time.Since(started)

	if err == nil || result.Stage != ProbeStageHandshake {
		t.Fatalf("result = %+v, err=%v; want a handshake failure", result, err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("the sequence took %v with a 300ms budget", elapsed)
	}
	if result.Attempts != 1 {
		t.Fatalf("attempts = %d, want no new attempt once the budget is spent", result.Attempts)
	}
}

func TestProbeRetryStopsWhenTheCallerCancels(t *testing.T) {
	addr := unusedLoopbackAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	started := time.Now()
	result, err := ProbeSOCKS5WithRetry(ctx,
		ProbeConfig{ProxyAddr: addr, Timeout: 2 * time.Second},
		ProbeRetryPolicy{Attempts: 100, Backoff: 10 * time.Second, Budget: time.Minute})
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("the sequence took %v after the caller cancelled", elapsed)
	}
	if err == nil || result.Attempts != 1 {
		t.Fatalf("result = %+v, err=%v; want the first failure and no further attempt", result, err)
	}

	// Cancelled before it starts: one probe that fails at once, no retry.
	result, err = ProbeSOCKS5WithRetry(ctx, ProbeConfig{ProxyAddr: addr}, ProbeRetryPolicy{Attempts: 5, Backoff: time.Millisecond})
	if err == nil || result.Attempts != 1 || ProbeFailureIsTransient(err) {
		t.Fatalf("result = %+v, err=%v; want a single cancelled probe", result, err)
	}
}

func TestProbeRetryRejectsAnEmptyAddressAtOnce(t *testing.T) {
	result, err := ProbeSOCKS5WithRetry(context.Background(), ProbeConfig{ProxyAddr: "  "},
		ProbeRetryPolicy{Attempts: 5, Backoff: 5 * time.Second})
	if err == nil || result.Attempts != 1 || result.Error == "" {
		t.Fatalf("result = %+v, err=%v; want one failed attempt", result, err)
	}
}

func TestProbeFailureIsTransient(t *testing.T) {
	socksErr := func(stage transport.Socks5Stage, reason transport.Socks5Reason, code byte, cause error) error {
		return &transport.Socks5Error{Stage: stage, Reason: reason, Code: code, Err: cause}
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"no error", nil, false},
		{"untyped error", errors.New("empty proxy addr"), false},
		{"connection refused", socksErr(transport.Socks5StageConnect, transport.Socks5ReasonIO, 0, syscall.ECONNREFUSED), true},
		{"connect timeout", socksErr(transport.Socks5StageConnect, transport.Socks5ReasonIO, 0, context.DeadlineExceeded), true},
		{"name not resolved", socksErr(transport.Socks5StageConnect, transport.Socks5ReasonIO, 0, &net.DNSError{Err: "no such host", IsNotFound: true}), true},
		{"address cannot be dialled", socksErr(transport.Socks5StageConnect, transport.Socks5ReasonIO, 0, &net.AddrError{Err: "missing port in address"}), false},
		{"closed during handshake", socksErr(transport.Socks5StageHandshake, transport.Socks5ReasonIO, 0, io.EOF), true},
		{"no answer to the request", socksErr(transport.Socks5StageRequest, transport.Socks5ReasonIO, 0, context.DeadlineExceeded), true},
		{"caller cancelled", socksErr(transport.Socks5StageHandshake, transport.Socks5ReasonIO, 0, context.Canceled), false},
		{"cancelled while connecting", socksErr(transport.Socks5StageConnect, transport.Socks5ReasonIO, 0, context.Canceled), false},
		{"wrong password", socksErr(transport.Socks5StageHandshake, transport.Socks5ReasonAuthRejected, 0x01, nil), false},
		{"credentials required", socksErr(transport.Socks5StageHandshake, transport.Socks5ReasonCredentialsRequired, 0x02, nil), false},
		{"no acceptable method", socksErr(transport.Socks5StageHandshake, transport.Socks5ReasonNoAcceptableMethod, 0xff, nil), false},
		{"unsupported method", socksErr(transport.Socks5StageHandshake, transport.Socks5ReasonUnsupportedMethod, 0x80, nil), false},
		{"credentials too long", socksErr(transport.Socks5StageHandshake, transport.Socks5ReasonInvalidCredentials, 0, nil), false},
		{"not socks5", socksErr(transport.Socks5StageHandshake, transport.Socks5ReasonNotSocks5, 0x48, nil), false},
		{"command not supported", socksErr(transport.Socks5StageRequest, transport.Socks5ReasonRequestRejected, 0x07, nil), false},
		{"not allowed by ruleset", socksErr(transport.Socks5StageRequest, transport.Socks5ReasonRequestRejected, 0x02, nil), false},
		{"general proxy failure", socksErr(transport.Socks5StageRequest, transport.Socks5ReasonRequestRejected, 0x01, nil), true},
		{"unusable reply", socksErr(transport.Socks5StageRequest, transport.Socks5ReasonMalformedReply, 0, nil), false},
	}
	for _, tc := range cases {
		if got := ProbeFailureIsTransient(tc.err); got != tc.want {
			t.Errorf("%s: transient = %v, want %v", tc.name, got, tc.want)
		}
		if tc.err == nil {
			continue
		}
		// The verdict is the same for the error as the probe returns it.
		wrapped := &probeError{text: "探测失败", cause: tc.err}
		if got := ProbeFailureIsTransient(wrapped); got != tc.want {
			t.Errorf("%s (as returned by the probe): transient = %v, want %v", tc.name, got, tc.want)
		}
	}
}
