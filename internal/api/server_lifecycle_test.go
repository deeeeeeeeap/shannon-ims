package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestRunContextRejectsCanceledLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	listenCalls := 0
	server := &Server{
		shutdownCh: make(chan struct{}),
		listenContext: func(context.Context, string, string) (net.Listener, error) {
			listenCalls++
			return nil, errors.New("listener must not start")
		},
	}

	err := server.RunContext(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunContext() error=%v, want context.Canceled", err)
	}
	if listenCalls != 0 {
		t.Fatalf("listener calls=%d, want 0 for canceled lifecycle", listenCalls)
	}
}

func TestShutdownBeforeRunPreventsLateListenerStart(t *testing.T) {
	listenCalls := 0
	server := &Server{
		shutdownCh: make(chan struct{}),
		listenContext: func(context.Context, string, string) (net.Listener, error) {
			listenCalls++
			return nil, errors.New("listener must not start")
		},
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error=%v", err)
	}

	err := server.RunContext(context.Background())

	if !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("RunContext() error=%v, want http.ErrServerClosed", err)
	}
	if listenCalls != 0 {
		t.Fatalf("listener calls=%d, want 0 after Shutdown", listenCalls)
	}
}

func TestPublishedServerCannotMissConcurrentShutdown(t *testing.T) {
	listenEntered := make(chan struct{})
	releaseListen := make(chan struct{})
	listener := newLifecycleTestListener()
	server := &Server{
		shutdownCh: make(chan struct{}),
		listenContext: func(context.Context, string, string) (net.Listener, error) {
			close(listenEntered)
			<-releaseListen
			return listener, nil
		},
	}
	runDone := make(chan error, 1)
	go func() {
		runDone <- server.RunContext(context.Background())
	}()
	select {
	case <-listenEntered:
	case <-time.After(time.Second):
		t.Fatal("RunContext did not publish the server and enter listener factory")
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown() before listener return error=%v", err)
	}
	close(releaseListen)

	select {
	case err := <-runDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("RunContext() error=%v, want http.ErrServerClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RunContext did not stop after concurrent Shutdown")
	}
	select {
	case <-listener.closed:
	default:
		t.Fatal("late listener was not closed after concurrent Shutdown")
	}
}

func TestShutdownCancelsPendingListenerStart(t *testing.T) {
	listenEntered := make(chan struct{})
	server := &Server{
		shutdownCh: make(chan struct{}),
		listenContext: func(ctx context.Context, _, _ string) (net.Listener, error) {
			close(listenEntered)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	runDone := make(chan error, 1)
	go func() {
		runDone <- server.RunContext(context.Background())
	}()
	select {
	case <-listenEntered:
	case <-time.After(time.Second):
		t.Fatal("RunContext did not enter pending listener start")
	}

	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error=%v", err)
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("RunContext() error=%v, want http.ErrServerClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending listener start was not canceled by Shutdown")
	}
}

func TestConcurrentAndRepeatedShutdownIsIdempotent(t *testing.T) {
	listener := newLifecycleTestListener()
	server := &Server{
		shutdownCh: make(chan struct{}),
		listenContext: func(context.Context, string, string) (net.Listener, error) {
			return listener, nil
		},
	}
	runDone := make(chan error, 1)
	go func() {
		runDone <- server.RunContext(context.Background())
	}()
	select {
	case <-listener.acceptEntered:
	case <-time.After(time.Second):
		t.Fatal("listener did not enter Accept")
	}

	const shutdownCalls = 8
	start := make(chan struct{})
	var ready sync.WaitGroup
	var done sync.WaitGroup
	errs := make(chan error, shutdownCalls)
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	ready.Add(shutdownCalls)
	done.Add(shutdownCalls)
	for i := 0; i < shutdownCalls; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			errs <- server.Shutdown(shutdownCtx)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Shutdown() error=%v", err)
		}
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("repeated Shutdown() error=%v", err)
	}

	select {
	case err := <-runDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("RunContext() error=%v, want http.ErrServerClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RunContext did not return after concurrent Shutdown calls")
	}
}

func TestRunCompatibilityAllowsRetryAfterServeError(t *testing.T) {
	acceptErr := errors.New("synthetic accept failure")
	listenCalls := 0
	server := &Server{
		shutdownCh: make(chan struct{}),
		listenContext: func(context.Context, string, string) (net.Listener, error) {
			listenCalls++
			return &lifecycleAcceptErrorListener{err: acceptErr}, nil
		},
	}

	for attempt := 1; attempt <= 2; attempt++ {
		if err := server.Run(); !errors.Is(err, acceptErr) {
			t.Fatalf("Run() attempt %d error=%v, want synthetic serve error", attempt, err)
		}
	}
	if listenCalls != 2 {
		t.Fatalf("listener calls=%d, want 2 after retry", listenCalls)
	}
}

func TestHTTPServerBaseContextFollowsApplicationLifecycle(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	httpServer := newHTTPServer(parent, "127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if httpServer.WriteTimeout <= 0 {
		t.Fatal("ordinary API WriteTimeout is unbounded")
	}
	baseCtx := httpServer.BaseContext(nil)
	cancelParent()

	select {
	case <-baseCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("HTTP BaseContext did not follow application cancellation")
	}
}

type lifecycleTestListener struct {
	closed        chan struct{}
	acceptEntered chan struct{}
	acceptOnce    sync.Once
	closeOnce     sync.Once
}

func newLifecycleTestListener() *lifecycleTestListener {
	return &lifecycleTestListener{
		closed:        make(chan struct{}),
		acceptEntered: make(chan struct{}),
	}
}

func (l *lifecycleTestListener) Accept() (net.Conn, error) {
	l.acceptOnce.Do(func() { close(l.acceptEntered) })
	<-l.closed
	return nil, net.ErrClosed
}

func (l *lifecycleTestListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *lifecycleTestListener) Addr() net.Addr {
	return lifecycleTestAddr("synthetic-listener")
}

type lifecycleTestAddr string

func (a lifecycleTestAddr) Network() string { return "tcp" }
func (a lifecycleTestAddr) String() string  { return string(a) }

type lifecycleAcceptErrorListener struct {
	err error
}

func (l *lifecycleAcceptErrorListener) Accept() (net.Conn, error) { return nil, l.err }
func (l *lifecycleAcceptErrorListener) Close() error              { return nil }
func (l *lifecycleAcceptErrorListener) Addr() net.Addr {
	return lifecycleTestAddr("synthetic-error-listener")
}
