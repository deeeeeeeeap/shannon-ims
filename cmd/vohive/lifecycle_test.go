package main

import (
	"context"
	"testing"
	"time"
)

func TestApplicationLifecycleCancelJoinsOwnedTask(t *testing.T) {
	lifecycle := newApplicationLifecycle(context.Background())
	started := make(chan struct{})
	stopped := make(chan struct{})
	if !lifecycle.Go(func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		close(stopped)
	}) {
		t.Fatal("Go() rejected task before lifecycle cancellation")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("owned task did not start")
	}

	waitCtx, cancelWait := context.WithTimeout(context.Background(), time.Second)
	defer cancelWait()
	if err := lifecycle.Stop(waitCtx); err != nil {
		t.Fatalf("Stop() error=%v", err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("Stop() returned before owned task exited")
	}
	if lifecycle.Go(func(context.Context) {}) {
		t.Fatal("Go() accepted a task after lifecycle Stop()")
	}
}

func TestApplicationLifecycleKeepsTimedOutCleanupOwned(t *testing.T) {
	lifecycle := newApplicationLifecycle(context.Background())
	lifecycle.Cancel()
	started := make(chan struct{})
	release := make(chan struct{})

	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelCleanup()
	err := lifecycle.RunCleanup(cleanupCtx, func() {
		close(started)
		<-release
	})
	if err != context.DeadlineExceeded {
		t.Fatalf("RunCleanup() error=%v, want deadline", err)
	}
	select {
	case <-started:
	default:
		t.Fatal("cleanup did not start after lifecycle cancellation")
	}

	stopCtx, cancelStop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelStop()
	if err := lifecycle.Stop(stopCtx); err != context.DeadlineExceeded {
		t.Fatalf("Stop() error=%v, want deadline while cleanup remains active", err)
	}

	close(release)
	joinCtx, cancelJoin := context.WithTimeout(context.Background(), time.Second)
	defer cancelJoin()
	if err := lifecycle.Stop(joinCtx); err != nil {
		t.Fatalf("Stop() after cleanup release error=%v", err)
	}
}
