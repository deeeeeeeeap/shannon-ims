package device

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
)

func TestRemoveWorkerCancelsInFlightESIMPhysicalLease(t *testing.T) {
	pool := NewPool(&config.Config{})
	worker := &Worker{
		ID:         "device-lease-cancel",
		Config:     config.DeviceConfig{ID: "device-lease-cancel"},
		generation: 1,
		Pool:       pool,
		stop:       make(chan struct{}),
	}
	pool.mu.Lock()
	pool.workers[worker.ID] = worker
	pool.mu.Unlock()

	lease, ok := worker.acquireESIMOperationLease(pool.ctx)
	if !ok {
		t.Fatal("failed to acquire eSIM operation lease")
	}
	physicalEntered := make(chan struct{})
	physicalDone := make(chan error, 1)
	go func() {
		defer lease.Release()
		physicalDone <- lease.RunPhysical(func() error {
			close(physicalEntered)
			<-lease.Context().Done()
			return lease.Context().Err()
		})
	}()

	select {
	case <-physicalEntered:
	case <-time.After(time.Second):
		t.Fatal("physical operation did not enter")
	}
	removeDone := make(chan error, 1)
	go func() {
		removeDone <- pool.RemoveWorker(worker.ID)
	}()

	select {
	case <-lease.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("RemoveWorker did not cancel the in-flight eSIM operation")
	}
	select {
	case err := <-physicalDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("physical operation error=%v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled physical operation did not return")
	}
	select {
	case err := <-removeDone:
		if err != nil {
			t.Fatalf("RemoveWorker error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RemoveWorker did not join the canceled eSIM operation")
	}
}
