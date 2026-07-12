package qmicore

import (
	"context"
	"errors"
	"testing"
)

func TestResetExistingDataConnectionUsesHook(t *testing.T) {
	called := false
	m := &Manager{
		resetExistingDataConnection: func(ctx context.Context) (bool, error) {
			called = true
			if ctx == nil {
				t.Fatal("ctx is nil")
			}
			return true, nil
		},
	}

	reset, err := m.ResetExistingDataConnection(context.Background())
	if err != nil {
		t.Fatalf("ResetExistingDataConnection() error = %v", err)
	}
	if !called {
		t.Fatal("reset hook was not called")
	}
	if !reset {
		t.Fatal("reset=false, want true")
	}
}

func TestResetExistingDataConnectionPropagatesHookError(t *testing.T) {
	wantErr := errors.New("status query failed")
	m := &Manager{
		resetExistingDataConnection: func(context.Context) (bool, error) {
			return false, wantErr
		},
	}

	reset, err := m.ResetExistingDataConnection(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("ResetExistingDataConnection() error = %v, want %v", err, wantErr)
	}
	if reset {
		t.Fatal("reset=true, want false on error")
	}
}

func TestResetExistingDataConnectionDelegatesToCoreHook(t *testing.T) {
	called := false
	m := &Manager{
		resetExistingDataConnectionViaCoreHook: func(ctx context.Context) (bool, error) {
			called = true
			if ctx == nil {
				t.Fatal("ctx is nil")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("ctx deadline not set")
			}
			return true, nil
		},
	}

	reset, err := m.ResetExistingDataConnection(context.Background())
	if err != nil {
		t.Fatalf("ResetExistingDataConnection() error = %v", err)
	}
	if !called {
		t.Fatal("core cleanup hook was not called")
	}
	if !reset {
		t.Fatal("reset=false, want true")
	}
}

func TestResetExistingDataConnectionPropagatesCoreHookError(t *testing.T) {
	wantErr := errors.New("core cleanup failed")
	m := &Manager{
		resetExistingDataConnectionViaCoreHook: func(context.Context) (bool, error) {
			return false, wantErr
		},
	}

	reset, err := m.ResetExistingDataConnection(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("ResetExistingDataConnection() error = %v, want %v", err, wantErr)
	}
	if reset {
		t.Fatal("reset=true, want false on error")
	}
}

func TestResetExistingDataConnectionWithoutCoreManagerFails(t *testing.T) {
	m := &Manager{}

	reset, err := m.ResetExistingDataConnection(context.Background())
	if err == nil {
		t.Fatal("ResetExistingDataConnection() error=nil, want error")
	}
	if reset {
		t.Fatal("reset=true, want false on error")
	}
}
