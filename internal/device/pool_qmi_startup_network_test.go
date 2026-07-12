package device

import (
	"context"
	"errors"
	"testing"
)

type fakeExistingDataConnectionResetter struct {
	calls int
	err   error
}

func (f *fakeExistingDataConnectionResetter) ResetExistingDataConnection(context.Context) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	return true, nil
}

func TestResetExistingQMIDataConnectionBeforePreferenceCallsResetter(t *testing.T) {
	resetter := &fakeExistingDataConnectionResetter{}

	reset, err := resetExistingQMIDataConnectionBeforePreference(context.Background(), "dev-a", "startup", resetter)
	if err != nil {
		t.Fatalf("resetExistingQMIDataConnectionBeforePreference() error = %v", err)
	}
	if !reset {
		t.Fatal("reset=false, want true")
	}
	if resetter.calls != 1 {
		t.Fatalf("calls=%d want 1", resetter.calls)
	}
}

func TestResetExistingQMIDataConnectionBeforePreferencePropagatesError(t *testing.T) {
	wantErr := errors.New("stop failed")
	resetter := &fakeExistingDataConnectionResetter{err: wantErr}

	reset, err := resetExistingQMIDataConnectionBeforePreference(context.Background(), "dev-a", "startup", resetter)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error=%v want %v", err, wantErr)
	}
	if reset {
		t.Fatal("reset=true, want false on error")
	}
}
