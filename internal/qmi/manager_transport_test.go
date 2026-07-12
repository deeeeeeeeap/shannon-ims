package qmicore

import (
	"errors"
	"strings"
	"testing"
)

func TestManagerDispatchesRecoveryExhausted(t *testing.T) {
	m := &Manager{}
	var gotReason string
	var gotErr error
	m.OnRecoveryExhausted(func(reason string, err error) {
		gotReason = reason
		gotErr = err
	})

	m.dispatchRecoveryExhausted("device_removed", errors.New("no such file or directory"))

	if gotReason != "device_removed" {
		t.Fatalf("reason = %q, want device_removed", gotReason)
	}
	if gotErr == nil || !strings.Contains(gotErr.Error(), "no such file or directory") {
		t.Fatalf("err = %v, want no such file or directory", gotErr)
	}
}
