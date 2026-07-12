package qmicore

import (
	"errors"
	"testing"
	"time"
)

func TestManagerDispatchRecoveryExhausted(t *testing.T) {
	m := &Manager{}
	got := make(chan string, 1)
	m.OnRecoveryExhausted(func(reason string, err error) {
		got <- reason
	})
	m.dispatchRecoveryExhausted("device_removed", errors.New("no such file or directory"))
	select {
	case r := <-got:
		if r != "device_removed" {
			t.Fatalf("reason = %q, want device_removed", r)
		}
	case <-time.After(time.Second):
		t.Fatal("handler not invoked")
	}
}
