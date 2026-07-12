package voiceclient

import (
	"context"
	"errors"
	"testing"
)

func TestIsRegisterTransactionTimeout(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("unexpected final REGISTER response: 403 Forbidden"), false},
		{errors.New("initial REGISTER: transaction ended: Timer_B timed out. transaction timeout"), true},
		{context.DeadlineExceeded, true},
		{errors.New("transaction ended without a response"), true},
	}
	for _, tc := range cases {
		if got := isRegisterTransactionTimeout(tc.err); got != tc.want {
			t.Fatalf("isRegisterTransactionTimeout(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestIsRegisterVariantRetryableIncludesTimeout(t *testing.T) {
	err := errors.New("initial REGISTER: transaction ended: Timer_B timed out. transaction timeout")
	if !isRegisterVariantRetryable(err) {
		t.Fatal("expected timeout to be variant-retryable")
	}
}

func TestRegisterDialTimeoutBudget(t *testing.T) {
	if registerDialTimeout < registerTransactionTimeout {
		t.Fatalf("register dial timeout %v must exceed per-transaction timeout %v", registerDialTimeout, registerTransactionTimeout)
	}
}