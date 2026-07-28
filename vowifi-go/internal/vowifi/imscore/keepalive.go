package imscore

import (
	"context"
	"math/rand"
	"time"
)

const maxInitialRegisterJitter = time.Second

// waitInitialRegisterJitter applies the author keepalive.go pre-register delay.
func waitInitialRegisterJitter(ctx context.Context, cfg Config) error {
	if maxInitialRegisterJitter <= 0 {
		return nil
	}
	delay := time.Duration(rand.Int63n(int64(maxInitialRegisterJitter)))
	if delay <= 0 {
		return nil
	}
	_ = cfg
	logRegisterDiagnostic(registerDiagnostic{stage: "initial_jitter", result: "none"})
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
