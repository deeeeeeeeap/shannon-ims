package imscore

import (
	"context"
	"math/rand"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
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
	logger.Info("初始注册随机延迟 (Jitter)",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
		logger.String("duration", delay.String()))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}