package runtimehost

import (
	"testing"

	swulogger "github.com/1239t/swu-go/pkg/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestSetLoggerInjectsApplicationLogger(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	swulogger.Info("runtimehost logger injection test")

	if observed.Len() != 1 {
		t.Fatalf("application logger entries = %d, want 1", observed.Len())
	}
}
