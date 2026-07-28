package runtimehost

import (
	"testing"

	swulogger "github.com/1239t/swu-go/pkg/logger"
	externalswu "github.com/1239t/swu-go/pkg/swu"
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

func TestNewSWUSessionUsesInjectedApplicationLogger(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	applicationLogger := zap.New(core)
	SetLogger(applicationLogger)
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	session := newExternalSWUSession(&externalswu.Config{})
	if session.Logger != applicationLogger {
		t.Fatal("NewSession did not receive the injected application logger")
	}
	for _, entry := range observed.All() {
		if entry.Message == "NewSession received nil logger, falling back to global logger" {
			t.Fatal("NewSession emitted the nil logger fallback warning")
		}
	}
}
