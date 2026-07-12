package logger

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestBindLookupUnbindReaderDevice(t *testing.T) {
	clearReaderIMSIBindings()
	t.Cleanup(clearReaderIMSIBindings)

	if _, ok := LookupIMSIByReader("r1"); ok {
		t.Fatalf("expected empty registry before bind")
	}

	BindReaderIMSI("r1", "234101736427229")
	if got, ok := LookupIMSIByReader("r1"); !ok || got != "234101736427229" {
		t.Fatalf("unexpected lookup after bind, got=%q ok=%v", got, ok)
	}

	// update binding
	BindReaderIMSI("r1", "234336570175207")
	if got, ok := LookupIMSIByReader("r1"); !ok || got != "234336570175207" {
		t.Fatalf("unexpected lookup after rebind, got=%q ok=%v", got, ok)
	}

	UnbindReaderIMSI("r1")
	if _, ok := LookupIMSIByReader("r1"); ok {
		t.Fatalf("expected no mapping after unbind")
	}
}

func TestResolveDeviceIDExplicitDeviceFirst(t *testing.T) {
	clearReaderIMSIBindings()
	t.Cleanup(clearReaderIMSIBindings)

	BindReaderIMSI("reader-1", "mapped-imsi")
	got, ok := resolveDeviceID(
		nil,
		[]zapcore.Field{
			zap.String("reader", "reader-1"),
			zap.String("device", "explicit-imsi"),
		},
	)
	if !ok || got != "explicit-imsi" {
		t.Fatalf("expected explicit device first, got=%q ok=%v", got, ok)
	}
}

func TestResolveDeviceIDByReaderMapping(t *testing.T) {
	clearReaderIMSIBindings()
	t.Cleanup(clearReaderIMSIBindings)

	BindReaderIMSI("reader-1", "234101736427229")
	got, ok := resolveDeviceID(
		nil,
		[]zapcore.Field{
			zap.String("reader", "reader-1"),
		},
	)
	if !ok || got != "234101736427229" {
		t.Fatalf("expected mapped imsi, got=%q ok=%v", got, ok)
	}
}

func TestResolveDeviceIDMissingReaderMapping(t *testing.T) {
	clearReaderIMSIBindings()
	t.Cleanup(clearReaderIMSIBindings)

	got, ok := resolveDeviceID(
		nil,
		[]zapcore.Field{
			zap.String("reader", "reader-404"),
		},
	)
	if ok || got != "" {
		t.Fatalf("expected unresolved device id, got=%q ok=%v", got, ok)
	}
}
