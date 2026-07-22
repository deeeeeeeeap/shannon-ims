package modem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1239t/vohive/internal/config"
)

func TestParseFuserPIDs(t *testing.T) {
	raw := "/dev/ttyUSB2: 1234 5678c 1234 9999\n"
	got := parseFuserPIDs(raw)
	if len(got) != 3 {
		t.Fatalf("expected 3 unique pids, got %d (%v)", len(got), got)
	}
	want := map[int]struct{}{1234: {}, 5678: {}, 9999: {}}
	for _, pid := range got {
		if _, ok := want[pid]; !ok {
			t.Fatalf("unexpected pid parsed: %d (all=%v)", pid, got)
		}
	}
}

func TestIsRetryableSerialOpenErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "busy", err: assertErr("device or resource busy"), want: true},
		{name: "temp unavailable", err: assertErr("temporarily unavailable"), want: true},
		{name: "permission", err: assertErr("permission denied"), want: false},
		{name: "nil", err: nil, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isRetryableSerialOpenErr(tc.err)
			if got != tc.want {
				t.Fatalf("isRetryableSerialOpenErr(%v)=%v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestManagerStartFailsClosedWhenATPortIsOccupied(t *testing.T) {
	m, err := New(config.DeviceConfig{
		ID:            "dev-at",
		DeviceBackend: "at",
		ATPort:        "/dev/synthetic-at-port",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	m.portUserLookup = func(string) ([]int, error) {
		return []int{4242}, nil
	}

	err = m.Start()
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("Start() error = %v, want non-sensitive occupied-port failure", err)
	}
	if m.CanExecuteAT() {
		t.Fatal("CanExecuteAT() = true after occupied-port failure, want false")
	}
}

func TestLookupPortUsersFailsClosedWhenFuserExitsWithDiagnostic(t *testing.T) {
	binDir := t.TempDir()
	fakeFuser := filepath.Join(binDir, "fuser")
	if err := os.WriteFile(fakeFuser, []byte("#!/bin/sh\nprintf 'permission denied' >&2\nexit 2\n"), 0o755); err != nil {
		t.Fatalf("write fake fuser: %v", err)
	}
	t.Setenv("PATH", binDir)
	portPath := filepath.Join(t.TempDir(), "synthetic-at-port")
	if err := os.WriteFile(portPath, nil, 0o600); err != nil {
		t.Fatalf("write synthetic port: %v", err)
	}

	users, err := lookupPortUsers(portPath)
	if err == nil {
		t.Fatalf("lookupPortUsers() users=%v error=nil for abnormal fuser exit", users)
	}
}

func TestLookupPortUsersFailsClosedOnUnexpectedExitWithoutDiagnostic(t *testing.T) {
	binDir := t.TempDir()
	fakeFuser := filepath.Join(binDir, "fuser")
	if err := os.WriteFile(fakeFuser, []byte("#!/bin/sh\nexit 2\n"), 0o755); err != nil {
		t.Fatalf("write fake fuser: %v", err)
	}
	t.Setenv("PATH", binDir)
	portPath := filepath.Join(t.TempDir(), "synthetic-at-port")
	if err := os.WriteFile(portPath, nil, 0o600); err != nil {
		t.Fatalf("write synthetic port: %v", err)
	}

	if users, err := lookupPortUsers(portPath); err == nil {
		t.Fatalf("lookupPortUsers() users=%v error=nil for unexpected exit code", users)
	}
}

func TestLookupPortUsersAcceptsConfirmedUnusedResult(t *testing.T) {
	binDir := t.TempDir()
	fakeFuser := filepath.Join(binDir, "fuser")
	if err := os.WriteFile(fakeFuser, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("write fake fuser: %v", err)
	}
	t.Setenv("PATH", binDir)
	portPath := filepath.Join(t.TempDir(), "synthetic-at-port")
	if err := os.WriteFile(portPath, nil, 0o600); err != nil {
		t.Fatalf("write synthetic port: %v", err)
	}

	users, err := lookupPortUsers(portPath)
	if err != nil {
		t.Fatalf("lookupPortUsers() error=%v for confirmed unused result", err)
	}
	if len(users) != 0 {
		t.Fatalf("lookupPortUsers() users=%v, want none", users)
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }
