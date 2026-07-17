package api

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
)

func TestLoadOrCreateSessionSecretPersistsAndReuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "session-secret")

	first, err := loadOrCreateSessionSecret(path)
	if err != nil {
		t.Fatalf("loadOrCreateSessionSecret(first) error = %v", err)
	}
	if len(first) != sessionSecretSize {
		t.Fatalf("first secret length = %d, want %d", len(first), sessionSecretSize)
	}

	second, err := loadOrCreateSessionSecret(path)
	if err != nil {
		t.Fatalf("loadOrCreateSessionSecret(second) error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("persisted session secret changed across reload")
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(onDisk, first) {
		t.Fatal("session secret file does not contain the generated secret")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("session secret mode = %o, want 600", got)
		}
	}
}

func TestLoadOrCreateSessionSecretConcurrentFirstUseReturnsOneSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "session-secret")
	const workers = 16

	results := make(chan []byte, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			secret, err := loadOrCreateSessionSecret(path)
			if err != nil {
				errs <- err
				return
			}
			results <- secret
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent loadOrCreateSessionSecret() error = %v", err)
	}
	var want []byte
	for got := range results {
		if want == nil {
			want = got
			continue
		}
		if !bytes.Equal(got, want) {
			t.Fatal("concurrent first use returned different session secrets")
		}
	}
}

func TestLoadOrCreateSessionSecretRejectsCorruptExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "session-secret")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	corrupt := []byte("short")
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := loadOrCreateSessionSecret(path); err == nil {
		t.Fatal("loadOrCreateSessionSecret() error = nil, want corrupt file rejection")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(after, corrupt) {
		t.Fatal("corrupt secret file was silently replaced")
	}
}

func TestLoadOrCreateSessionSecretTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are verified by Linux tests")
	}
	path := filepath.Join(t.TempDir(), "data", "session-secret")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x33}, sessionSecretSize), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := loadOrCreateSessionSecret(path); err != nil {
		t.Fatalf("loadOrCreateSessionSecret() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("session secret mode = %o, want 600", got)
	}
}

func TestNewPersistsSessionSecretBesideRuntimeData(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(configPath, []byte("web: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfg := &config.Config{Web: config.WebConfig{
		Username: "admin",
		Password: "a-unique-local-password",
	}}

	first, err := New(cfg, nil, nil, nil, nil, nil, configPath)
	if err != nil {
		t.Fatalf("New(first) error = %v", err)
	}
	if len(first.sessionSecret) != sessionSecretSize {
		t.Fatalf("first session secret length = %d, want %d", len(first.sessionSecret), sessionSecretSize)
	}
	if bytes.Equal(first.sessionSecret, []byte(cfg.Web.Password)) {
		t.Fatal("session secret must be independent from the Web password")
	}

	token, _, err := first.issueSessionToken()
	if err != nil {
		t.Fatalf("issueSessionToken() error = %v", err)
	}
	second, err := New(cfg, nil, nil, nil, nil, nil, configPath)
	if err != nil {
		t.Fatalf("New(second) error = %v", err)
	}
	if !bytes.Equal(first.sessionSecret, second.sessionSecret) {
		t.Fatal("New() did not reuse persisted session secret")
	}
	if !second.isSessionTokenValid(token, time.Now()) {
		t.Fatal("token issued before restart was not valid after persisted secret reload")
	}

	wantPath := filepath.Join(root, "data", "session-secret")
	if got := sessionSecretPath(configPath); got != wantPath {
		t.Fatalf("sessionSecretPath() = %q, want %q", got, wantPath)
	}
}

func TestSessionTokenRequiresIndependentSecretAndCurrentPassword(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, sessionSecretSize)
	server := &Server{
		auth:          config.WebConfig{Username: "admin", Password: "first-password"},
		sessionSecret: secret,
	}
	token, _, err := server.issueSessionToken()
	if err != nil {
		t.Fatalf("issueSessionToken() error = %v", err)
	}

	differentSecret := &Server{
		auth:          server.auth,
		sessionSecret: bytes.Repeat([]byte{0x24}, sessionSecretSize),
	}
	if differentSecret.isSessionTokenValid(token, time.Now()) {
		t.Fatal("token validated with a different session secret")
	}

	server.auth.Password = "second-password"
	if server.isSessionTokenValid(token, time.Now()) {
		t.Fatal("token remained valid after password rotation")
	}
}

func TestIssueSessionTokenFailsClosedWithoutSecret(t *testing.T) {
	server := &Server{auth: config.WebConfig{Username: "admin", Password: "a-unique-local-password"}}
	if _, _, err := server.issueSessionToken(); err == nil {
		t.Fatal("issueSessionToken() error = nil, want missing secret rejection")
	}
}
