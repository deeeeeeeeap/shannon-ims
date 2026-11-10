package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestWriteConfigFileAtomicReplacesContentAndLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("old: true\n"), 0o644); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	if err := writeConfigFileAtomic(path, []byte("new: true\n")); err != nil {
		t.Fatalf("writeConfigFileAtomic() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(got) != "new: true\n" {
		t.Fatalf("content = %q, want the new document", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("temporary files left behind: %v", names)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat config: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("config permissions = %o, want 600 because the file carries credentials", perm)
		}
	}
}

func TestWriteConfigFileAtomicCreatesMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")
	if err := writeConfigFileAtomic(path, []byte("a: 1\n")); err != nil {
		t.Fatalf("writeConfigFileAtomic() error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config not created: %v", err)
	}
}

func TestMutateConfigFileSkipsWriteWhenUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	err = mutateConfigFile(path, func(data []byte) ([]byte, bool, error) {
		return []byte("ignored: true\n"), false, nil
	})
	if err != nil {
		t.Fatalf("mutateConfigFile() error = %v", err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "a: 1\n" {
		t.Fatalf("file rewritten although changed=false: %q", got)
	}
	after, _ := os.Stat(path)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("file touched although changed=false")
	}
}

func TestMutateConfigFileKeepsOriginalWhenMutationFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	want := fmt.Errorf("boom")
	err := mutateConfigFile(path, func(data []byte) ([]byte, bool, error) {
		return []byte("partial"), true, want
	})
	if err != want {
		t.Fatalf("error = %v, want %v", err, want)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "a: 1\n" {
		t.Fatalf("file modified by a failed mutation: %q", got)
	}
}

// Every writer rewrites the whole document. Before the shared lock, a device
// update running next to a notification or proxy update could drop the other
// section or collide on the fixed "<path>.tmp" name.
func TestConcurrentConfigWritersKeepEveryUpdate(t *testing.T) {
	const devices = 12
	var seed strings.Builder
	seed.WriteString("web:\n  username: admin\n  password: initialised-secret\ndevices:\n")
	for i := 0; i < devices; i++ {
		fmt.Fprintf(&seed, "- id: dev%d\n  device_backend: qmi\n", i)
	}
	path := writeTempConfig(t, seed.String())

	imeiFor := func(i int) string { return fmt.Sprintf("8600000000%05d", i) }

	var wg sync.WaitGroup
	errs := make(chan error, devices*3)
	for i := 0; i < devices; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			if err := UpdateDeviceIMEIInFile(path, map[string]string{fmt.Sprintf("dev%d", i): imeiFor(i)}); err != nil {
				errs <- fmt.Errorf("imei dev%d: %w", i, err)
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			inst := ProxyInstance{ID: fmt.Sprintf("p%d", i), Mode: "socks5", ListenAddr: "127.0.0.1", ListenPort: 20000 + i, Enabled: true}
			if err := AddProxyInstanceInFile(path, inst); err != nil {
				errs <- fmt.Errorf("proxy p%d: %w", i, err)
			}
		}(i)
		go func() {
			defer wg.Done()
			webhook := WebhookConfig{Enabled: true, URLs: []string{"https://hooks.example.test/sms"}, TimeoutMs: 5000, RetryMax: 3}
			if err := UpdateNotificationInFile(path, TelegramConfig{}, FeishuConfig{}, QQConfig{}, webhook, BarkConfig{}, EmailConfig{}, PushplusConfig{}); err != nil {
				errs <- fmt.Errorf("notification: %w", err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("config unreadable after concurrent writers: %v", err)
	}
	if len(cfg.Devices) != devices {
		t.Fatalf("devices = %d, want %d", len(cfg.Devices), devices)
	}
	for i, d := range cfg.Devices {
		if d.ModemIMEI != imeiFor(i) {
			t.Errorf("device %s lost its IMEI update: %q", d.ID, d.ModemIMEI)
		}
	}
	if len(cfg.Proxy.Instances) != devices {
		t.Errorf("proxy instances = %d, want %d", len(cfg.Proxy.Instances), devices)
	}
	if !cfg.Webhook.Enabled || len(cfg.Webhook.URLs) != 1 {
		t.Errorf("webhook section lost: %+v", cfg.Webhook)
	}
	if cfg.Web.Username != "admin" {
		t.Errorf("web section lost: username=%q", cfg.Web.Username)
	}

	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

// Reloads are triggered from API handlers and from device goroutines at the
// same time; run with -race this fails on a shared parser instance.
func TestLoadIsSafeForConcurrentUse(t *testing.T) {
	pathA := writeTempConfig(t, "server:\n  port: 7001\ndevices:\n- id: a\n")
	pathB := writeTempConfig(t, "server:\n  port: 7002\ndevices:\n- id: b\n- id: c\n")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path, wantPort, wantDevices := pathA, ":7001", 1
			if i%2 == 1 {
				path, wantPort, wantDevices = pathB, ":7002", 2
			}
			cfg, err := Load(path)
			if err != nil {
				t.Errorf("Load() error = %v", err)
				return
			}
			if cfg.Server.Port != wantPort || len(cfg.Devices) != wantDevices {
				t.Errorf("Load(%s) mixed up documents: port=%q devices=%d", filepath.Base(path), cfg.Server.Port, len(cfg.Devices))
			}
		}(i)
	}
	wg.Wait()
}
