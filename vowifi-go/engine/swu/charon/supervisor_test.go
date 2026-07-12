package charon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveBinaryPathFromEnv(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "charon")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	old := os.Getenv("VOHIVE_CHARON_BINARY")
	t.Setenv("VOHIVE_CHARON_BINARY", bin)
	t.Cleanup(func() {
		_ = old
	})

	if got := resolveBinaryPath(); got.Path != bin {
		t.Fatalf("resolveBinaryPath() path = %q, want %q", got.Path, bin)
	}
}
