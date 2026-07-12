package device

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveMBIMProxyBinaryFallsBackToKnownPath(t *testing.T) {
	// 构造一个临时"二进制"作为已知安装位置,验证不在 PATH 时也能找到。
	dir := t.TempDir()
	fake := filepath.Join(dir, "mbim-proxy")
	if err := os.WriteFile(fake, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatalf("write fake: %v", err)
	}

	orig := mbimProxyCandidatePaths
	t.Cleanup(func() { mbimProxyCandidatePaths = orig })
	mbimProxyCandidatePaths = []string{"/nonexistent/mbim-proxy", fake}

	if got := resolveMBIMProxyBinary(); got != fake {
		t.Fatalf("resolveMBIMProxyBinary() = %q, want %q", got, fake)
	}
}

func TestResolveMBIMProxyBinaryReturnsEmptyWhenAbsent(t *testing.T) {
	orig := mbimProxyCandidatePaths
	t.Cleanup(func() { mbimProxyCandidatePaths = orig })
	mbimProxyCandidatePaths = []string{filepath.Join(t.TempDir(), "absent-mbim-proxy")}

	// 注意:若运行环境恰好 PATH 里有 mbim-proxy,LookPath 会命中;此时跳过断言。
	if got := resolveMBIMProxyBinary(); got != "" {
		t.Skipf("环境 PATH 中存在 mbim-proxy(%q),跳过缺失断言", got)
	}
}
