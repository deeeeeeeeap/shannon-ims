package api

import (
	"path/filepath"
	"testing"
)

// resolveUninstallTargets 必须使用运行时实际加载的配置文件路径，
// 而不是硬编码相对路径 "config"——后者在 OpenWrt 部署下（通过 -c 传入
// /etc/vohive/config.yaml，与进程工作目录无关）永远指向一个不存在的目录，
// 导致真实配置文件从未被清理。
func TestResolveUninstallTargetsUsesStrictRuntimeChildren(t *testing.T) {
	root := t.TempDir()
	configFile := filepath.Join(root, "config", "config.yaml")
	executable := filepath.Join(root, "bin", "shannon-ims")

	targets, err := resolveUninstallTargets(root, configFile, executable)
	if err != nil {
		t.Fatalf("resolveUninstallTargets() error = %v", err)
	}
	if targets.DataDir != filepath.Join(root, "data") {
		t.Fatalf("DataDir = %q, want runtime data directory", targets.DataDir)
	}
	if targets.ConfigFile != configFile {
		t.Fatalf("ConfigFile = %q, want %q", targets.ConfigFile, configFile)
	}
	if targets.Executable != executable {
		t.Fatalf("Executable = %q, want %q", targets.Executable, executable)
	}
}

func TestResolveUninstallTargetsSkipsConfigWhenPathUnknown(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "bin", "shannon-ims")
	targets, err := resolveUninstallTargets(root, "", executable)
	if err != nil {
		t.Fatalf("resolveUninstallTargets() error = %v", err)
	}
	if targets.ConfigFile != "" {
		t.Fatalf("ConfigFile = %q, want empty when config path unknown", targets.ConfigFile)
	}
}

func TestResolveUninstallTargetsRejectsPathsOutsideRuntimeRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "unrelated")
	insideConfig := filepath.Join(root, "config", "config.yaml")
	insideExecutable := filepath.Join(root, "bin", "shannon-ims")

	for name, paths := range map[string][2]string{
		"config outside root":     {outside, insideExecutable},
		"executable outside root": {insideConfig, outside},
		"root as config target":   {root, insideExecutable},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveUninstallTargets(root, paths[0], paths[1]); err == nil {
				t.Fatal("resolveUninstallTargets() error = nil, want unsafe path rejection")
			}
		})
	}
}

// detectServiceStopCommands 决定自毁前应主动通知哪个服务管理器停止+禁用自启，
// 这样即使删除可执行文件失败（例如只读文件系统），supervisor 也不会把进程重新拉起来，
// 而不是像原来那样仅依赖"删掉自己导致 exec 失败"这种脆弱的副作用。
func TestDetectServiceStopCommandsPrefersOpenWrtInitScript(t *testing.T) {
	statFile := func(path string) bool { return path == "/etc/init.d/vohive" }
	lookPath := func(name string) (string, error) { return "/usr/bin/systemctl", nil }

	cmds := detectServiceStopCommands(lookPath, statFile)

	if len(cmds) != 2 {
		t.Fatalf("len(cmds) = %d, want 2 (disable + stop), got %v", len(cmds), cmds)
	}
	if cmds[0][0] != "/etc/init.d/vohive" || cmds[0][1] != "disable" {
		t.Fatalf("cmds[0] = %v, want [/etc/init.d/vohive disable]", cmds[0])
	}
	if cmds[1][0] != "/etc/init.d/vohive" || cmds[1][1] != "stop" {
		t.Fatalf("cmds[1] = %v, want [/etc/init.d/vohive stop]", cmds[1])
	}
}

func TestDetectServiceStopCommandsFallsBackToSystemd(t *testing.T) {
	statFile := func(path string) bool { return false }
	lookPath := func(name string) (string, error) {
		if name == "systemctl" {
			return "/usr/bin/systemctl", nil
		}
		return "", errNotFound
	}

	cmds := detectServiceStopCommands(lookPath, statFile)

	if len(cmds) != 1 {
		t.Fatalf("len(cmds) = %d, want 1, got %v", len(cmds), cmds)
	}
	want := []string{"systemctl", "disable", "--now", "vohive"}
	if len(cmds[0]) != len(want) {
		t.Fatalf("cmds[0] = %v, want %v", cmds[0], want)
	}
	for i := range want {
		if cmds[0][i] != want[i] {
			t.Fatalf("cmds[0] = %v, want %v", cmds[0], want)
		}
	}
}

func TestDetectServiceStopCommandsEmptyWhenNoSupervisorDetected(t *testing.T) {
	statFile := func(path string) bool { return false }
	lookPath := func(name string) (string, error) { return "", errNotFound }

	cmds := detectServiceStopCommands(lookPath, statFile)

	if len(cmds) != 0 {
		t.Fatalf("cmds = %v, want empty when neither systemd nor openwrt detected", cmds)
	}
}
