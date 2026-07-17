package runtimepath

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveUsesConfigInstallRootInsteadOfWorkingDirectory(t *testing.T) {
	installRoot := t.TempDir()
	configPath := filepath.Join(installRoot, "config", "config.yaml")

	layout, err := Resolve("", configPath)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	wants := map[string]string{
		"root":              installRoot,
		"config":            configPath,
		"data":              filepath.Join(installRoot, "data"),
		"logs":              filepath.Join(installRoot, "logs"),
		"log file":          filepath.Join(installRoot, "logs", "app.log"),
		"database":          filepath.Join(installRoot, "data", "vohive.db"),
		"legacy database":   filepath.Join(installRoot, "data", "ec20.db"),
		"carrier overrides": filepath.Join(installRoot, "data", "carrier_overrides.json"),
		"country table":     filepath.Join(installRoot, "data", "mcc-mnc-table.json"),
	}
	gots := map[string]string{
		"root":              layout.Root,
		"config":            layout.ConfigFile,
		"data":              layout.DataDir,
		"logs":              layout.LogDir,
		"log file":          layout.LogFile,
		"database":          layout.Database,
		"legacy database":   layout.LegacyDatabase,
		"carrier overrides": layout.CarrierOverrides,
		"country table":     layout.CountryTable,
	}
	for name, want := range wants {
		got := gots[name]
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
		if !filepath.IsAbs(got) {
			t.Errorf("%s = %q, want absolute path", name, got)
		}
	}
}

func TestValidateRemovalRequiresStrictChildOfRuntimeRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "data")
	got, err := ValidateRemoval(root, inside)
	if err != nil {
		t.Fatalf("ValidateRemoval(inside) error = %v", err)
	}
	if got != inside {
		t.Fatalf("ValidateRemoval(inside) = %q, want %q", got, inside)
	}

	for name, target := range map[string]string{
		"root itself": root,
		"sibling":     filepath.Join(filepath.Dir(root), "unrelated-data"),
		"parent":      filepath.Dir(root),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateRemoval(root, target); err == nil {
				t.Fatalf("ValidateRemoval(%q) error = nil, want rejection", target)
			}
		})
	}
}

func TestValidateRemovalRejectsSymlinkedParentOutsideRuntimeRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	linkedParent := filepath.Join(root, "config")
	if err := os.Symlink(outside, linkedParent); err != nil {
		t.Skipf("directory symlink unavailable on this platform: %v", err)
	}

	target := filepath.Join(linkedParent, "config.yaml")
	if _, err := ValidateRemoval(root, target); err == nil {
		t.Fatalf("ValidateRemoval(%q) error = nil, want physical escape rejection", target)
	}
}

func TestValidateRemovalRejectsWindowsJunctionOutsideRuntimeRoot(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows junction regression")
	}

	root := t.TempDir()
	outside := t.TempDir()
	junction := filepath.Join(root, "config")
	output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput()
	if err != nil {
		t.Skipf("directory junction unavailable: %v (%s)", err, output)
	}

	target := filepath.Join(junction, "config.yaml")
	if _, err := ValidateRemoval(root, target); err == nil {
		t.Fatalf("ValidateRemoval(%q) error = nil, want junction escape rejection", target)
	}
}

func TestValidateRemovalAllowsMissingTargetUnderExistingRuntimeRoot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "data", "not-created-yet")

	got, err := ValidateRemoval(root, target)
	if err != nil {
		t.Fatalf("ValidateRemoval(missing target) error = %v", err)
	}
	if got != target {
		t.Fatalf("ValidateRemoval(missing target) = %q, want %q", got, target)
	}
}

func TestValidateRemovalAllowsRuntimeRootSymlinkWithoutNestedRedirect(t *testing.T) {
	physicalRoot := t.TempDir()
	aliasParent := t.TempDir()
	rootAlias := filepath.Join(aliasParent, "runtime")
	if err := os.Symlink(physicalRoot, rootAlias); err != nil {
		t.Skipf("directory symlink unavailable on this platform: %v", err)
	}

	got, err := ValidateRemoval(rootAlias, filepath.Join(rootAlias, "data"))
	if err != nil {
		t.Fatalf("ValidateRemoval(root alias) error = %v", err)
	}
	want := filepath.Join(physicalRoot, "data")
	if got != want {
		t.Fatalf("ValidateRemoval(root alias) = %q, want physical target %q", got, want)
	}
}

func TestResolveRejectsFilesystemRootAsRuntimeRoot(t *testing.T) {
	volumeRoot := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	configPath := filepath.Join(volumeRoot, "config", "config.yaml")
	if _, err := Resolve("", configPath); err == nil {
		t.Fatalf("Resolve(%q) error = nil, want filesystem-root rejection", configPath)
	}
}
