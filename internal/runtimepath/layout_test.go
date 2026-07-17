package runtimepath

import (
	"path/filepath"
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

func TestResolveRejectsFilesystemRootAsRuntimeRoot(t *testing.T) {
	volumeRoot := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	configPath := filepath.Join(volumeRoot, "config", "config.yaml")
	if _, err := Resolve("", configPath); err == nil {
		t.Fatalf("Resolve(%q) error = nil, want filesystem-root rejection", configPath)
	}
}
