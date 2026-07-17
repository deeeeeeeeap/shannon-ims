package runtimepath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Layout contains every mutable runtime path rooted at one absolute directory.
type Layout struct {
	Root             string
	ConfigFile       string
	DataDir          string
	LogDir           string
	LogFile          string
	Database         string
	LegacyDatabase   string
	CarrierOverrides string
	CountryTable     string
}

// Resolve derives an absolute runtime layout. An explicit root wins; otherwise
// a conventional <root>/config/config.yaml path identifies <root>.
func Resolve(rootOverride, configPath string) (Layout, error) {
	rootOverride = strings.TrimSpace(rootOverride)
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = filepath.Join("config", "config.yaml")
	}

	var root string
	var configFile string
	var err error
	if rootOverride != "" {
		root, err = filepath.Abs(rootOverride)
		if err != nil {
			return Layout{}, fmt.Errorf("resolve runtime root: %w", err)
		}
		if filepath.IsAbs(configPath) {
			configFile = filepath.Clean(configPath)
		} else {
			configFile = filepath.Join(root, configPath)
		}
	} else {
		configFile, err = filepath.Abs(configPath)
		if err != nil {
			return Layout{}, fmt.Errorf("resolve config path: %w", err)
		}
		configDir := filepath.Dir(configFile)
		if filepath.Base(configDir) == "config" {
			root = filepath.Dir(configDir)
		} else {
			root = configDir
		}
	}

	root = filepath.Clean(root)
	configFile = filepath.Clean(configFile)
	if filepath.Dir(root) == root {
		return Layout{}, fmt.Errorf("runtime root must not be a filesystem root: %q", root)
	}
	dataDir := filepath.Join(root, "data")
	logDir := filepath.Join(root, "logs")
	return Layout{
		Root:             root,
		ConfigFile:       configFile,
		DataDir:          dataDir,
		LogDir:           logDir,
		LogFile:          filepath.Join(logDir, "app.log"),
		Database:         filepath.Join(dataDir, "vohive.db"),
		LegacyDatabase:   filepath.Join(dataDir, "ec20.db"),
		CarrierOverrides: filepath.Join(dataDir, "carrier_overrides.json"),
		CountryTable:     filepath.Join(dataDir, "mcc-mnc-table.json"),
	}, nil
}

// ValidateRemoval returns the physical target only when both its lexical and
// resolved paths are strict children of the absolute runtime root. Symlink or
// junction redirection below the root is rejected rather than followed.
func ValidateRemoval(root, target string) (string, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	target = filepath.Clean(strings.TrimSpace(target))
	if root == "." || target == "." || !filepath.IsAbs(root) || !filepath.IsAbs(target) {
		return "", fmt.Errorf("runtime removal paths must be absolute")
	}
	if filepath.Dir(root) == root {
		return "", fmt.Errorf("runtime root must not be a filesystem root: %q", root)
	}
	rel, err := strictChildRel(root, target)
	if err != nil {
		return "", err
	}

	physicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve physical runtime root %q: %w", root, err)
	}
	physicalRoot = filepath.Clean(physicalRoot)
	if filepath.Dir(physicalRoot) == physicalRoot {
		return "", fmt.Errorf("physical runtime root must not be a filesystem root: %q", physicalRoot)
	}

	physicalTarget, err := resolvePhysicalPath(target)
	if err != nil {
		return "", fmt.Errorf("resolve physical removal target %q: %w", target, err)
	}
	if _, err := strictChildRel(physicalRoot, physicalTarget); err != nil {
		return "", fmt.Errorf("physical removal target escapes runtime root: %w", err)
	}

	expectedTarget := filepath.Join(physicalRoot, rel)
	if !samePath(expectedTarget, physicalTarget) {
		return "", fmt.Errorf("removal target %q is redirected below runtime root %q", target, root)
	}
	return physicalTarget, nil
}

func strictChildRel(root, target string) (string, error) {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", fmt.Errorf("resolve runtime removal target: %w", err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("removal target %q is outside runtime root %q", target, root)
	}
	return rel, nil
}

// resolvePhysicalPath resolves all existing path components. A missing final
// target is represented beneath its nearest existing physical parent so that
// uninstall remains safe and idempotent without requiring every target to
// exist. Dangling links fail closed.
func resolvePhysicalPath(path string) (string, error) {
	current := filepath.Clean(path)
	var missing []string
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		} else if !os.IsNotExist(err) {
			return "", err
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing parent for %q", path)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func samePath(left, right string) bool {
	rel, err := filepath.Rel(filepath.Clean(left), filepath.Clean(right))
	return err == nil && rel == "."
}
