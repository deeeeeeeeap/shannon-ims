package api

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const sessionSecretSize = 32

func sessionSecretPath(runtimeRoot string) string {
	runtimeRoot = strings.TrimSpace(runtimeRoot)
	return filepath.Join(runtimeRoot, "data", "session-secret")
}

func loadOrCreateSessionSecret(path string) ([]byte, error) {
	if secret, err := readSessionSecret(path); err == nil {
		return secret, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create session secret directory: %w", err)
	}

	secret := make([]byte, sessionSecretSize)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, fmt.Errorf("generate session secret: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".session-secret-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary session secret: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	closeWithError := func() error {
		if err := tmp.Close(); err != nil {
			return fmt.Errorf("close temporary session secret: %w", err)
		}
		return nil
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("protect temporary session secret: %w", err)
	}
	if _, err := tmp.Write(secret); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write temporary session secret: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("sync temporary session secret: %w", err)
	}
	if err := closeWithError(); err != nil {
		return nil, err
	}

	// A hard link publishes the fully written inode without replacing an
	// existing secret. Concurrent starters therefore converge on one value.
	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return readSessionSecret(path)
		}
		return nil, fmt.Errorf("publish session secret: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("protect session secret: %w", err)
	}
	return append([]byte(nil), secret...), nil
}

func readSessionSecret(path string) ([]byte, error) {
	secret, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(secret) != sessionSecretSize {
		return nil, fmt.Errorf("session secret file is invalid: expected %d bytes", sessionSecretSize)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("protect session secret: %w", err)
	}
	return append([]byte(nil), secret...), nil
}
