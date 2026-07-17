package config

import (
	"os"
	"strings"
	"testing"
)

func TestValidateWebCredentialsRejectsUnsafeStartupPasswords(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{name: "missing password", username: "admin", password: ""},
		{name: "blank password", username: "admin", password: "   "},
		{name: "legacy default", username: "admin", password: "admin"},
		{name: "legacy default mixed case", username: "admin", password: "AdMiN"},
		{name: "example placeholder", username: "admin", password: "CHANGE_ME_BEFORE_FIRST_RUN"},
		{name: "generic placeholder", username: "admin", password: "placeholder"},
		{name: "missing username", username: "", password: "a-unique-local-password"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWebCredentials(WebConfig{
				Username: tt.username,
				Password: tt.password,
			})
			if err == nil {
				t.Fatal("ValidateWebCredentials() error = nil, want fail-closed error")
			}
			if strings.Contains(err.Error(), tt.password) && strings.TrimSpace(tt.password) != "" {
				t.Fatalf("validation error exposed rejected password: %v", err)
			}
		})
	}
}

func TestValidateWebCredentialsAcceptsInitializedCredentials(t *testing.T) {
	tests := []WebConfig{
		{Username: "admin", Password: "a-unique-local-password"},
		{Username: "operator", Password: "$2b$10$syntheticBcryptHashForStartupValidationOnly"},
	}

	for _, web := range tests {
		if err := ValidateWebCredentials(web); err != nil {
			t.Fatalf("ValidateWebCredentials() error = %v", err)
		}
	}
}

func TestLoadForStartupFailsClosedWithoutInitializedWebPassword(t *testing.T) {
	path := writeTempConfig(t, `
server:
  port: 7575
web:
  username: admin
`)

	if _, err := LoadForStartup(path); err == nil {
		t.Fatal("LoadForStartup() error = nil, want missing Web password rejection")
	}
}

func TestLoadForStartupAcceptsExplicitWebPassword(t *testing.T) {
	path := writeTempConfig(t, `
server:
  port: 7575
web:
  username: admin
  password: a-unique-local-password
`)

	cfg, err := LoadForStartup(path)
	if err != nil {
		t.Fatalf("LoadForStartup() error = %v", err)
	}
	if cfg.Server.Port != ":7575" {
		t.Fatalf("Server.Port = %q, want %q", cfg.Server.Port, ":7575")
	}
}

func TestInitGlobalManagerForStartupRejectsPlaceholderPassword(t *testing.T) {
	path := writeTempConfig(t, `
web:
  username: admin
  password: CHANGE_ME_BEFORE_FIRST_RUN
`)

	if err := InitGlobalManagerForStartup(path); err == nil {
		t.Fatal("InitGlobalManagerForStartup() error = nil, want placeholder rejection")
	}
}

func TestSecureGlobalManagerRejectsUnsafeReload(t *testing.T) {
	path := writeTempConfig(t, `
web:
  username: admin
  password: initial-unique-password
`)
	if err := InitGlobalManagerForStartup(path); err != nil {
		t.Fatalf("InitGlobalManagerForStartup() error = %v", err)
	}

	if err := os.WriteFile(path, []byte("web:\n  username: admin\n  password: admin\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := ReloadFromFile(); err == nil {
		t.Fatal("ReloadFromFile() error = nil, want unsafe credential rejection")
	}
	if got := GetConfig().Web.Password; got != "initial-unique-password" {
		t.Fatalf("global password changed after rejected reload: %q", got)
	}
}
