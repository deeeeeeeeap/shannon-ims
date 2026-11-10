package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/config"
	"github.com/gin-gonic/gin"
)

// The device form sends neither serial parameters nor the operator selection.
// Saving it must not wipe what the config file and the operator-selection
// endpoint stored for the device.
func TestDeviceConfigFromDTOWithBaseKeepsOmittedSerialAndOperatorSelection(t *testing.T) {
	base := config.DeviceConfig{
		ID:                    "dev1",
		BaudRate:              9600,
		DataBits:              7,
		StopBits:              2,
		Parity:                "E",
		OperatorSelectionMode: "manual",
		OperatorSelectionPLMN: "310260",
		OperatorSelectionRAT:  "lte",
	}

	cfg := deviceConfigFromDTOWithBase(deviceConfigDTO{ID: "dev1", Name: "renamed"}, &base)

	if cfg.BaudRate != 9600 || cfg.DataBits != 7 || cfg.StopBits != 2 || cfg.Parity != "E" {
		t.Fatalf("serial parameters lost: %+v", cfg)
	}
	if cfg.OperatorSelectionMode != "manual" || cfg.OperatorSelectionPLMN != "310260" || cfg.OperatorSelectionRAT != "lte" {
		t.Fatalf("operator selection lost: mode=%q plmn=%q rat=%q", cfg.OperatorSelectionMode, cfg.OperatorSelectionPLMN, cfg.OperatorSelectionRAT)
	}
	if cfg.Name != "renamed" {
		t.Fatalf("Name=%q, want the submitted value", cfg.Name)
	}
}

func TestDeviceConfigFromDTOWithBaseAppliesExplicitSerialAndOperatorSelection(t *testing.T) {
	base := config.DeviceConfig{
		ID:                    "dev1",
		BaudRate:              9600,
		Parity:                "E",
		OperatorSelectionMode: "manual",
		OperatorSelectionPLMN: "310260",
		OperatorSelectionRAT:  "lte",
	}

	cfg := deviceConfigFromDTOWithBase(deviceConfigDTO{
		ID:                    "dev1",
		BaudRate:              460800,
		Parity:                "N",
		OperatorSelectionMode: "automatic",
	}, &base)

	if cfg.BaudRate != 460800 || cfg.Parity != "N" {
		t.Fatalf("explicit serial parameters ignored: baud=%d parity=%q", cfg.BaudRate, cfg.Parity)
	}
	// An explicit selection replaces all three fields; a stale PLMN or RAT
	// from the previous manual choice must not leak into the new one.
	if cfg.OperatorSelectionMode != "automatic" || cfg.OperatorSelectionPLMN != "" || cfg.OperatorSelectionRAT != "" {
		t.Fatalf("operator selection = %q/%q/%q, want automatic with no PLMN or RAT", cfg.OperatorSelectionMode, cfg.OperatorSelectionPLMN, cfg.OperatorSelectionRAT)
	}
}

func TestDeviceConfigFromDTOWithoutBaseLeavesSerialUnset(t *testing.T) {
	cfg := deviceConfigFromDTO(deviceConfigDTO{ID: "dev1"})
	if cfg.BaudRate != 0 || cfg.DataBits != 0 || cfg.StopBits != 0 || cfg.Parity != "" {
		t.Fatalf("a new device must not get invented serial parameters: %+v", cfg)
	}
	if got := cfg.SerialSettings(); got.BaudRate != 115200 || got.DataBits != 8 || got.StopBits != 1 || got.Parity != "N" {
		t.Fatalf("effective serial settings = %+v, want 115200 8N1", got)
	}
}

// A typo in device_backend used to be accepted and silently run as AT.
func TestBackendModeValidationRejectsUnknownValues(t *testing.T) {
	for _, mode := range []string{"", "at", "AT", "qmi", " mbim "} {
		if err := backend.ValidateBackendMode(mode); err != nil {
			t.Errorf("ValidateBackendMode(%q) = %v, want nil", mode, err)
		}
		if err := validateDeviceBackendConfig(config.DeviceConfig{DeviceBackend: mode}); err != nil {
			t.Errorf("validateDeviceBackendConfig(%q) = %v, want nil", mode, err)
		}
	}
	for _, mode := range []string{"qmii", "auto", "serial"} {
		if err := backend.ValidateBackendMode(mode); err == nil {
			t.Errorf("ValidateBackendMode(%q) = nil, want error", mode)
		}
		if err := validateDeviceBackendConfig(config.DeviceConfig{DeviceBackend: mode}); err == nil {
			t.Errorf("validateDeviceBackendConfig(%q) = nil, want error", mode)
		}
	}
	// Normalisation keeps its lenient contract for configs written before the
	// check existed.
	if got := backend.NormalizeBackendMode("qmii"); got != backend.BackendAT {
		t.Fatalf("NormalizeBackendMode(unknown) = %q, want %q", got, backend.BackendAT)
	}
}

func TestSystemInfoReportsConfigFindings(t *testing.T) {
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := "devices:\n- id: dev1\n  device_backend: qmii\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := config.InitGlobalManager(path); err != nil {
		t.Fatalf("InitGlobalManager() error = %v", err)
	}

	s := &Server{configPath: path}
	query := func() map[string]json.RawMessage {
		t.Helper()
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/system/info", nil)
		s.handleSystemInfo(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return body
	}

	body := query()
	var issues []config.Issue
	if err := json.Unmarshal(body["config_issues"], &issues); err != nil {
		t.Fatalf("decode config_issues: %v", err)
	}
	if len(issues) != 1 || issues[0].Path != "devices[0].device_backend" || issues[0].Severity != config.SeverityWarning {
		t.Fatalf("config_issues = %+v, want one device_backend warning", issues)
	}
	var reportedPath string
	if err := json.Unmarshal(body["config"], &reportedPath); err != nil || reportedPath != path {
		t.Fatalf("config = %s, want the path the server was started with", body["config"])
	}

	// After the operator fixes the file the list is an empty array, not null.
	if err := config.UpdateDeviceInFile(path, "dev1", config.DeviceConfig{ID: "dev1", DeviceBackend: "qmi"}); err != nil {
		t.Fatalf("UpdateDeviceInFile() error = %v", err)
	}
	if got := string(query()["config_issues"]); got != "[]" {
		t.Fatalf("config_issues = %s, want []", got)
	}
}
