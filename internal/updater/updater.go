package updater

import (
	"errors"
	"os"
	"strings"

	"github.com/1239t/vohive/internal/global"
)

var ErrAutomaticUpdateDisabled = errors.New("automatic updates are disabled until signed Shannon IMS release metadata is available")

type UpdateInfo struct {
	Enabled     bool   `json:"enabled"`
	HasUpdate   bool   `json:"has_update"`
	CurrentVer  string `json:"current_version"`
	LatestVer   string `json:"latest_version"`
	ReleaseNote string `json:"release_note"`
	IsDocker    bool   `json:"is_docker"`
	Reason      string `json:"reason,omitempty"`
}

// CheckUpdate reports the fail-closed updater state without contacting any
// legacy or third-party release repository. Automatic updates can be enabled
// again only after Shannon IMS publishes project-owned, signed metadata and
// verifies the selected artifact before replacement.
func CheckUpdate() (*UpdateInfo, error) {
	currentVersion := strings.TrimSpace(global.Version)
	if currentVersion == "" {
		currentVersion = "unknown"
	}

	_, dockerErr := os.Stat("/.dockerenv")
	return &UpdateInfo{
		Enabled:    false,
		HasUpdate:  false,
		CurrentVer: currentVersion,
		IsDocker:   dockerErr == nil,
		Reason:     ErrAutomaticUpdateDisabled.Error(),
	}, nil
}

// ApplyUpdate is intentionally fail-closed until signed release metadata and
// artifact verification are implemented for the Shannon IMS repository.
func ApplyUpdate() error {
	return ErrAutomaticUpdateDisabled
}
