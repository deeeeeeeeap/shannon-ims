package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

const esimSwitchBlockingDeviceIndex = "idx_esim_switch_one_blocking_per_device"

type ESIMSwitchPhase string

const (
	ESIMSwitchPhaseIntentPersisted           ESIMSwitchPhase = "intent_persisted"
	ESIMSwitchPhaseTeardownPlanned           ESIMSwitchPhase = "teardown_planned"
	ESIMSwitchPhaseApplyPlanned              ESIMSwitchPhase = "apply_planned"
	ESIMSwitchPhaseAccepted                  ESIMSwitchPhase = "accepted"
	ESIMSwitchPhaseRestoring                 ESIMSwitchPhase = "restoring"
	ESIMSwitchPhaseNeedsReconciliation       ESIMSwitchPhase = "needs_reconciliation"
	ESIMSwitchPhaseFailedBeforePhysicalApply ESIMSwitchPhase = "failed_before_physical_apply"
	ESIMSwitchPhaseSucceeded                 ESIMSwitchPhase = "succeeded"
)

type ESIMSwitchAcceptanceState string

const (
	ESIMSwitchAcceptanceUnknown  ESIMSwitchAcceptanceState = "unknown"
	ESIMSwitchAcceptanceAccepted ESIMSwitchAcceptanceState = "accepted"
	ESIMSwitchAcceptanceRejected ESIMSwitchAcceptanceState = "rejected"
)

type ESIMSwitchRadioState string

const (
	ESIMSwitchRadioUnknown ESIMSwitchRadioState = "unknown"
	ESIMSwitchRadioOnline  ESIMSwitchRadioState = "online"
	ESIMSwitchRadioFlight  ESIMSwitchRadioState = "flight"
)

const ESIMSwitchOperationProfileSwitch = "profile_switch"

const (
	ESIMSwitchErrorNone              = ""
	ESIMSwitchErrorJournalWrite      = "journal_write_failed"
	ESIMSwitchErrorTeardown          = "teardown_failed"
	ESIMSwitchErrorApplyUnknown      = "apply_result_unknown"
	ESIMSwitchErrorRecovery          = "recovery_failed"
	ESIMSwitchErrorDeviceUnavailable = "device_unavailable"
	ESIMSwitchErrorProfileAmbiguous  = "profile_ambiguous"
)

var (
	ErrESIMSwitchJournalUnavailable  = errors.New("eSIM switch journal unavailable")
	ErrESIMSwitchOperationInvalid    = errors.New("invalid eSIM switch operation")
	ErrESIMSwitchOperationInProgress = errors.New("eSIM switch operation already in progress")
	ErrESIMSwitchOperationNotFound   = errors.New("eSIM switch operation not found")
	ErrESIMSwitchOperationStale      = errors.New("stale eSIM switch operation update")
)

// ESIMSwitchOperation is the durable, privacy-bounded state for one profile
// switch. Values stored in Phase, AcceptanceState, PreRadioState, and ErrorCode
// are validated finite enums at the store boundary before rows are written.
type ESIMSwitchOperation struct {
	OperationID         string                    `gorm:"column:operation_id;primaryKey;size:64" json:"-"`
	DeviceID            string                    `gorm:"column:device_id;not null;size:255" json:"-"`
	OwnerEpoch          string                    `gorm:"column:owner_epoch;not null;size:64" json:"-"`
	WorkerGeneration    uint64                    `gorm:"column:worker_generation;not null" json:"-"`
	OperationType       string                    `gorm:"column:operation_type;not null;size:32"`
	TargetICCID         string                    `gorm:"column:target_iccid;not null;size:32" json:"-"`
	PreNetworkConnected bool                      `gorm:"column:pre_network_connected;not null"`
	PreNetworkEnabled   bool                      `gorm:"column:pre_network_enabled;not null"`
	PreVoWiFiActive     bool                      `gorm:"column:pre_vowifi_active;not null"`
	PreRadioState       ESIMSwitchRadioState      `gorm:"column:pre_radio_state;not null;size:16"`
	Phase               ESIMSwitchPhase           `gorm:"column:phase;not null;size:48"`
	AcceptanceState     ESIMSwitchAcceptanceState `gorm:"column:acceptance_state;not null;size:16"`
	Version             uint64                    `gorm:"column:version;not null"`
	ErrorCode           string                    `gorm:"column:error_code;not null;size:48"`
	Terminal            bool                      `gorm:"column:terminal;not null;default:false"`
	ReconcileOwnerEpoch string                    `gorm:"column:reconcile_owner_epoch;not null;size:64" json:"-"`
	ReconcileGeneration uint64                    `gorm:"column:reconcile_generation;not null" json:"-"`
	CreatedAt           time.Time                 `gorm:"column:created_at;not null"`
	UpdatedAt           time.Time                 `gorm:"column:updated_at;not null"`
	CompletedAt         *time.Time                `gorm:"column:completed_at"`
}

func (ESIMSwitchOperation) TableName() string { return "esim_switch_operations" }

type CreateESIMSwitchOperationInput struct {
	OperationID         string
	DeviceID            string
	OwnerEpoch          string
	WorkerGeneration    uint64
	TargetICCID         string
	PreNetworkConnected bool
	PreNetworkEnabled   bool
	PreVoWiFiActive     bool
	PreRadioState       ESIMSwitchRadioState
	Now                 time.Time
}

type TransitionESIMSwitchOperationInput struct {
	OperationID         string
	OwnerEpoch          string
	WorkerGeneration    uint64
	ExpectedPhase       ESIMSwitchPhase
	ExpectedVersion     uint64
	NextPhase           ESIMSwitchPhase
	NextAcceptanceState ESIMSwitchAcceptanceState
	ErrorCode           string
	Now                 time.Time
}

type ClaimESIMSwitchOperationInput struct {
	OperationID              string
	ExpectedOwnerEpoch       string
	ExpectedWorkerGeneration uint64
	ExpectedPhase            ESIMSwitchPhase
	ExpectedVersion          uint64
	NewOwnerEpoch            string
	NewWorkerGeneration      uint64
	Now                      time.Time
}

type ESIMSwitchJournalStore struct {
	database *gorm.DB
}

func NewESIMSwitchJournalStore(database *gorm.DB) *ESIMSwitchJournalStore {
	return &ESIMSwitchJournalStore{database: database}
}

func (s *ESIMSwitchJournalStore) Create(ctx context.Context, input CreateESIMSwitchOperationInput) (ESIMSwitchOperation, error) {
	if s == nil || s.database == nil {
		return ESIMSwitchOperation{}, ErrESIMSwitchJournalUnavailable
	}
	operationID := strings.TrimSpace(input.OperationID)
	deviceID := strings.TrimSpace(input.DeviceID)
	ownerEpoch := strings.TrimSpace(input.OwnerEpoch)
	targetICCID := strings.TrimSpace(input.TargetICCID)
	if operationID == "" || deviceID == "" || ownerEpoch == "" || targetICCID == "" ||
		input.WorkerGeneration == 0 || !validESIMSwitchRadioState(input.PreRadioState) {
		return ESIMSwitchOperation{}, ErrESIMSwitchOperationInvalid
	}
	now := input.Now.UTC()
	if input.Now.IsZero() {
		now = time.Now().UTC()
	}
	operation := ESIMSwitchOperation{
		OperationID:         operationID,
		DeviceID:            deviceID,
		OwnerEpoch:          ownerEpoch,
		WorkerGeneration:    input.WorkerGeneration,
		OperationType:       ESIMSwitchOperationProfileSwitch,
		TargetICCID:         targetICCID,
		PreNetworkConnected: input.PreNetworkConnected,
		PreNetworkEnabled:   input.PreNetworkEnabled,
		PreVoWiFiActive:     input.PreVoWiFiActive,
		PreRadioState:       input.PreRadioState,
		Phase:               ESIMSwitchPhaseIntentPersisted,
		AcceptanceState:     ESIMSwitchAcceptanceUnknown,
		Version:             1,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.database.WithContext(ctx).Create(&operation).Error; err != nil {
		if isESIMSwitchBlockingConstraintError(err) {
			return ESIMSwitchOperation{}, ErrESIMSwitchOperationInProgress
		}
		return ESIMSwitchOperation{}, ErrESIMSwitchJournalUnavailable
	}
	return operation, nil
}

func (s *ESIMSwitchJournalStore) GetBlockingByDevice(ctx context.Context, deviceID string) (ESIMSwitchOperation, error) {
	if s == nil || s.database == nil {
		return ESIMSwitchOperation{}, ErrESIMSwitchJournalUnavailable
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return ESIMSwitchOperation{}, ErrESIMSwitchOperationInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var operation ESIMSwitchOperation
	err := s.database.WithContext(ctx).
		Where("device_id = ? AND terminal = ?", deviceID, false).
		Order("created_at DESC").
		First(&operation).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ESIMSwitchOperation{}, ErrESIMSwitchOperationNotFound
	}
	if err != nil {
		return ESIMSwitchOperation{}, ErrESIMSwitchJournalUnavailable
	}
	operation.CreatedAt = operation.CreatedAt.UTC()
	operation.UpdatedAt = operation.UpdatedAt.UTC()
	if operation.CompletedAt != nil {
		completed := operation.CompletedAt.UTC()
		operation.CompletedAt = &completed
	}
	return operation, nil
}

func (s *ESIMSwitchJournalStore) Transition(ctx context.Context, input TransitionESIMSwitchOperationInput) (ESIMSwitchOperation, error) {
	if s == nil || s.database == nil {
		return ESIMSwitchOperation{}, ErrESIMSwitchJournalUnavailable
	}
	input.OperationID = strings.TrimSpace(input.OperationID)
	input.OwnerEpoch = strings.TrimSpace(input.OwnerEpoch)
	input.ErrorCode = strings.TrimSpace(input.ErrorCode)
	if input.OperationID == "" || input.OwnerEpoch == "" || input.WorkerGeneration == 0 ||
		input.ExpectedVersion == 0 || !validESIMSwitchPhase(input.ExpectedPhase) ||
		!validESIMSwitchPhase(input.NextPhase) || !validESIMSwitchTransition(input.ExpectedPhase, input.NextPhase) ||
		!validESIMSwitchAcceptance(input.NextAcceptanceState) ||
		!validESIMSwitchPhaseAcceptance(input.NextPhase, input.NextAcceptanceState) ||
		!validESIMSwitchErrorCode(input.ErrorCode) {
		return ESIMSwitchOperation{}, ErrESIMSwitchOperationInvalid
	}
	now := input.Now.UTC()
	if input.Now.IsZero() {
		now = time.Now().UTC()
	}
	terminal := input.NextPhase == ESIMSwitchPhaseFailedBeforePhysicalApply || input.NextPhase == ESIMSwitchPhaseSucceeded
	updates := map[string]any{
		"phase":            input.NextPhase,
		"acceptance_state": input.NextAcceptanceState,
		"error_code":       input.ErrorCode,
		"terminal":         terminal,
		"updated_at":       now,
		"version":          gorm.Expr("version + 1"),
	}
	if terminal {
		updates["completed_at"] = now
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var updated ESIMSwitchOperation
	err := s.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&ESIMSwitchOperation{}).
			Where(
				"operation_id = ? AND owner_epoch = ? AND worker_generation = ? AND phase = ? AND version = ? AND terminal = ?",
				input.OperationID,
				input.OwnerEpoch,
				input.WorkerGeneration,
				input.ExpectedPhase,
				input.ExpectedVersion,
				false,
			).
			Updates(updates)
		if result.Error != nil {
			return ErrESIMSwitchJournalUnavailable
		}
		if result.RowsAffected != 1 {
			return ErrESIMSwitchOperationStale
		}
		if err := tx.Where("operation_id = ?", input.OperationID).First(&updated).Error; err != nil {
			return ErrESIMSwitchJournalUnavailable
		}
		return nil
	})
	if err != nil {
		return ESIMSwitchOperation{}, err
	}
	updated.CreatedAt = updated.CreatedAt.UTC()
	updated.UpdatedAt = updated.UpdatedAt.UTC()
	if updated.CompletedAt != nil {
		completed := updated.CompletedAt.UTC()
		updated.CompletedAt = &completed
	}
	return updated, nil
}

func (s *ESIMSwitchJournalStore) ClaimForReconciliation(ctx context.Context, input ClaimESIMSwitchOperationInput) (ESIMSwitchOperation, error) {
	if s == nil || s.database == nil {
		return ESIMSwitchOperation{}, ErrESIMSwitchJournalUnavailable
	}
	input.OperationID = strings.TrimSpace(input.OperationID)
	input.ExpectedOwnerEpoch = strings.TrimSpace(input.ExpectedOwnerEpoch)
	input.NewOwnerEpoch = strings.TrimSpace(input.NewOwnerEpoch)
	if input.OperationID == "" || input.ExpectedOwnerEpoch == "" || input.NewOwnerEpoch == "" ||
		input.ExpectedWorkerGeneration == 0 || input.NewWorkerGeneration == 0 ||
		input.ExpectedVersion == 0 || !validESIMSwitchPhase(input.ExpectedPhase) {
		return ESIMSwitchOperation{}, ErrESIMSwitchOperationInvalid
	}
	now := input.Now.UTC()
	if input.Now.IsZero() {
		now = time.Now().UTC()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var claimed ESIMSwitchOperation
	err := s.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&ESIMSwitchOperation{}).
			Where(
				"operation_id = ? AND owner_epoch = ? AND worker_generation = ? AND phase = ? AND version = ? AND terminal = ?",
				input.OperationID,
				input.ExpectedOwnerEpoch,
				input.ExpectedWorkerGeneration,
				input.ExpectedPhase,
				input.ExpectedVersion,
				false,
			).
			Where(
				"NOT (reconcile_owner_epoch = ? AND reconcile_generation = ?)",
				input.NewOwnerEpoch,
				input.NewWorkerGeneration,
			).
			Updates(map[string]any{
				"owner_epoch":           input.NewOwnerEpoch,
				"worker_generation":     input.NewWorkerGeneration,
				"reconcile_owner_epoch": input.NewOwnerEpoch,
				"reconcile_generation":  input.NewWorkerGeneration,
				"updated_at":            now,
				"version":               gorm.Expr("version + 1"),
			})
		if result.Error != nil {
			return ErrESIMSwitchJournalUnavailable
		}
		if result.RowsAffected != 1 {
			return ErrESIMSwitchOperationStale
		}
		if err := tx.Where("operation_id = ?", input.OperationID).First(&claimed).Error; err != nil {
			return ErrESIMSwitchJournalUnavailable
		}
		return nil
	})
	if err != nil {
		return ESIMSwitchOperation{}, err
	}
	claimed.CreatedAt = claimed.CreatedAt.UTC()
	claimed.UpdatedAt = claimed.UpdatedAt.UTC()
	if claimed.CompletedAt != nil {
		completed := claimed.CompletedAt.UTC()
		claimed.CompletedAt = &completed
	}
	return claimed, nil
}

func validESIMSwitchRadioState(state ESIMSwitchRadioState) bool {
	switch state {
	case ESIMSwitchRadioUnknown, ESIMSwitchRadioOnline, ESIMSwitchRadioFlight:
		return true
	default:
		return false
	}
}

func validESIMSwitchPhase(phase ESIMSwitchPhase) bool {
	switch phase {
	case ESIMSwitchPhaseIntentPersisted,
		ESIMSwitchPhaseTeardownPlanned,
		ESIMSwitchPhaseApplyPlanned,
		ESIMSwitchPhaseAccepted,
		ESIMSwitchPhaseRestoring,
		ESIMSwitchPhaseNeedsReconciliation,
		ESIMSwitchPhaseFailedBeforePhysicalApply,
		ESIMSwitchPhaseSucceeded:
		return true
	default:
		return false
	}
}

func validESIMSwitchTransition(from, to ESIMSwitchPhase) bool {
	switch from {
	case ESIMSwitchPhaseIntentPersisted:
		return to == ESIMSwitchPhaseTeardownPlanned || to == ESIMSwitchPhaseFailedBeforePhysicalApply
	case ESIMSwitchPhaseTeardownPlanned:
		return to == ESIMSwitchPhaseApplyPlanned || to == ESIMSwitchPhaseAccepted || to == ESIMSwitchPhaseNeedsReconciliation
	case ESIMSwitchPhaseApplyPlanned:
		return to == ESIMSwitchPhaseAccepted || to == ESIMSwitchPhaseNeedsReconciliation
	case ESIMSwitchPhaseAccepted:
		return to == ESIMSwitchPhaseRestoring || to == ESIMSwitchPhaseNeedsReconciliation
	case ESIMSwitchPhaseRestoring:
		return to == ESIMSwitchPhaseSucceeded || to == ESIMSwitchPhaseNeedsReconciliation
	case ESIMSwitchPhaseNeedsReconciliation:
		return to == ESIMSwitchPhaseAccepted
	default:
		return false
	}
}

func validESIMSwitchAcceptance(state ESIMSwitchAcceptanceState) bool {
	switch state {
	case ESIMSwitchAcceptanceUnknown, ESIMSwitchAcceptanceAccepted, ESIMSwitchAcceptanceRejected:
		return true
	default:
		return false
	}
}

func validESIMSwitchPhaseAcceptance(phase ESIMSwitchPhase, state ESIMSwitchAcceptanceState) bool {
	switch phase {
	case ESIMSwitchPhaseIntentPersisted,
		ESIMSwitchPhaseTeardownPlanned,
		ESIMSwitchPhaseApplyPlanned,
		ESIMSwitchPhaseFailedBeforePhysicalApply:
		return state == ESIMSwitchAcceptanceUnknown
	case ESIMSwitchPhaseAccepted,
		ESIMSwitchPhaseRestoring,
		ESIMSwitchPhaseSucceeded:
		return state == ESIMSwitchAcceptanceAccepted
	case ESIMSwitchPhaseNeedsReconciliation:
		return state == ESIMSwitchAcceptanceUnknown ||
			state == ESIMSwitchAcceptanceAccepted ||
			state == ESIMSwitchAcceptanceRejected
	default:
		return false
	}
}

func validESIMSwitchErrorCode(code string) bool {
	switch code {
	case ESIMSwitchErrorNone,
		ESIMSwitchErrorJournalWrite,
		ESIMSwitchErrorTeardown,
		ESIMSwitchErrorApplyUnknown,
		ESIMSwitchErrorRecovery,
		ESIMSwitchErrorDeviceUnavailable,
		ESIMSwitchErrorProfileAmbiguous:
		return true
	default:
		return false
	}
}

func isESIMSwitchBlockingConstraintError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint failed") &&
		strings.Contains(message, "esim_switch_operations.device_id")
}

// RunESIMSwitchJournalMigration creates the switch journal and its cross-process
// per-device exclusion constraint in one SQLite transaction. It is safe to run
// repeatedly during startup.
func RunESIMSwitchJournalMigration(database *gorm.DB) error {
	if database == nil {
		return fmt.Errorf("eSIM switch journal migration: database is nil")
	}
	return database.Transaction(func(migration *gorm.DB) error {
		if err := migration.AutoMigrate(&ESIMSwitchOperation{}); err != nil {
			return fmt.Errorf("eSIM switch journal migration: create schema: %w", err)
		}
		if err := migration.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS idx_esim_switch_one_blocking_per_device
			ON esim_switch_operations(device_id)
			WHERE terminal = 0
		`).Error; err != nil {
			return fmt.Errorf("eSIM switch journal migration: create blocking index: %w", err)
		}

		var indexSQL string
		if err := migration.Raw(
			"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
			esimSwitchBlockingDeviceIndex,
		).Scan(&indexSQL).Error; err != nil {
			return fmt.Errorf("eSIM switch journal migration: verify blocking index: %w", err)
		}
		normalized := strings.ToLower(strings.Join(strings.Fields(indexSQL), " "))
		if !strings.Contains(normalized, "create unique index") ||
			!strings.Contains(normalized, "where terminal = 0") {
			return fmt.Errorf("eSIM switch journal migration: blocking index verification failed")
		}
		return nil
	})
}
