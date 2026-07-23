package db

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestESIMSwitchJournalMigrationIsIdempotent(t *testing.T) {
	dialector, err := openSQLiteDialector("modernc", filepath.Join(t.TempDir(), "journal.db"))
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	database, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}

	for run := 1; run <= 2; run++ {
		if err := RunESIMSwitchJournalMigration(database); err != nil {
			t.Fatalf("migration run %d: %v", run, err)
		}
	}
	if !database.Migrator().HasTable(&ESIMSwitchOperation{}) {
		t.Fatal("migration did not create eSIM switch journal table")
	}

	var indexSQL string
	if err := database.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
		esimSwitchBlockingDeviceIndex,
	).Scan(&indexSQL).Error; err != nil {
		t.Fatalf("load blocking index: %v", err)
	}
	normalized := strings.ToLower(strings.Join(strings.Fields(indexSQL), " "))
	if !strings.Contains(normalized, "create unique index") ||
		!strings.Contains(normalized, "where terminal = 0") {
		t.Fatalf("blocking index is not a partial unique index: %q", indexSQL)
	}
}

func TestESIMSwitchJournalMigrationPreservesSyntheticLegacyDatabase(t *testing.T) {
	database := openESIMSwitchJournalTestDB(t, filepath.Join(t.TempDir(), "legacy.db"))
	if err := database.Exec(`CREATE TABLE legacy_schema_marker (
		id INTEGER PRIMARY KEY,
		value TEXT NOT NULL
	)`).Error; err != nil {
		t.Fatalf("create synthetic legacy schema: %v", err)
	}
	if err := database.Exec("INSERT INTO legacy_schema_marker (id, value) VALUES (?, ?)", 1, "preserved").Error; err != nil {
		t.Fatalf("seed synthetic legacy schema: %v", err)
	}

	for run := 1; run <= 2; run++ {
		if err := RunESIMSwitchJournalMigration(database); err != nil {
			t.Fatalf("migration run %d: %v", run, err)
		}
	}

	var marker string
	if err := database.Raw("SELECT value FROM legacy_schema_marker WHERE id = ?", 1).Scan(&marker).Error; err != nil {
		t.Fatalf("read synthetic legacy row: %v", err)
	}
	if marker != "preserved" {
		t.Fatalf("synthetic legacy row=%q, want preserved", marker)
	}
	if !database.Migrator().HasTable(&ESIMSwitchOperation{}) {
		t.Fatal("migration did not add the eSIM switch journal to the legacy database")
	}
}

func TestInitCreatesESIMSwitchJournalSchema(t *testing.T) {
	previousDB := DB
	t.Cleanup(func() {
		if DB != nil && DB != previousDB {
			if sqlDB, err := DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
		}
		DB = previousDB
	})

	if err := Init(filepath.Join(t.TempDir(), "production-init.db")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !DB.Migrator().HasTable(&ESIMSwitchOperation{}) {
		t.Fatal("Init did not create eSIM switch journal table")
	}
}

func TestESIMSwitchJournalSurvivesDatabaseReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "journal-reopen.db")
	database := openESIMSwitchJournalTestDB(t, dbPath)
	if err := RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migration: %v", err)
	}
	store := NewESIMSwitchJournalStore(database)
	created, err := store.Create(context.Background(), CreateESIMSwitchOperationInput{
		OperationID:         "operation-reopen",
		DeviceID:            "device-reopen",
		OwnerEpoch:          "epoch-reopen",
		WorkerGeneration:    7,
		TargetICCID:         "synthetic-target",
		PreNetworkConnected: true,
		PreVoWiFiActive:     true,
		PreRadioState:       ESIMSwitchRadioOnline,
		Now:                 time.Unix(100, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if created.Version != 1 || created.Phase != ESIMSwitchPhaseIntentPersisted {
		t.Fatalf("created state version=%d phase=%q", created.Version, created.Phase)
	}
	closeESIMSwitchJournalTestDB(t, database)

	reopened := openESIMSwitchJournalTestDB(t, dbPath)
	reopenedStore := NewESIMSwitchJournalStore(reopened)
	got, err := reopenedStore.GetBlockingByDevice(context.Background(), "device-reopen")
	if err != nil {
		t.Fatalf("get reopened operation: %v", err)
	}
	if got.OperationID != created.OperationID || got.OwnerEpoch != created.OwnerEpoch ||
		got.WorkerGeneration != created.WorkerGeneration || got.TargetICCID != created.TargetICCID {
		t.Fatal("reopened operation does not match the committed operation")
	}
	if got.CreatedAt.Location() != time.UTC || got.UpdatedAt.Location() != time.UTC {
		t.Fatal("journal timestamps are not UTC")
	}
}

func TestESIMSwitchJournalRejectsStaleOwnerEpochOrGeneration(t *testing.T) {
	database := openESIMSwitchJournalTestDB(t, filepath.Join(t.TempDir(), "journal-cas.db"))
	if err := RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migration: %v", err)
	}
	store := NewESIMSwitchJournalStore(database)
	created, err := store.Create(context.Background(), CreateESIMSwitchOperationInput{
		OperationID:      "operation-cas",
		DeviceID:         "device-cas",
		OwnerEpoch:       "epoch-current",
		WorkerGeneration: 4,
		TargetICCID:      "synthetic-target",
		PreRadioState:    ESIMSwitchRadioOnline,
		Now:              time.Unix(200, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}

	for name, mutate := range map[string]func(*TransitionESIMSwitchOperationInput){
		"owner":      func(input *TransitionESIMSwitchOperationInput) { input.OwnerEpoch = "epoch-stale" },
		"generation": func(input *TransitionESIMSwitchOperationInput) { input.WorkerGeneration++ },
	} {
		t.Run(name, func(t *testing.T) {
			input := TransitionESIMSwitchOperationInput{
				OperationID:         created.OperationID,
				OwnerEpoch:          created.OwnerEpoch,
				WorkerGeneration:    created.WorkerGeneration,
				ExpectedPhase:       created.Phase,
				ExpectedVersion:     created.Version,
				NextPhase:           ESIMSwitchPhaseTeardownPlanned,
				NextAcceptanceState: ESIMSwitchAcceptanceUnknown,
				Now:                 time.Unix(201, 0).UTC(),
			}
			mutate(&input)
			if _, err := store.Transition(context.Background(), input); !errors.Is(err, ErrESIMSwitchOperationStale) {
				t.Fatalf("Transition() error=%v, want stale operation", err)
			}
		})
	}

	updated, err := store.Transition(context.Background(), TransitionESIMSwitchOperationInput{
		OperationID:         created.OperationID,
		OwnerEpoch:          created.OwnerEpoch,
		WorkerGeneration:    created.WorkerGeneration,
		ExpectedPhase:       created.Phase,
		ExpectedVersion:     created.Version,
		NextPhase:           ESIMSwitchPhaseTeardownPlanned,
		NextAcceptanceState: ESIMSwitchAcceptanceUnknown,
		Now:                 time.Unix(202, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("current Transition(): %v", err)
	}
	if updated.Phase != ESIMSwitchPhaseTeardownPlanned || updated.Version != created.Version+1 {
		t.Fatalf("updated phase=%q version=%d", updated.Phase, updated.Version)
	}
}

func TestESIMSwitchJournalRejectsAcceptanceWithoutEvidence(t *testing.T) {
	database := openESIMSwitchJournalTestDB(t, filepath.Join(t.TempDir(), "journal-acceptance.db"))
	if err := RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migration: %v", err)
	}
	store := NewESIMSwitchJournalStore(database)
	created, err := store.Create(context.Background(), CreateESIMSwitchOperationInput{
		OperationID:      "operation-acceptance",
		DeviceID:         "device-acceptance",
		OwnerEpoch:       "epoch-acceptance",
		WorkerGeneration: 1,
		TargetICCID:      "synthetic-target",
		PreRadioState:    ESIMSwitchRadioUnknown,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}

	if _, err := store.Transition(context.Background(), TransitionESIMSwitchOperationInput{
		OperationID:         created.OperationID,
		OwnerEpoch:          created.OwnerEpoch,
		WorkerGeneration:    created.WorkerGeneration,
		ExpectedPhase:       created.Phase,
		ExpectedVersion:     created.Version,
		NextPhase:           ESIMSwitchPhaseTeardownPlanned,
		NextAcceptanceState: ESIMSwitchAcceptanceAccepted,
	}); !errors.Is(err, ErrESIMSwitchOperationInvalid) {
		t.Fatalf("premature acceptance transition error=%v, want invalid", err)
	}
	blocking, err := store.GetBlockingByDevice(context.Background(), created.DeviceID)
	if err != nil {
		t.Fatalf("reload operation: %v", err)
	}
	if blocking.Phase != created.Phase || blocking.AcceptanceState != ESIMSwitchAcceptanceUnknown ||
		blocking.Version != created.Version {
		t.Fatal("invalid acceptance transition changed durable state")
	}
}

func TestESIMSwitchJournalConstraintRejectsConcurrentWriters(t *testing.T) {
	database := openESIMSwitchJournalTestDB(t, filepath.Join(t.TempDir(), "journal-concurrent.db"))
	if err := RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migration: %v", err)
	}
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatalf("database.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	store := NewESIMSwitchJournalStore(database)

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 1; i <= 2; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.Create(context.Background(), CreateESIMSwitchOperationInput{
				OperationID:      "operation-concurrent-" + string(rune('0'+i)),
				DeviceID:         "device-concurrent",
				OwnerEpoch:       "epoch-concurrent",
				WorkerGeneration: uint64(i),
				TargetICCID:      "synthetic-target",
				PreRadioState:    ESIMSwitchRadioUnknown,
				Now:              time.Unix(300+int64(i), 0).UTC(),
			})
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, rejected int
	for resultErr := range results {
		switch {
		case resultErr == nil:
			succeeded++
		case errors.Is(resultErr, ErrESIMSwitchOperationInProgress):
			rejected++
		default:
			t.Fatalf("unexpected create error: %v", resultErr)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent results success=%d rejected=%d", succeeded, rejected)
	}
	var blocking int64
	if err := database.Model(&ESIMSwitchOperation{}).Where("terminal = ?", false).Count(&blocking).Error; err != nil {
		t.Fatalf("count blocking operations: %v", err)
	}
	if blocking != 1 {
		t.Fatalf("blocking operations=%d, want 1", blocking)
	}
}

func TestESIMSwitchJournalAllowsOnlyOneIncompleteOperationPerDevice(t *testing.T) {
	database := openESIMSwitchJournalTestDB(t, filepath.Join(t.TempDir(), "journal-blocking.db"))
	if err := RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migration: %v", err)
	}
	store := NewESIMSwitchJournalStore(database)
	first, err := store.Create(context.Background(), CreateESIMSwitchOperationInput{
		OperationID:      "operation-first",
		DeviceID:         "device-blocking",
		OwnerEpoch:       "epoch-blocking",
		WorkerGeneration: 1,
		TargetICCID:      "synthetic-target-a",
		PreRadioState:    ESIMSwitchRadioUnknown,
	})
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	if _, err := store.Create(context.Background(), CreateESIMSwitchOperationInput{
		OperationID:      "operation-blocked",
		DeviceID:         "device-blocking",
		OwnerEpoch:       "epoch-blocking",
		WorkerGeneration: 1,
		TargetICCID:      "synthetic-target-b",
		PreRadioState:    ESIMSwitchRadioUnknown,
	}); !errors.Is(err, ErrESIMSwitchOperationInProgress) {
		t.Fatalf("second incomplete Create() error=%v", err)
	}
	if _, err := store.Transition(context.Background(), TransitionESIMSwitchOperationInput{
		OperationID:         first.OperationID,
		OwnerEpoch:          first.OwnerEpoch,
		WorkerGeneration:    first.WorkerGeneration,
		ExpectedPhase:       first.Phase,
		ExpectedVersion:     first.Version,
		NextPhase:           ESIMSwitchPhaseFailedBeforePhysicalApply,
		NextAcceptanceState: ESIMSwitchAcceptanceUnknown,
	}); err != nil {
		t.Fatalf("complete first: %v", err)
	}
	if _, err := store.Create(context.Background(), CreateESIMSwitchOperationInput{
		OperationID:      "operation-after-terminal",
		DeviceID:         "device-blocking",
		OwnerEpoch:       "epoch-blocking",
		WorkerGeneration: 2,
		TargetICCID:      "synthetic-target-c",
		PreRadioState:    ESIMSwitchRadioUnknown,
	}); err != nil {
		t.Fatalf("create after terminal: %v", err)
	}
}

func TestESIMSwitchJournalClaimIsOncePerOwnerGeneration(t *testing.T) {
	database := openESIMSwitchJournalTestDB(t, filepath.Join(t.TempDir(), "journal-claim.db"))
	if err := RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migration: %v", err)
	}
	store := NewESIMSwitchJournalStore(database)
	created, err := store.Create(context.Background(), CreateESIMSwitchOperationInput{
		OperationID:      "operation-claim",
		DeviceID:         "device-claim",
		OwnerEpoch:       "epoch-old",
		WorkerGeneration: 3,
		TargetICCID:      "synthetic-target",
		PreRadioState:    ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}

	claimed, err := store.ClaimForReconciliation(context.Background(), ClaimESIMSwitchOperationInput{
		OperationID:              created.OperationID,
		ExpectedOwnerEpoch:       created.OwnerEpoch,
		ExpectedWorkerGeneration: created.WorkerGeneration,
		ExpectedPhase:            created.Phase,
		ExpectedVersion:          created.Version,
		NewOwnerEpoch:            "epoch-new",
		NewWorkerGeneration:      1,
	})
	if err != nil {
		t.Fatalf("claim operation: %v", err)
	}
	if claimed.OwnerEpoch != "epoch-new" || claimed.WorkerGeneration != 1 ||
		claimed.ReconcileOwnerEpoch != "epoch-new" || claimed.ReconcileGeneration != 1 {
		t.Fatal("claim did not atomically publish the new owner generation")
	}

	if _, err := store.ClaimForReconciliation(context.Background(), ClaimESIMSwitchOperationInput{
		OperationID:              claimed.OperationID,
		ExpectedOwnerEpoch:       claimed.OwnerEpoch,
		ExpectedWorkerGeneration: claimed.WorkerGeneration,
		ExpectedPhase:            claimed.Phase,
		ExpectedVersion:          claimed.Version,
		NewOwnerEpoch:            claimed.OwnerEpoch,
		NewWorkerGeneration:      claimed.WorkerGeneration,
	}); !errors.Is(err, ErrESIMSwitchOperationStale) {
		t.Fatalf("repeat claim error=%v, want stale", err)
	}
	if _, err := store.Transition(context.Background(), TransitionESIMSwitchOperationInput{
		OperationID:         claimed.OperationID,
		OwnerEpoch:          created.OwnerEpoch,
		WorkerGeneration:    created.WorkerGeneration,
		ExpectedPhase:       claimed.Phase,
		ExpectedVersion:     claimed.Version,
		NextPhase:           ESIMSwitchPhaseTeardownPlanned,
		NextAcceptanceState: ESIMSwitchAcceptanceUnknown,
	}); !errors.Is(err, ErrESIMSwitchOperationStale) {
		t.Fatalf("old owner transition error=%v, want stale", err)
	}
}

func TestESIMSwitchJournalDoesNotExposeSensitiveFields(t *testing.T) {
	const deviceMarker = "private-device-marker"
	const targetMarker = "private-profile-marker"
	encoded, err := json.Marshal(ESIMSwitchOperation{
		OperationID: "opaque-operation",
		DeviceID:    deviceMarker,
		TargetICCID: targetMarker,
		ErrorCode:   ESIMSwitchErrorApplyUnknown,
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(encoded), deviceMarker) || strings.Contains(string(encoded), targetMarker) {
		t.Fatal("journal JSON exposed a private device or profile value")
	}

	database := openESIMSwitchJournalTestDB(t, filepath.Join(t.TempDir(), "journal-privacy.db"))
	if err := RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migration: %v", err)
	}
	store := NewESIMSwitchJournalStore(database)
	if _, err := store.Create(context.Background(), CreateESIMSwitchOperationInput{
		OperationID:      "operation-privacy-first",
		DeviceID:         deviceMarker,
		OwnerEpoch:       "epoch-privacy",
		WorkerGeneration: 1,
		TargetICCID:      targetMarker,
		PreRadioState:    ESIMSwitchRadioUnknown,
	}); err != nil {
		t.Fatalf("create operation: %v", err)
	}
	_, conflictErr := store.Create(context.Background(), CreateESIMSwitchOperationInput{
		OperationID:      "operation-privacy-second",
		DeviceID:         deviceMarker,
		OwnerEpoch:       "epoch-privacy",
		WorkerGeneration: 2,
		TargetICCID:      targetMarker,
		PreRadioState:    ESIMSwitchRadioUnknown,
	})
	if !errors.Is(conflictErr, ErrESIMSwitchOperationInProgress) {
		t.Fatalf("conflict error=%v", conflictErr)
	}
	if strings.Contains(conflictErr.Error(), deviceMarker) || strings.Contains(conflictErr.Error(), targetMarker) {
		t.Fatal("journal conflict error exposed a private value")
	}
}

func openESIMSwitchJournalTestDB(t *testing.T, path string) *gorm.DB {
	t.Helper()
	dialector, err := openSQLiteDialector("modernc", path)
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	database, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}
	return database
}

func closeESIMSwitchJournalTestDB(t *testing.T, database *gorm.DB) {
	t.Helper()
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatalf("database.DB: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}
