package device

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/apduarbiter"
	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/internal/esim"
	"github.com/1239t/vohive/internal/vowifihost"
	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/lpa"
	sgp22 "github.com/damonto/euicc-go/v2"
	glebarezsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type failingESIMSwitchJournal struct {
	createErr     error
	transitionErr error
}

type acceptanceFailingESIMSwitchJournal struct {
	base esimSwitchJournalStore
}

type blockingReconciliationJournal struct {
	entered chan struct{}
	release chan struct{}
}

type blockingESIMSwitchReconcileBackend struct {
	esimSwitchRestoreBackendStub
	started chan<- struct{}
	release <-chan struct{}
}

type countingProfileOperationTransmitter struct {
	calls *atomic.Int32
	err   error
}

func (t countingProfileOperationTransmitter) Transmit(request bertlv.Marshaler, _ bertlv.Unmarshaler) error {
	if _, ok := request.(*sgp22.ProfileOperationRequest); !ok {
		return errors.New("unexpected synthetic APDU request")
	}
	if t.calls != nil {
		t.calls.Add(1)
	}
	return t.err
}

func (countingProfileOperationTransmitter) TransmitRaw([]byte) ([]byte, error) {
	return nil, errors.New("synthetic raw APDU is unavailable")
}

func (b *blockingESIMSwitchReconcileBackend) GetICCIDLive(ctx context.Context) (string, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-b.release:
		return b.liveICCID, nil
	}
}

func (b *blockingReconciliationJournal) Create(context.Context, db.CreateESIMSwitchOperationInput) (db.ESIMSwitchOperation, error) {
	return db.ESIMSwitchOperation{}, db.ErrESIMSwitchJournalUnavailable
}

func (b *blockingReconciliationJournal) Transition(context.Context, db.TransitionESIMSwitchOperationInput) (db.ESIMSwitchOperation, error) {
	return db.ESIMSwitchOperation{}, db.ErrESIMSwitchJournalUnavailable
}

func (b *blockingReconciliationJournal) GetBlockingByDevice(context.Context, string) (db.ESIMSwitchOperation, error) {
	close(b.entered)
	<-b.release
	return db.ESIMSwitchOperation{}, db.ErrESIMSwitchOperationNotFound
}

func (b *blockingReconciliationJournal) ClaimForReconciliation(context.Context, db.ClaimESIMSwitchOperationInput) (db.ESIMSwitchOperation, error) {
	return db.ESIMSwitchOperation{}, db.ErrESIMSwitchOperationStale
}

func (f acceptanceFailingESIMSwitchJournal) Create(ctx context.Context, input db.CreateESIMSwitchOperationInput) (db.ESIMSwitchOperation, error) {
	return f.base.Create(ctx, input)
}

func (f acceptanceFailingESIMSwitchJournal) Transition(ctx context.Context, input db.TransitionESIMSwitchOperationInput) (db.ESIMSwitchOperation, error) {
	if input.NextPhase == db.ESIMSwitchPhaseAccepted {
		return db.ESIMSwitchOperation{}, db.ErrESIMSwitchJournalUnavailable
	}
	return f.base.Transition(ctx, input)
}

func (f failingESIMSwitchJournal) Create(_ context.Context, input db.CreateESIMSwitchOperationInput) (db.ESIMSwitchOperation, error) {
	if f.createErr != nil {
		return db.ESIMSwitchOperation{}, f.createErr
	}
	return db.ESIMSwitchOperation{
		OperationID:      input.OperationID,
		DeviceID:         input.DeviceID,
		OwnerEpoch:       input.OwnerEpoch,
		WorkerGeneration: input.WorkerGeneration,
		TargetICCID:      input.TargetICCID,
		PreRadioState:    input.PreRadioState,
		Phase:            db.ESIMSwitchPhaseIntentPersisted,
		AcceptanceState:  db.ESIMSwitchAcceptanceUnknown,
		Version:          1,
	}, nil
}

func (f failingESIMSwitchJournal) Transition(_ context.Context, input db.TransitionESIMSwitchOperationInput) (db.ESIMSwitchOperation, error) {
	if f.transitionErr != nil {
		return db.ESIMSwitchOperation{}, f.transitionErr
	}
	return db.ESIMSwitchOperation{
		OperationID:      input.OperationID,
		OwnerEpoch:       input.OwnerEpoch,
		WorkerGeneration: input.WorkerGeneration,
		Phase:            input.NextPhase,
		AcceptanceState:  input.NextAcceptanceState,
		Version:          input.ExpectedVersion + 1,
	}, nil
}

func TestESIMSwitchJournalPersistsIntentBeforePhysicalApply(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-journal.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)

	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-test"
	worker := &Worker{
		ID:         "device-test",
		generation: 9,
		Config: config.DeviceConfig{
			ID: "device-test",
			ESIMSwitch: config.ESIMSwitchConfig{
				RadioCycle: true,
			},
		},
	}
	physicalCalls := 0
	assertWriteAhead := func() {
		physicalCalls++
		operation, err := store.GetBlockingByDevice(context.Background(), worker.ID)
		if err != nil {
			t.Fatalf("physical side effect observed before journal: %v", err)
		}
		if operation.Phase != db.ESIMSwitchPhaseTeardownPlanned {
			t.Fatalf("phase at first physical side effect=%q", operation.Phase)
		}
		if operation.OwnerEpoch != p.ownerEpoch || operation.WorkerGeneration != worker.generation {
			t.Fatal("journal owner does not match the active worker")
		}
	}
	worker.Backend = &esimSwitchRestoreBackendStub{
		mode:    backend.BackendQMI,
		getMode: backend.ModeOnline,
		setModeHook: func(backend.OperatingMode) {
			assertWriteAhead()
		},
	}
	p.workers[worker.ID] = worker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		assertWriteAhead()
		return nil
	}

	token, err := p.beginDurableESIMSwitch(worker, "synthetic-target")
	if err != nil {
		t.Fatalf("begin durable switch: %v", err)
	}
	if token == 0 || physicalCalls == 0 {
		t.Fatal("switch did not return an opaque handle or reach the planned physical boundary")
	}
}

func TestESIMSwitchOwnerEpochChangesAcrossPoolInstances(t *testing.T) {
	first := NewPool(&config.Config{})
	second := NewPool(&config.Config{})
	if first.ownerEpoch == "" || second.ownerEpoch == "" || first.ownerEpoch == second.ownerEpoch {
		t.Fatal("independent Pool instances did not receive unique owner epochs")
	}
}

func TestESIMSwitchTimeoutGuardIsOwnedByPoolLifecycle(t *testing.T) {
	p := NewPool(&config.Config{})
	snapshot := p.beginESIMSwitch("device-test", "")
	if snapshot.SwitchToken == 0 {
		t.Fatal("switch did not start")
	}

	p.backgroundMu.Lock()
	activeBeforeShutdown := p.backgroundActive
	p.backgroundMu.Unlock()
	if activeBeforeShutdown != 1 {
		t.Fatalf("owned background tasks=%d, want 1 timeout guard", activeBeforeShutdown)
	}

	if err := p.ShutdownContext(context.Background()); err != nil {
		t.Fatalf("ShutdownContext: %v", err)
	}
	p.backgroundMu.Lock()
	activeAfterShutdown := p.backgroundActive
	p.backgroundMu.Unlock()
	if activeAfterShutdown != 0 {
		t.Fatalf("owned background tasks after shutdown=%d, want 0", activeAfterShutdown)
	}
}

func TestESIMSwitchJournalFailurePreventsPhysicalApply(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store esimSwitchJournalStore
	}{
		{name: "create", store: failingESIMSwitchJournal{createErr: db.ErrESIMSwitchJournalUnavailable}},
		{name: "transition", store: failingESIMSwitchJournal{transitionErr: db.ErrESIMSwitchJournalUnavailable}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPool(&config.Config{})
			p.esimSwitchJournal = tc.store
			p.ownerEpoch = "epoch-test"
			physicalCalls := 0
			worker := &Worker{
				ID:         "device-test",
				generation: 2,
				Config: config.DeviceConfig{
					ID:         "device-test",
					ESIMSwitch: config.ESIMSwitchConfig{RadioCycle: true},
				},
				Backend: &esimSwitchRestoreBackendStub{
					mode:    backend.BackendQMI,
					getMode: backend.ModeOnline,
					setModeHook: func(backend.OperatingMode) {
						physicalCalls++
					},
				},
			}
			p.workers[worker.ID] = worker
			p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
				physicalCalls++
				return nil
			}

			if _, err := p.beginDurableESIMSwitch(worker, "synthetic-target"); !errors.Is(err, db.ErrESIMSwitchJournalUnavailable) {
				t.Fatalf("begin durable switch error=%v", err)
			}
			if physicalCalls != 0 {
				t.Fatalf("physical calls=%d, want 0", physicalCalls)
			}
		})
	}
}

func TestESIMSwitchCallbacksFailClosedOnJournalError(t *testing.T) {
	p := NewPool(&config.Config{})
	p.esimSwitchJournal = failingESIMSwitchJournal{createErr: db.ErrESIMSwitchJournalUnavailable}
	p.ownerEpoch = "epoch-test"
	physicalCalls := 0
	worker := &Worker{
		ID:         "device-test",
		generation: 5,
		Config: config.DeviceConfig{
			ID:         "device-test",
			ESIMSwitch: config.ESIMSwitchConfig{RadioCycle: true},
		},
		Backend: &esimSwitchRestoreBackendStub{
			mode:    backend.BackendQMI,
			getMode: backend.ModeOnline,
			setModeHook: func(backend.OperatingMode) {
				physicalCalls++
			},
		},
	}
	p.workers[worker.ID] = worker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		physicalCalls++
		return nil
	}
	onBefore, _, _, _, _, _, _ := p.newESIMSwitchCallbacksForWorker(worker)

	if _, err := onBefore(esim.SwitchOperationEnableProfile, "synthetic-target"); !errors.Is(err, db.ErrESIMSwitchJournalUnavailable) {
		t.Fatalf("onBefore error=%v", err)
	}
	if physicalCalls != 0 {
		t.Fatalf("physical calls=%d, want 0", physicalCalls)
	}
}

func TestESIMSwitchFailureBeforeAnySideEffectDoesNotRestorePhysicalState(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-failure-before-side-effect.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	p := NewPool(&config.Config{})
	t.Cleanup(p.cancel)
	p.esimSwitchJournal = db.NewESIMSwitchJournalStore(database)
	p.ownerEpoch = "epoch-current"
	var radioCalls atomic.Int32
	worker := &Worker{
		ID:         "device-test",
		generation: 1,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend: &esimSwitchRestoreBackendStub{
			mode:    backend.BackendQMI,
			getMode: backend.ModeOnline,
			setModeHook: func(backend.OperatingMode) {
				radioCalls.Add(1)
			},
		},
		Pool: p,
	}
	p.workers[worker.ID] = worker
	beforeSideEffectErr := errors.New("synthetic stop after intent")
	p.esimSwitchFailpoint = func(point esimSwitchFailpoint) error {
		if point == esimSwitchFailpointAfterIntent {
			return beforeSideEffectErr
		}
		return nil
	}
	onBefore, _, _, _, onFailed, _, _ := p.newESIMSwitchCallbacksForWorker(worker)
	token, err := onBefore(esim.SwitchOperationEnableProfile, "synthetic-target")
	if !errors.Is(err, beforeSideEffectErr) || token == 0 {
		t.Fatalf("onBefore token=%d error=%v", token, err)
	}
	onFailed(token, err)
	if got := radioCalls.Load(); got != 0 {
		t.Fatalf("radio recovery calls=%d, want 0 before any side effect", got)
	}
	var completed db.ESIMSwitchOperation
	if err := database.Where("operation_id <> ?", "").First(&completed).Error; err != nil {
		t.Fatalf("load completed operation: %v", err)
	}
	if completed.Phase != db.ESIMSwitchPhaseFailedBeforePhysicalApply || !completed.Terminal {
		t.Fatalf("completed phase=%q terminal=%v", completed.Phase, completed.Terminal)
	}
}

func TestESIMSwitchConcurrentJournalConflictUsesBusyContract(t *testing.T) {
	p := NewPool(&config.Config{})
	p.esimSwitchJournal = failingESIMSwitchJournal{createErr: db.ErrESIMSwitchOperationInProgress}
	p.ownerEpoch = "epoch-test"
	worker := &Worker{ID: "device-test", generation: 3, Config: config.DeviceConfig{ID: "device-test"}}
	p.workers[worker.ID] = worker
	onBefore, _, _, _, _, _, _ := p.newESIMSwitchCallbacksForWorker(worker)
	if _, err := onBefore(esim.SwitchOperationEnableProfile, "synthetic-target"); !errors.Is(err, esim.ErrOperationInProgress) {
		t.Fatalf("onBefore error=%v, want existing busy contract", err)
	}
}

func TestESIMSwitchBusyConflictPreservesExistingRecoverySnapshot(t *testing.T) {
	p := NewPool(&config.Config{})
	t.Cleanup(p.cancel)
	p.esimSwitchJournal = failingESIMSwitchJournal{createErr: db.ErrESIMSwitchOperationInProgress}
	p.ownerEpoch = "epoch-test"
	worker := &Worker{ID: "device-test", generation: 3, Config: config.DeviceConfig{ID: "device-test"}}
	p.workers[worker.ID] = worker
	const originalToken = uint64(41)
	original := esimSwitchContext{
		SwitchToken:      originalToken,
		CapturedAt:       time.Unix(100, 0),
		TargetICCID:      "synthetic-first-target",
		OperationID:      "operation-existing",
		OwnerEpoch:       p.ownerEpoch,
		WorkerGeneration: worker.generation,
		JournalVersion:   4,
		JournalPhase:     db.ESIMSwitchPhaseAccepted,
	}
	p.switchSeq = originalToken
	p.switchingDevices[worker.ID] = true
	p.switchTokens[worker.ID] = originalToken
	p.switchContexts[worker.ID] = original

	onBefore, _, _, _, _, _, _ := p.newESIMSwitchCallbacksForWorker(worker)
	if _, err := onBefore(esim.SwitchOperationEnableProfile, "synthetic-second-target"); !errors.Is(err, esim.ErrOperationInProgress) {
		t.Fatalf("onBefore error=%v, want existing busy contract", err)
	}
	p.switchMu.Lock()
	currentToken := p.switchTokens[worker.ID]
	current, exists := p.switchContexts[worker.ID]
	switching := p.switchingDevices[worker.ID]
	p.switchMu.Unlock()
	if !exists || !switching || currentToken != originalToken || current.SwitchToken != originalToken ||
		current.OperationID != original.OperationID || current.JournalPhase != original.JournalPhase {
		t.Fatalf("existing recovery snapshot was replaced: exists=%v switching=%v token=%d phase=%q",
			exists, switching, currentToken, current.JournalPhase)
	}
}

func TestESIMSwitchCallbacksPersistApplyPlan(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-apply.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-test"
	worker := &Worker{
		ID:         "device-test",
		generation: 6,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend: &esimSwitchRestoreBackendStub{
			mode:    backend.BackendQMI,
			getMode: backend.ModeOnline,
		},
	}
	p.workers[worker.ID] = worker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		return nil
	}
	onBefore, onBeforePhysical, _, _, _, _, _ := p.newESIMSwitchCallbacksForWorker(worker)
	token, err := onBefore(esim.SwitchOperationEnableProfile, "synthetic-target")
	if err != nil {
		t.Fatalf("persist intent: %v", err)
	}
	if err := onBeforePhysical(esim.SwitchOperationEnableProfile, token); err != nil {
		t.Fatalf("persist apply plan: %v", err)
	}
	operation, err := store.GetBlockingByDevice(context.Background(), worker.ID)
	if err != nil {
		t.Fatalf("load operation: %v", err)
	}
	if operation.Phase != db.ESIMSwitchPhaseApplyPlanned {
		t.Fatalf("durable phase=%q", operation.Phase)
	}
}

func TestPostAcceptedJournalFailureLeavesRecoverableOperation(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-accepted-failure.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	realStore := db.NewESIMSwitchJournalStore(database)
	p := NewPool(&config.Config{})
	p.esimSwitchJournal = realStore
	p.ownerEpoch = "epoch-test"
	worker := &Worker{
		ID:         "device-test",
		generation: 8,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend: &esimSwitchRestoreBackendStub{
			mode:    backend.BackendQMI,
			getMode: backend.ModeOnline,
		},
	}
	p.workers[worker.ID] = worker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		return nil
	}
	onBefore, onBeforePhysical, onAccepted, _, _, _, _ := p.newESIMSwitchCallbacksForWorker(worker)
	token, err := onBefore(esim.SwitchOperationEnableProfile, "synthetic-target")
	if err != nil {
		t.Fatalf("persist intent: %v", err)
	}
	if err := onBeforePhysical(esim.SwitchOperationEnableProfile, token); err != nil {
		t.Fatalf("persist apply plan: %v", err)
	}
	p.esimSwitchJournal = acceptanceFailingESIMSwitchJournal{base: realStore}
	if err := onAccepted(esim.SwitchOperationEnableProfile, token); !errors.Is(err, db.ErrESIMSwitchJournalUnavailable) {
		t.Fatalf("persist accepted error=%v", err)
	}
	operation, err := realStore.GetBlockingByDevice(context.Background(), worker.ID)
	if err != nil {
		t.Fatalf("load blocking operation: %v", err)
	}
	if operation.Phase != db.ESIMSwitchPhaseApplyPlanned ||
		operation.AcceptanceState != db.ESIMSwitchAcceptanceUnknown || operation.Terminal {
		t.Fatalf("unexpected state phase=%q acceptance=%q terminal=%v", operation.Phase, operation.AcceptanceState, operation.Terminal)
	}
}

func TestESIMSwitchUnknownApplyFailureNeedsReconciliation(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-unknown.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-test"
	worker := &Worker{
		ID:         "device-test",
		generation: 10,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend: &esimSwitchRestoreBackendStub{
			mode:    backend.BackendQMI,
			getMode: backend.ModeOnline,
		},
	}
	p.workers[worker.ID] = worker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		return nil
	}
	onBefore, onBeforePhysical, _, _, onFailed, _, _ := p.newESIMSwitchCallbacksForWorker(worker)
	token, err := onBefore(esim.SwitchOperationEnableProfile, "synthetic-target")
	if err != nil {
		t.Fatalf("persist intent: %v", err)
	}
	if err := onBeforePhysical(esim.SwitchOperationEnableProfile, token); err != nil {
		t.Fatalf("persist apply plan: %v", err)
	}
	onFailed(token, errors.New("synthetic transport failure with private details"))

	operation, err := store.GetBlockingByDevice(context.Background(), worker.ID)
	if err != nil {
		t.Fatalf("load blocking operation: %v", err)
	}
	if operation.Phase != db.ESIMSwitchPhaseNeedsReconciliation || operation.Terminal {
		t.Fatalf("unknown result phase=%q terminal=%v", operation.Phase, operation.Terminal)
	}
	if operation.ErrorCode != db.ESIMSwitchErrorApplyUnknown {
		t.Fatalf("error code=%q", operation.ErrorCode)
	}
}

func TestESIMSwitchFailureReplacementAfterPersistCannotActOnEitherGeneration(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-failure-replacement.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	p := NewPool(&config.Config{})
	t.Cleanup(p.cancel)
	p.esimSwitchJournal = db.NewESIMSwitchJournalStore(database)
	p.ownerEpoch = "epoch-current"
	oldBackend := &esimSwitchRestoreBackendStub{mode: backend.BackendQMI, getMode: backend.ModeOnline}
	oldWorker := &Worker{
		ID:         "device-test",
		generation: 1,
		stop:       make(chan struct{}),
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend:    oldBackend,
		Pool:       p,
	}
	p.workers[oldWorker.ID] = oldWorker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		return nil
	}
	onBefore, onBeforePhysical, _, _, onFailed, _, _ := p.newESIMSwitchCallbacksForWorker(oldWorker)
	token, err := onBefore(esim.SwitchOperationEnableProfile, "synthetic-target")
	if err != nil {
		t.Fatalf("persist intent: %v", err)
	}
	if err := onBeforePhysical(esim.SwitchOperationEnableProfile, token); err != nil {
		t.Fatalf("persist apply plan: %v", err)
	}

	failurePersisted := make(chan struct{})
	releaseFailure := make(chan struct{})
	p.esimSwitchFailpoint = func(point esimSwitchFailpoint) error {
		if point == esimSwitchFailpointAfterFailurePersisted {
			close(failurePersisted)
			<-releaseFailure
		}
		return nil
	}
	failureDone := make(chan struct{})
	go func() {
		onFailed(token, errors.New("synthetic switch failure"))
		close(failureDone)
	}()
	select {
	case <-failurePersisted:
	case <-time.After(time.Second):
		t.Fatal("failure callback did not reach persisted barrier")
	}
	removeDone := make(chan error, 1)
	go func() {
		removeDone <- p.RemoveWorker(oldWorker.ID)
	}()
	select {
	case <-oldWorker.stop:
	case <-time.After(time.Second):
		close(releaseFailure)
		t.Fatal("RemoveWorker did not signal old generation stop")
	}
	var newRadioCalls atomic.Int32
	newWorker := &Worker{
		ID:         oldWorker.ID,
		generation: oldWorker.generation + 1,
		Config:     config.DeviceConfig{ID: oldWorker.ID},
		Backend: &esimSwitchRestoreBackendStub{
			mode:    backend.BackendQMI,
			getMode: backend.ModeRFOff,
			setModeHook: func(backend.OperatingMode) {
				newRadioCalls.Add(1)
			},
		},
		Pool: p,
	}
	p.mu.Lock()
	p.workers[newWorker.ID] = newWorker
	p.mu.Unlock()
	close(releaseFailure)
	select {
	case <-failureDone:
	case <-time.After(time.Second):
		t.Fatal("failure callback did not return after replacement")
	}
	select {
	case removeErr := <-removeDone:
		if removeErr != nil {
			t.Fatalf("RemoveWorker: %v", removeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("RemoveWorker did not join failure callback")
	}
	if got := len(oldBackend.setCalls); got != 0 {
		t.Fatalf("old worker failure recovery calls=%d, want 0", got)
	}
	if got := newRadioCalls.Load(); got != 0 {
		t.Fatalf("new worker failure recovery calls=%d, want 0", got)
	}
}

func TestESIMSwitchRecoveryIsWriteAheadAndTerminal(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-recovery.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-test"
	worker := &Worker{
		ID:         "device-test",
		generation: 12,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend: &esimSwitchRestoreBackendStub{
			mode:    backend.BackendQMI,
			getMode: backend.ModeOnline,
		},
	}
	p.workers[worker.ID] = worker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		return nil
	}
	onBefore, onBeforePhysical, onAccepted, _, _, _, _ := p.newESIMSwitchCallbacksForWorker(worker)
	token, err := onBefore(esim.SwitchOperationEnableProfile, "synthetic-target")
	if err != nil {
		t.Fatalf("persist intent: %v", err)
	}
	if err := onBeforePhysical(esim.SwitchOperationEnableProfile, token); err != nil {
		t.Fatalf("persist apply plan: %v", err)
	}
	if err := onAccepted(esim.SwitchOperationEnableProfile, token); err != nil {
		t.Fatalf("persist accepted: %v", err)
	}
	accepted, err := store.GetBlockingByDevice(context.Background(), worker.ID)
	if err != nil {
		t.Fatalf("load accepted operation: %v", err)
	}

	if err := p.beginESIMSwitchRecovery(worker.ID, token); err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	restoring, err := store.GetBlockingByDevice(context.Background(), worker.ID)
	if err != nil {
		t.Fatalf("load restoring operation: %v", err)
	}
	if restoring.Phase != db.ESIMSwitchPhaseRestoring || restoring.AcceptanceState != db.ESIMSwitchAcceptanceAccepted {
		t.Fatalf("restoring phase=%q acceptance=%q", restoring.Phase, restoring.AcceptanceState)
	}
	if err := p.completeESIMSwitchRecovery(worker.ID, token); err != nil {
		t.Fatalf("complete recovery: %v", err)
	}
	if _, err := store.GetBlockingByDevice(context.Background(), worker.ID); !errors.Is(err, db.ErrESIMSwitchOperationNotFound) {
		t.Fatalf("blocking lookup after success error=%v", err)
	}
	var completed db.ESIMSwitchOperation
	if err := database.Where("operation_id = ?", accepted.OperationID).First(&completed).Error; err != nil {
		t.Fatalf("load completed operation: %v", err)
	}
	if completed.Phase != db.ESIMSwitchPhaseSucceeded || !completed.Terminal || completed.CompletedAt == nil {
		t.Fatalf("completed phase=%q terminal=%v completed_at_nil=%v", completed.Phase, completed.Terminal, completed.CompletedAt == nil)
	}
}

func TestESIMSwitchCrashBeforeAnySideEffectDoesNotApply(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-crash-intent.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-test"
	crashErr := errors.New("synthetic process interruption")
	p.esimSwitchFailpoint = func(point esimSwitchFailpoint) error {
		if point == esimSwitchFailpointAfterIntent {
			return crashErr
		}
		return nil
	}
	physicalCalls := 0
	worker := &Worker{
		ID:         "device-test",
		generation: 14,
		Config: config.DeviceConfig{
			ID:         "device-test",
			ESIMSwitch: config.ESIMSwitchConfig{RadioCycle: true},
		},
		Backend: &esimSwitchRestoreBackendStub{
			mode:    backend.BackendQMI,
			getMode: backend.ModeOnline,
			setModeHook: func(backend.OperatingMode) {
				physicalCalls++
			},
		},
	}
	p.workers[worker.ID] = worker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		physicalCalls++
		return nil
	}
	if _, err := p.beginDurableESIMSwitch(worker, "synthetic-target"); !errors.Is(err, crashErr) {
		t.Fatalf("begin durable switch error=%v", err)
	}
	if physicalCalls != 0 {
		t.Fatalf("physical calls=%d, want 0", physicalCalls)
	}
	operation, err := store.GetBlockingByDevice(context.Background(), worker.ID)
	if err != nil {
		t.Fatalf("load operation: %v", err)
	}
	if operation.Phase != db.ESIMSwitchPhaseIntentPersisted || operation.Terminal {
		t.Fatalf("phase=%q terminal=%v", operation.Phase, operation.Terminal)
	}
}

func TestESIMSwitchReconcileActiveTargetDoesNotReapplyProfile(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-reconcile-active.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	operation, err := store.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:      "operation-reconcile-active",
		DeviceID:         "device-test",
		OwnerEpoch:       "epoch-old",
		WorkerGeneration: 4,
		TargetICCID:      "synthetic-target",
		PreRadioState:    db.ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
		OperationID:         operation.OperationID,
		OwnerEpoch:          operation.OwnerEpoch,
		WorkerGeneration:    operation.WorkerGeneration,
		ExpectedPhase:       operation.Phase,
		ExpectedVersion:     operation.Version,
		NextPhase:           db.ESIMSwitchPhaseTeardownPlanned,
		NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
	})
	if err != nil {
		t.Fatalf("persist teardown plan: %v", err)
	}
	operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
		OperationID:         operation.OperationID,
		OwnerEpoch:          operation.OwnerEpoch,
		WorkerGeneration:    operation.WorkerGeneration,
		ExpectedPhase:       operation.Phase,
		ExpectedVersion:     operation.Version,
		NextPhase:           db.ESIMSwitchPhaseApplyPlanned,
		NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
	})
	if err != nil {
		t.Fatalf("persist apply plan: %v", err)
	}

	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-new"
	backendStub := &esimSwitchRestoreBackendStub{
		mode:      backend.BackendQMI,
		getMode:   backend.ModeOnline,
		liveICCID: "synthetic-target",
	}
	worker := &Worker{
		ID:         "device-test",
		generation: 1,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend:    backendStub,
	}
	p.workers[worker.ID] = worker

	if err := p.reconcileESIMSwitchForWorker(worker); err != nil {
		t.Fatalf("reconcile operation: %v", err)
	}
	var completed db.ESIMSwitchOperation
	if err := database.Where("operation_id = ?", operation.OperationID).First(&completed).Error; err != nil {
		t.Fatalf("load completed operation: %v", err)
	}
	if completed.Phase != db.ESIMSwitchPhaseSucceeded || !completed.Terminal ||
		completed.OwnerEpoch != p.ownerEpoch || completed.WorkerGeneration != worker.generation {
		t.Fatalf("completed state phase=%q terminal=%v owner_current=%v generation=%d",
			completed.Phase, completed.Terminal, completed.OwnerEpoch == p.ownerEpoch, completed.WorkerGeneration)
	}
}

func TestESIMSwitchReconcileActiveTargetRestoresPersistedPreState(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-reconcile-prestate.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	operation, err := store.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:         "operation-reconcile-prestate",
		DeviceID:            "device-test",
		OwnerEpoch:          "epoch-old",
		WorkerGeneration:    4,
		TargetICCID:         "synthetic-target",
		PreNetworkConnected: true,
		PreNetworkEnabled:   true,
		PreVoWiFiActive:     true,
		PreRadioState:       db.ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	for _, next := range []db.ESIMSwitchPhase{
		db.ESIMSwitchPhaseTeardownPlanned,
		db.ESIMSwitchPhaseApplyPlanned,
	} {
		operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
			OperationID:         operation.OperationID,
			OwnerEpoch:          operation.OwnerEpoch,
			WorkerGeneration:    operation.WorkerGeneration,
			ExpectedPhase:       operation.Phase,
			ExpectedVersion:     operation.Version,
			NextPhase:           next,
			NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
		})
		if err != nil {
			t.Fatalf("transition to %q: %v", next, err)
		}
	}

	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-new"
	steps := make([]string, 0, 3)
	backendStub := &esimSwitchRestoreBackendStub{
		mode:      backend.BackendQMI,
		getMode:   backend.ModeRFOff,
		liveICCID: "synthetic-target",
		setModeHook: func(mode backend.OperatingMode) {
			if mode == backend.ModeOnline {
				steps = append(steps, "radio")
			}
		},
	}
	network := &fakeController{connectHook: func() {
		steps = append(steps, "network")
	}}
	worker := &Worker{
		ID:          "device-test",
		generation:  1,
		Config:      config.DeviceConfig{ID: "device-test"},
		Backend:     backendStub,
		netOverride: network,
	}
	p.workers[worker.ID] = worker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(_ context.Context, command vowifihost.LifecycleCommand) error {
		if command.Kind == vowifihost.LifecycleCommandSwitchEnd {
			steps = append(steps, "vowifi")
		}
		return nil
	}

	if err := p.reconcileESIMSwitchForWorker(worker); err != nil {
		t.Fatalf("reconcile operation: %v", err)
	}
	if got, want := strings.Join(steps, ","), "radio,network,vowifi"; got != want {
		t.Fatalf("restore order=%q, want %q", got, want)
	}
	if !network.connected {
		t.Fatal("persisted network state was not restored")
	}
	if worker.EsimMgr != nil {
		t.Fatal("reconciliation unexpectedly installed or invoked an eSIM manager")
	}
}

func TestESIMSwitchRemovalAfterRestoringPreventsPhysicalRecovery(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-remove-after-restoring.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	baseStore := db.NewESIMSwitchJournalStore(database)
	operation, err := baseStore.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:         "operation-remove-after-restoring",
		DeviceID:            "device-test",
		OwnerEpoch:          "epoch-old",
		WorkerGeneration:    4,
		TargetICCID:         "synthetic-target",
		PreNetworkConnected: true,
		PreNetworkEnabled:   true,
		PreVoWiFiActive:     true,
		PreRadioState:       db.ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	for _, next := range []db.ESIMSwitchPhase{
		db.ESIMSwitchPhaseTeardownPlanned,
		db.ESIMSwitchPhaseApplyPlanned,
		db.ESIMSwitchPhaseAccepted,
	} {
		acceptance := db.ESIMSwitchAcceptanceUnknown
		if next == db.ESIMSwitchPhaseAccepted {
			acceptance = db.ESIMSwitchAcceptanceAccepted
		}
		operation, err = baseStore.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
			OperationID:         operation.OperationID,
			OwnerEpoch:          operation.OwnerEpoch,
			WorkerGeneration:    operation.WorkerGeneration,
			ExpectedPhase:       operation.Phase,
			ExpectedVersion:     operation.Version,
			NextPhase:           next,
			NextAcceptanceState: acceptance,
		})
		if err != nil {
			t.Fatalf("transition to %q: %v", next, err)
		}
	}

	restoringCommitted := make(chan struct{}, 1)
	releaseRestoring := make(chan struct{})
	p := NewPool(&config.Config{})
	p.esimSwitchJournal = baseStore
	p.ownerEpoch = "epoch-new"
	p.esimSwitchFailpoint = func(point esimSwitchFailpoint) error {
		if point == esimSwitchFailpointDuringRecovery {
			restoringCommitted <- struct{}{}
			<-releaseRestoring
		}
		return nil
	}
	var oldRadioCalls atomic.Int32
	var oldNetworkCalls atomic.Int32
	var oldVoWiFiCalls atomic.Int32
	oldBackend := &esimSwitchRestoreBackendStub{
		mode:    backend.BackendQMI,
		getMode: backend.ModeRFOff,
		setModeHook: func(backend.OperatingMode) {
			oldRadioCalls.Add(1)
		},
	}
	oldWorker := &Worker{
		ID:         operation.DeviceID,
		generation: 1,
		stop:       make(chan struct{}),
		Config:     config.DeviceConfig{ID: operation.DeviceID},
		Backend:    oldBackend,
		netOverride: &fakeController{connectHook: func() {
			oldNetworkCalls.Add(1)
		}},
		Pool: p,
	}
	p.workers[oldWorker.ID] = oldWorker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(_ context.Context, command vowifihost.LifecycleCommand) error {
		if command.Kind == vowifihost.LifecycleCommandSwitchEnd {
			oldVoWiFiCalls.Add(1)
		}
		return nil
	}

	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- p.reconcileESIMSwitchForWorker(oldWorker)
	}()
	select {
	case <-restoringCommitted:
	case <-time.After(time.Second):
		t.Fatal("Restoring transition barrier was not reached")
	}
	removeDone := make(chan error, 1)
	go func() {
		removeDone <- p.RemoveWorker(oldWorker.ID)
	}()
	select {
	case <-oldWorker.stop:
	case <-time.After(time.Second):
		close(releaseRestoring)
		t.Fatal("RemoveWorker did not signal generation stop")
	}
	close(releaseRestoring)
	select {
	case reconcileErr := <-reconcileDone:
		if reconcileErr != nil && !errors.Is(reconcileErr, db.ErrESIMSwitchOperationStale) {
			t.Fatalf("reconcile error=%v", reconcileErr)
		}
	case <-time.After(time.Second):
		t.Fatal("reconcile did not return after removal")
	}
	select {
	case removeErr := <-removeDone:
		if removeErr != nil {
			t.Fatalf("RemoveWorker: %v", removeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("RemoveWorker did not join reconciliation")
	}

	var newRadioCalls atomic.Int32
	newWorker := &Worker{
		ID:         oldWorker.ID,
		generation: oldWorker.generation + 1,
		Config:     config.DeviceConfig{ID: oldWorker.ID},
		Backend: &esimSwitchRestoreBackendStub{setModeHook: func(backend.OperatingMode) {
			newRadioCalls.Add(1)
		}},
	}
	p.mu.Lock()
	p.workers[newWorker.ID] = newWorker
	p.mu.Unlock()
	if got := oldRadioCalls.Load(); got != 0 {
		t.Fatalf("old worker radio recovery calls=%d, want 0", got)
	}
	if got := oldNetworkCalls.Load(); got != 0 {
		t.Fatalf("old worker network recovery calls=%d, want 0", got)
	}
	if got := oldVoWiFiCalls.Load(); got != 0 {
		t.Fatalf("old worker VoWiFi recovery calls=%d, want 0", got)
	}
	if got := newRadioCalls.Load(); got != 0 {
		t.Fatalf("new worker radio recovery calls=%d, want 0", got)
	}
}

func TestESIMSwitchNormalRecoveryReplacementAfterRestoringCannotActOnEitherGeneration(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-normal-recovery-replacement.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	operation, err := store.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:      "operation-normal-recovery-replacement",
		DeviceID:         "device-test",
		OwnerEpoch:       "epoch-current",
		WorkerGeneration: 1,
		TargetICCID:      "synthetic-target",
		PreRadioState:    db.ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	for _, next := range []db.ESIMSwitchPhase{
		db.ESIMSwitchPhaseTeardownPlanned,
		db.ESIMSwitchPhaseApplyPlanned,
		db.ESIMSwitchPhaseAccepted,
	} {
		acceptance := db.ESIMSwitchAcceptanceUnknown
		if next == db.ESIMSwitchPhaseAccepted {
			acceptance = db.ESIMSwitchAcceptanceAccepted
		}
		operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
			OperationID:         operation.OperationID,
			OwnerEpoch:          operation.OwnerEpoch,
			WorkerGeneration:    operation.WorkerGeneration,
			ExpectedPhase:       operation.Phase,
			ExpectedVersion:     operation.Version,
			NextPhase:           next,
			NextAcceptanceState: acceptance,
		})
		if err != nil {
			t.Fatalf("transition to %q: %v", next, err)
		}
	}

	p := NewPool(&config.Config{})
	t.Cleanup(p.cancel)
	p.esimSwitchJournal = store
	p.ownerEpoch = operation.OwnerEpoch
	oldBackend := &esimSwitchRestoreBackendStub{mode: backend.BackendQMI, getMode: backend.ModeRFOff}
	oldWorker := &Worker{
		ID:         operation.DeviceID,
		generation: operation.WorkerGeneration,
		stop:       make(chan struct{}),
		Config:     config.DeviceConfig{ID: operation.DeviceID},
		Backend:    oldBackend,
		Pool:       p,
	}
	p.workers[oldWorker.ID] = oldWorker
	const token = uint64(1)
	p.switchingDevices[oldWorker.ID] = true
	p.switchTokens[oldWorker.ID] = token
	p.switchContexts[oldWorker.ID] = esimSwitchContext{
		SwitchToken:      token,
		CapturedAt:       time.Unix(100, 0),
		TargetICCID:      operation.TargetICCID,
		OperationID:      operation.OperationID,
		OwnerEpoch:       operation.OwnerEpoch,
		WorkerGeneration: operation.WorkerGeneration,
		JournalVersion:   operation.Version,
		JournalPhase:     operation.Phase,
		RadioStateBefore: operation.PreRadioState,
	}

	restoringCommitted := make(chan struct{})
	releaseRestoring := make(chan struct{})
	p.esimSwitchFailpoint = func(point esimSwitchFailpoint) error {
		if point == esimSwitchFailpointDuringRecovery {
			close(restoringCommitted)
			<-releaseRestoring
		}
		return nil
	}
	handlerDone := make(chan struct{})
	go func() {
		p.handleESIMSwitchAfter(oldWorker.ID, token)
		close(handlerDone)
	}()
	select {
	case <-restoringCommitted:
	case <-time.After(time.Second):
		t.Fatal("normal recovery did not reach Restoring barrier")
	}
	removeDone := make(chan error, 1)
	go func() {
		removeDone <- p.RemoveWorker(oldWorker.ID)
	}()
	select {
	case <-oldWorker.stop:
	case <-time.After(time.Second):
		close(releaseRestoring)
		t.Fatal("RemoveWorker did not signal old generation stop")
	}
	var newRadioCalls atomic.Int32
	newBackend := &esimSwitchRestoreBackendStub{
		mode:      backend.BackendQMI,
		getMode:   backend.ModeRFOff,
		liveICCID: operation.TargetICCID,
		liveIMSI:  "synthetic-subscriber",
		setModeHook: func(backend.OperatingMode) {
			newRadioCalls.Add(1)
		},
	}
	newWorker := &Worker{
		ID:         oldWorker.ID,
		generation: oldWorker.generation + 1,
		Config: config.DeviceConfig{
			ID: oldWorker.ID,
			ESIMSwitch: config.ESIMSwitchConfig{
				RadioCycle: true,
			},
		},
		Backend: newBackend,
		Pool:    p,
	}
	p.mu.Lock()
	p.workers[newWorker.ID] = newWorker
	p.mu.Unlock()
	close(releaseRestoring)
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("normal recovery did not return after replacement")
	}
	select {
	case removeErr := <-removeDone:
		if removeErr != nil {
			t.Fatalf("RemoveWorker: %v", removeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("RemoveWorker did not join normal recovery")
	}
	if got := len(oldBackend.setCalls); got != 0 {
		t.Fatalf("old worker radio recovery calls=%d, want 0", got)
	}
	if got := newRadioCalls.Load(); got != 0 {
		t.Fatalf("new worker radio recovery calls=%d, want 0", got)
	}
}

func TestESIMSwitchReconcileOldWorkerReadCannotAdvanceAfterReplacement(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-reconcile-stale-read.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	operation, err := store.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:      "operation-reconcile-stale-read",
		DeviceID:         "device-test",
		OwnerEpoch:       "epoch-old",
		WorkerGeneration: 4,
		TargetICCID:      "synthetic-target",
		PreRadioState:    db.ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	for _, next := range []db.ESIMSwitchPhase{
		db.ESIMSwitchPhaseTeardownPlanned,
		db.ESIMSwitchPhaseApplyPlanned,
	} {
		operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
			OperationID:         operation.OperationID,
			OwnerEpoch:          operation.OwnerEpoch,
			WorkerGeneration:    operation.WorkerGeneration,
			ExpectedPhase:       operation.Phase,
			ExpectedVersion:     operation.Version,
			NextPhase:           next,
			NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
		})
		if err != nil {
			t.Fatalf("transition to %q: %v", next, err)
		}
	}

	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-new"
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	oldBackend := &blockingESIMSwitchReconcileBackend{
		esimSwitchRestoreBackendStub: esimSwitchRestoreBackendStub{
			mode:      backend.BackendQMI,
			getMode:   backend.ModeOnline,
			liveICCID: "synthetic-target",
		},
		started: started,
		release: release,
	}
	oldWorker := &Worker{
		ID:         operation.DeviceID,
		generation: 1,
		Config:     config.DeviceConfig{ID: operation.DeviceID},
		Backend:    oldBackend,
	}
	p.workers[oldWorker.ID] = oldWorker
	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- p.reconcileESIMSwitchForWorker(oldWorker)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("profile read did not start")
	}
	newWorker := &Worker{
		ID:         oldWorker.ID,
		generation: oldWorker.generation + 1,
		Config:     config.DeviceConfig{ID: oldWorker.ID},
		Backend:    &esimSwitchRestoreBackendStub{mode: backend.BackendQMI, getMode: backend.ModeOnline},
	}
	p.mu.Lock()
	p.workers[newWorker.ID] = newWorker
	p.mu.Unlock()
	close(release)
	select {
	case err := <-reconcileDone:
		if err != nil && !errors.Is(err, db.ErrESIMSwitchOperationStale) {
			t.Fatalf("reconcile error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconcile did not return")
	}
	if len(oldBackend.setCalls) != 0 {
		t.Fatalf("stale reconcile performed %d radio operations", len(oldBackend.setCalls))
	}
	pending, err := store.GetBlockingByDevice(context.Background(), operation.DeviceID)
	if err != nil {
		t.Fatalf("load pending operation: %v", err)
	}
	if pending.Phase != db.ESIMSwitchPhaseApplyPlanned || pending.Terminal ||
		pending.WorkerGeneration != oldWorker.generation {
		t.Fatalf("pending phase=%q terminal=%v generation=%d",
			pending.Phase, pending.Terminal, pending.WorkerGeneration)
	}
}

func TestESIMSwitchStaleFailureCallbackCannotActAfterReconcileClaim(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-stale-callback.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	operation, err := store.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:      "operation-stale-callback",
		DeviceID:         "device-test",
		OwnerEpoch:       "epoch-old",
		WorkerGeneration: 8,
		TargetICCID:      "synthetic-target",
		PreRadioState:    db.ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
		OperationID:         operation.OperationID,
		OwnerEpoch:          operation.OwnerEpoch,
		WorkerGeneration:    operation.WorkerGeneration,
		ExpectedPhase:       operation.Phase,
		ExpectedVersion:     operation.Version,
		NextPhase:           db.ESIMSwitchPhaseTeardownPlanned,
		NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
	})
	if err != nil {
		t.Fatalf("persist teardown plan: %v", err)
	}

	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-new"
	backendStub := &esimSwitchRestoreBackendStub{mode: backend.BackendQMI, getMode: backend.ModeRFOff}
	worker := &Worker{
		ID:         operation.DeviceID,
		generation: 1,
		Config:     config.DeviceConfig{ID: operation.DeviceID},
		Backend:    backendStub,
	}
	p.workers[worker.ID] = worker
	const token = uint64(1)
	p.switchingDevices[worker.ID] = true
	p.switchTokens[worker.ID] = token
	p.switchContexts[worker.ID] = esimSwitchContext{
		SwitchToken:      token,
		CapturedAt:       time.Unix(100, 0),
		OperationID:      operation.OperationID,
		OwnerEpoch:       operation.OwnerEpoch,
		WorkerGeneration: operation.WorkerGeneration,
		JournalVersion:   operation.Version,
		JournalPhase:     operation.Phase,
		RadioStateBefore: db.ESIMSwitchRadioOnline,
	}

	claimed, err := store.ClaimForReconciliation(context.Background(), db.ClaimESIMSwitchOperationInput{
		OperationID:              operation.OperationID,
		ExpectedOwnerEpoch:       operation.OwnerEpoch,
		ExpectedWorkerGeneration: operation.WorkerGeneration,
		ExpectedPhase:            operation.Phase,
		ExpectedVersion:          operation.Version,
		NewOwnerEpoch:            p.ownerEpoch,
		NewWorkerGeneration:      worker.generation,
	})
	if err != nil {
		t.Fatalf("claim operation: %v", err)
	}

	p.handleESIMSwitchFailedWithError(worker.ID, token, errors.New("synthetic stale callback"))
	if len(backendStub.setCalls) != 0 {
		t.Fatalf("stale callback performed %d radio operations", len(backendStub.setCalls))
	}
	var after db.ESIMSwitchOperation
	if err := database.Where("operation_id = ?", operation.OperationID).First(&after).Error; err != nil {
		t.Fatalf("load claimed operation: %v", err)
	}
	if after.OwnerEpoch != claimed.OwnerEpoch || after.WorkerGeneration != claimed.WorkerGeneration ||
		after.Phase != claimed.Phase || after.Version != claimed.Version {
		t.Fatal("stale callback changed the claimed durable operation")
	}
}

func TestESIMSwitchOldWorkerCallbackCannotActBeforeNewWorkerClaim(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-stale-generation.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	operation, err := store.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:      "operation-stale-generation",
		DeviceID:         "device-test",
		OwnerEpoch:       "epoch-current",
		WorkerGeneration: 8,
		TargetICCID:      "synthetic-target",
		PreRadioState:    db.ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
		OperationID:         operation.OperationID,
		OwnerEpoch:          operation.OwnerEpoch,
		WorkerGeneration:    operation.WorkerGeneration,
		ExpectedPhase:       operation.Phase,
		ExpectedVersion:     operation.Version,
		NextPhase:           db.ESIMSwitchPhaseTeardownPlanned,
		NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
	})
	if err != nil {
		t.Fatalf("persist teardown plan: %v", err)
	}

	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = operation.OwnerEpoch
	backendStub := &esimSwitchRestoreBackendStub{mode: backend.BackendQMI, getMode: backend.ModeRFOff}
	newWorker := &Worker{
		ID:         operation.DeviceID,
		generation: operation.WorkerGeneration + 1,
		Config:     config.DeviceConfig{ID: operation.DeviceID},
		Backend:    backendStub,
	}
	p.workers[newWorker.ID] = newWorker
	const token = uint64(1)
	p.switchingDevices[newWorker.ID] = true
	p.switchTokens[newWorker.ID] = token
	p.switchContexts[newWorker.ID] = esimSwitchContext{
		SwitchToken:      token,
		CapturedAt:       time.Unix(100, 0),
		OperationID:      operation.OperationID,
		OwnerEpoch:       operation.OwnerEpoch,
		WorkerGeneration: operation.WorkerGeneration,
		JournalVersion:   operation.Version,
		JournalPhase:     operation.Phase,
		RadioStateBefore: db.ESIMSwitchRadioOnline,
	}

	p.handleESIMSwitchFailedWithError(newWorker.ID, token, errors.New("synthetic old worker callback"))
	if len(backendStub.setCalls) != 0 {
		t.Fatalf("old worker callback performed %d radio operations", len(backendStub.setCalls))
	}
	var after db.ESIMSwitchOperation
	if err := database.Where("operation_id = ?", operation.OperationID).First(&after).Error; err != nil {
		t.Fatalf("load operation: %v", err)
	}
	if after.Phase != operation.Phase || after.Version != operation.Version ||
		after.OwnerEpoch != operation.OwnerEpoch || after.WorkerGeneration != operation.WorkerGeneration {
		t.Fatal("old worker callback changed durable state before the new worker claim")
	}
}

func TestESIMSwitchWorkerReplacementAfterIntentPreventsTeardown(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-replaced-after-intent.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	p := NewPool(&config.Config{})
	t.Cleanup(func() { _ = p.ShutdownContext(context.Background()) })
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-current"
	oldWorker := &Worker{
		ID:         "device-test",
		generation: 1,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend:    &esimSwitchRestoreBackendStub{mode: backend.BackendQMI, getMode: backend.ModeOnline},
	}
	newWorker := &Worker{
		ID:         oldWorker.ID,
		generation: oldWorker.generation + 1,
		Config:     config.DeviceConfig{ID: oldWorker.ID},
		Backend:    &esimSwitchRestoreBackendStub{mode: backend.BackendQMI, getMode: backend.ModeOnline},
	}
	p.workers[oldWorker.ID] = oldWorker
	physicalCalls := 0
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		physicalCalls++
		return nil
	}
	p.esimSwitchFailpoint = func(point esimSwitchFailpoint) error {
		if point == esimSwitchFailpointAfterIntent {
			p.mu.Lock()
			p.workers[oldWorker.ID] = newWorker
			p.mu.Unlock()
		}
		return nil
	}

	if _, err := p.beginDurableESIMSwitch(oldWorker, "synthetic-target"); !errors.Is(err, db.ErrESIMSwitchOperationStale) {
		t.Fatalf("begin durable switch error=%v, want stale", err)
	}
	if physicalCalls != 0 {
		t.Fatalf("physical calls=%d, want 0", physicalCalls)
	}
	operation, err := store.GetBlockingByDevice(context.Background(), oldWorker.ID)
	if err != nil {
		t.Fatalf("load operation: %v", err)
	}
	if operation.Phase != db.ESIMSwitchPhaseIntentPersisted || operation.Terminal {
		t.Fatalf("phase=%q terminal=%v", operation.Phase, operation.Terminal)
	}
}

func TestESIMSwitchReplacementAfterTeardownPlannedCannotTeardownEitherGeneration(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-replaced-after-teardown-plan.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	p := NewPool(&config.Config{})
	t.Cleanup(func() { _ = p.ShutdownContext(context.Background()) })
	p.esimSwitchJournal = db.NewESIMSwitchJournalStore(database)
	p.ownerEpoch = "epoch-current"

	oldBackend := &esimSwitchRestoreBackendStub{mode: backend.BackendQMI, getMode: backend.ModeOnline}
	newBackend := &esimSwitchRestoreBackendStub{mode: backend.BackendQMI, getMode: backend.ModeOnline}
	oldWorker := &Worker{
		ID:          "device-test",
		generation:  1,
		stop:        make(chan struct{}),
		Config:      config.DeviceConfig{ID: "device-test", ESIMSwitch: config.ESIMSwitchConfig{RadioCycle: true}},
		Backend:     oldBackend,
		APDUArbiter: apduarbiter.New("device-test-old", apduarbiter.Options{}),
	}
	newWorker := &Worker{
		ID:          oldWorker.ID,
		generation:  oldWorker.generation + 1,
		stop:        make(chan struct{}),
		Config:      config.DeviceConfig{ID: oldWorker.ID, ESIMSwitch: config.ESIMSwitchConfig{RadioCycle: true}},
		Backend:     newBackend,
		APDUArbiter: apduarbiter.New("device-test-new", apduarbiter.Options{}),
	}
	oldProbeCalls := 0
	newProbeCalls := 0
	if err := oldWorker.APDUArbiter.WaitSIMAuthReady(context.Background(), func(context.Context) error {
		oldProbeCalls++
		return nil
	}); err != nil {
		t.Fatalf("prime old APDU gate: %v", err)
	}
	if err := newWorker.APDUArbiter.WaitSIMAuthReady(context.Background(), func(context.Context) error {
		newProbeCalls++
		return nil
	}); err != nil {
		t.Fatalf("prime new APDU gate: %v", err)
	}
	p.workers[oldWorker.ID] = oldWorker
	switchBeginCalls := 0
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		switchBeginCalls++
		return nil
	}
	p.esimSwitchFailpoint = func(point esimSwitchFailpoint) error {
		if point != esimSwitchFailpointAfterTeardownPlanned {
			return nil
		}
		oldWorker.stopOnce.Do(func() { close(oldWorker.stop) })
		p.mu.Lock()
		p.workers[oldWorker.ID] = newWorker
		p.mu.Unlock()
		return nil
	}

	_, switchErr := p.beginDurableESIMSwitch(oldWorker, "synthetic-target")
	if err := oldWorker.APDUArbiter.WaitSIMAuthReady(context.Background(), func(context.Context) error {
		oldProbeCalls++
		return nil
	}); err != nil {
		t.Fatalf("recheck old APDU gate: %v", err)
	}
	if err := newWorker.APDUArbiter.WaitSIMAuthReady(context.Background(), func(context.Context) error {
		newProbeCalls++
		return nil
	}); err != nil {
		t.Fatalf("recheck new APDU gate: %v", err)
	}
	oldAPDUTeardowns := oldProbeCalls - 1
	newAPDUTeardowns := newProbeCalls - 1
	if switchBeginCalls != 0 || len(oldBackend.setCalls) != 0 || len(newBackend.setCalls) != 0 ||
		oldAPDUTeardowns != 0 || newAPDUTeardowns != 0 {
		t.Fatalf("physical calls switch_begin=%d old_radio=%d new_radio=%d old_apdu=%d new_apdu=%d",
			switchBeginCalls, len(oldBackend.setCalls), len(newBackend.setCalls), oldAPDUTeardowns, newAPDUTeardowns)
	}
	if !errors.Is(switchErr, db.ErrESIMSwitchOperationStale) {
		t.Fatalf("begin durable switch error=%v, want stale", switchErr)
	}
}

func TestESIMSwitchRemovalAfterApplyPlannedPreventsEnableProfile(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-remove-after-apply-plan.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	p := NewPool(&config.Config{})
	p.esimSwitchJournal = db.NewESIMSwitchJournalStore(database)
	p.ownerEpoch = "epoch-current"
	worker := &Worker{
		ID:         "device-test",
		generation: 1,
		stop:       make(chan struct{}),
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend:    &esimSwitchRestoreBackendStub{mode: backend.BackendQMI, getMode: backend.ModeOnline},
		Pool:       p,
	}
	p.workers[worker.ID] = worker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		return nil
	}
	applyPlanned := make(chan struct{})
	releaseApply := make(chan struct{})
	p.esimSwitchFailpoint = func(point esimSwitchFailpoint) error {
		if point == esimSwitchFailpointAfterApplyPlanned {
			close(applyPlanned)
			<-releaseApply
		}
		return nil
	}
	onBefore, onBeforePhysical, onAccepted, onAfter, onFailed, onDegraded, onPhase := p.newESIMSwitchCallbacksForWorker(worker)
	var enableCalls atomic.Int32
	manager := esim.NewManagerWithChannelFactoryCallbacks(worker.ID, func([]byte) (*lpa.Client, error) {
		return &lpa.Client{APDU: countingProfileOperationTransmitter{
			calls: &enableCalls,
			err:   errors.New("synthetic profile apply failure"),
		}}, nil
	}, nil, esim.ChannelFactorySwitchCallbacks{
		OnBeforeSwitch:        onBefore,
		AcquireSwitchLease:    worker.acquireESIMManagerSwitchLease,
		OnBeforePhysicalApply: onBeforePhysical,
		OnSwitchAccepted:      onAccepted,
		OnAfterSwitch: func(_ esim.SwitchOperation, token uint64) {
			onAfter(token)
		},
		OnSwitchFailed: func(_ esim.SwitchOperation, token uint64, err error) {
			onFailed(token, err)
		},
		OnSwitchDegraded: func(_ esim.SwitchOperation, token uint64, phase esim.SwitchPhase, err error) {
			onDegraded(token, phase, err)
		},
		OnSwitchPhase: func(_ esim.SwitchOperation, token uint64, phase esim.SwitchPhase) {
			onPhase(token, phase)
		},
	})
	worker.EsimMgr = manager

	switchDone := make(chan error, 1)
	go func() {
		_, switchErr := manager.SwitchProfileWithResult(context.Background(), "8986001234567890123", "A0000005591010FFFFFFFF8900000100")
		switchDone <- switchErr
	}()
	select {
	case <-applyPlanned:
	case <-time.After(time.Second):
		t.Fatal("ApplyPlanned barrier was not reached")
	}
	removeDone := make(chan error, 1)
	go func() {
		removeDone <- p.RemoveWorker(worker.ID)
	}()
	select {
	case <-worker.stop:
	case <-time.After(time.Second):
		close(releaseApply)
		t.Fatal("RemoveWorker did not signal worker stop")
	}
	close(releaseApply)
	select {
	case <-switchDone:
	case <-time.After(time.Second):
		t.Fatal("switch did not return after removal")
	}
	select {
	case removeErr := <-removeDone:
		if removeErr != nil {
			t.Fatalf("RemoveWorker: %v", removeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("RemoveWorker did not join the switch operation")
	}
	if got := enableCalls.Load(); got != 0 {
		t.Fatalf("EnableProfile calls=%d, want 0 after generation removal", got)
	}
}

func TestESIMSwitchReconcileUnavailableDeviceRemainsPending(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-reconcile-unavailable.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	operation, err := store.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:      "operation-reconcile-unavailable",
		DeviceID:         "device-test",
		OwnerEpoch:       "epoch-old",
		WorkerGeneration: 2,
		TargetICCID:      "synthetic-target",
		PreRadioState:    db.ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
		OperationID:         operation.OperationID,
		OwnerEpoch:          operation.OwnerEpoch,
		WorkerGeneration:    operation.WorkerGeneration,
		ExpectedPhase:       operation.Phase,
		ExpectedVersion:     operation.Version,
		NextPhase:           db.ESIMSwitchPhaseTeardownPlanned,
		NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
	})
	if err != nil {
		t.Fatalf("persist teardown: %v", err)
	}
	operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
		OperationID:         operation.OperationID,
		OwnerEpoch:          operation.OwnerEpoch,
		WorkerGeneration:    operation.WorkerGeneration,
		ExpectedPhase:       operation.Phase,
		ExpectedVersion:     operation.Version,
		NextPhase:           db.ESIMSwitchPhaseApplyPlanned,
		NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
	})
	if err != nil {
		t.Fatalf("persist apply plan: %v", err)
	}

	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-new"
	backendStub := &esimSwitchRestoreBackendStub{
		mode:         backend.BackendQMI,
		getMode:      backend.ModeOnline,
		liveICCIDErr: errors.New("synthetic unavailable"),
	}
	worker := &Worker{
		ID:         "device-test",
		generation: 1,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend:    backendStub,
	}
	p.workers[worker.ID] = worker
	if err := p.reconcileESIMSwitchForWorker(worker); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if err := p.reconcileESIMSwitchForWorker(worker); err != nil {
		t.Fatalf("repeat reconcile: %v", err)
	}
	if backendStub.liveICCIDCalls != 1 || len(backendStub.setCalls) != 0 {
		t.Fatalf("read_calls=%d restore_calls=%d", backendStub.liveICCIDCalls, len(backendStub.setCalls))
	}
	pending, err := store.GetBlockingByDevice(context.Background(), worker.ID)
	if err != nil {
		t.Fatalf("load pending operation: %v", err)
	}
	if pending.Phase != db.ESIMSwitchPhaseApplyPlanned || pending.Terminal {
		t.Fatalf("pending phase=%q terminal=%v", pending.Phase, pending.Terminal)
	}
}

func TestESIMSwitchReconcileAmbiguousStateNeedsReconciliation(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-reconcile-ambiguous.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	operation, err := store.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:      "operation-reconcile-ambiguous",
		DeviceID:         "device-test",
		OwnerEpoch:       "epoch-old",
		WorkerGeneration: 2,
		TargetICCID:      "synthetic-target",
		PreRadioState:    db.ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
		OperationID:         operation.OperationID,
		OwnerEpoch:          operation.OwnerEpoch,
		WorkerGeneration:    operation.WorkerGeneration,
		ExpectedPhase:       operation.Phase,
		ExpectedVersion:     operation.Version,
		NextPhase:           db.ESIMSwitchPhaseTeardownPlanned,
		NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
	})
	if err != nil {
		t.Fatalf("persist teardown: %v", err)
	}
	operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
		OperationID:         operation.OperationID,
		OwnerEpoch:          operation.OwnerEpoch,
		WorkerGeneration:    operation.WorkerGeneration,
		ExpectedPhase:       operation.Phase,
		ExpectedVersion:     operation.Version,
		NextPhase:           db.ESIMSwitchPhaseApplyPlanned,
		NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
	})
	if err != nil {
		t.Fatalf("persist apply plan: %v", err)
	}

	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-new"
	backendStub := &esimSwitchRestoreBackendStub{
		mode:      backend.BackendQMI,
		getMode:   backend.ModeOnline,
		liveICCID: "different-synthetic-profile",
	}
	worker := &Worker{
		ID:         "device-test",
		generation: 1,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend:    backendStub,
	}
	p.workers[worker.ID] = worker
	if err := p.reconcileESIMSwitchForWorker(worker); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if err := p.reconcileESIMSwitchForWorker(worker); err != nil {
		t.Fatalf("repeat reconcile: %v", err)
	}
	if backendStub.liveICCIDCalls != 1 || len(backendStub.setCalls) != 0 {
		t.Fatalf("read_calls=%d restore_calls=%d", backendStub.liveICCIDCalls, len(backendStub.setCalls))
	}
	pending, err := store.GetBlockingByDevice(context.Background(), worker.ID)
	if err != nil {
		t.Fatalf("load pending operation: %v", err)
	}
	if pending.Phase != db.ESIMSwitchPhaseNeedsReconciliation || pending.Terminal ||
		pending.ErrorCode != db.ESIMSwitchErrorProfileAmbiguous {
		t.Fatalf("pending phase=%q terminal=%v error_code=%q", pending.Phase, pending.Terminal, pending.ErrorCode)
	}
}

func TestNeedsReconciliationOnlyPerformsReadOnlyRecheck(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-reconcile-recheck.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	operation, err := store.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:      "operation-reconcile-recheck",
		DeviceID:         "device-test",
		OwnerEpoch:       "epoch-old",
		WorkerGeneration: 2,
		TargetICCID:      "synthetic-target",
		PreRadioState:    db.ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	for _, next := range []db.ESIMSwitchPhase{
		db.ESIMSwitchPhaseTeardownPlanned,
		db.ESIMSwitchPhaseApplyPlanned,
		db.ESIMSwitchPhaseNeedsReconciliation,
	} {
		operation, err = store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
			OperationID:         operation.OperationID,
			OwnerEpoch:          operation.OwnerEpoch,
			WorkerGeneration:    operation.WorkerGeneration,
			ExpectedPhase:       operation.Phase,
			ExpectedVersion:     operation.Version,
			NextPhase:           next,
			NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
			ErrorCode: func() string {
				if next == db.ESIMSwitchPhaseNeedsReconciliation {
					return db.ESIMSwitchErrorProfileAmbiguous
				}
				return db.ESIMSwitchErrorNone
			}(),
		})
		if err != nil {
			t.Fatalf("transition to %q: %v", next, err)
		}
	}

	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-new"
	backendStub := &esimSwitchRestoreBackendStub{
		mode:      backend.BackendQMI,
		getMode:   backend.ModeOnline,
		liveICCID: "synthetic-target",
	}
	worker := &Worker{
		ID:         "device-test",
		generation: 3,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend:    backendStub,
	}
	p.workers[worker.ID] = worker
	if err := p.reconcileESIMSwitchForWorker(worker); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if backendStub.liveICCIDCalls != 1 {
		t.Fatalf("profile read calls=%d, want 1", backendStub.liveICCIDCalls)
	}
	var completed db.ESIMSwitchOperation
	if err := database.Where("operation_id = ?", operation.OperationID).First(&completed).Error; err != nil {
		t.Fatalf("load completed operation: %v", err)
	}
	if completed.Phase != db.ESIMSwitchPhaseSucceeded || !completed.Terminal ||
		completed.AcceptanceState != db.ESIMSwitchAcceptanceAccepted {
		t.Fatalf("completed phase=%q terminal=%v acceptance=%q", completed.Phase, completed.Terminal, completed.AcceptanceState)
	}
}

func TestCompletedESIMSwitchIsNotReconciledAgain(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-reconcile-terminal.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	operation, err := store.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:      "operation-terminal",
		DeviceID:         "device-test",
		OwnerEpoch:       "epoch-old",
		WorkerGeneration: 1,
		TargetICCID:      "synthetic-target",
		PreRadioState:    db.ESIMSwitchRadioUnknown,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if _, err := store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
		OperationID:         operation.OperationID,
		OwnerEpoch:          operation.OwnerEpoch,
		WorkerGeneration:    operation.WorkerGeneration,
		ExpectedPhase:       operation.Phase,
		ExpectedVersion:     operation.Version,
		NextPhase:           db.ESIMSwitchPhaseFailedBeforePhysicalApply,
		NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
	}); err != nil {
		t.Fatalf("complete operation: %v", err)
	}

	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-new"
	backendStub := &esimSwitchRestoreBackendStub{
		mode:      backend.BackendQMI,
		getMode:   backend.ModeOnline,
		liveICCID: "synthetic-target",
	}
	worker := &Worker{
		ID:         "device-test",
		generation: 2,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend:    backendStub,
	}
	p.workers[worker.ID] = worker
	if err := p.reconcileESIMSwitchForWorker(worker); err != nil {
		t.Fatalf("reconcile terminal operation: %v", err)
	}
	if backendStub.liveICCIDCalls != 0 || len(backendStub.setCalls) != 0 {
		t.Fatalf("terminal operation read_calls=%d restore_calls=%d", backendStub.liveICCIDCalls, len(backendStub.setCalls))
	}
}

func TestCompletedESIMSwitchFailureCallbackDoesNotRestoreAgain(t *testing.T) {
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-terminal-callback.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	operation, err := store.Create(context.Background(), db.CreateESIMSwitchOperationInput{
		OperationID:      "operation-terminal-callback",
		DeviceID:         "device-test",
		OwnerEpoch:       "epoch-current",
		WorkerGeneration: 1,
		TargetICCID:      "synthetic-target",
		PreRadioState:    db.ESIMSwitchRadioOnline,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	completed, err := store.Transition(context.Background(), db.TransitionESIMSwitchOperationInput{
		OperationID:         operation.OperationID,
		OwnerEpoch:          operation.OwnerEpoch,
		WorkerGeneration:    operation.WorkerGeneration,
		ExpectedPhase:       operation.Phase,
		ExpectedVersion:     operation.Version,
		NextPhase:           db.ESIMSwitchPhaseFailedBeforePhysicalApply,
		NextAcceptanceState: db.ESIMSwitchAcceptanceUnknown,
	})
	if err != nil {
		t.Fatalf("complete operation: %v", err)
	}

	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = completed.OwnerEpoch
	backendStub := &esimSwitchRestoreBackendStub{mode: backend.BackendQMI, getMode: backend.ModeRFOff}
	worker := &Worker{
		ID:         completed.DeviceID,
		generation: completed.WorkerGeneration,
		Config:     config.DeviceConfig{ID: completed.DeviceID},
		Backend:    backendStub,
	}
	p.workers[worker.ID] = worker
	const token = uint64(1)
	p.switchingDevices[worker.ID] = true
	p.switchTokens[worker.ID] = token
	p.switchContexts[worker.ID] = esimSwitchContext{
		SwitchToken:      token,
		CapturedAt:       time.Unix(100, 0),
		OperationID:      completed.OperationID,
		OwnerEpoch:       completed.OwnerEpoch,
		WorkerGeneration: completed.WorkerGeneration,
		JournalVersion:   completed.Version,
		JournalPhase:     completed.Phase,
		RadioStateBefore: db.ESIMSwitchRadioOnline,
	}

	p.handleESIMSwitchFailedWithError(worker.ID, token, errors.New("synthetic duplicate callback"))
	if len(backendStub.setCalls) != 0 {
		t.Fatalf("terminal callback performed %d radio operations", len(backendStub.setCalls))
	}
	var after db.ESIMSwitchOperation
	if err := database.Where("operation_id = ?", completed.OperationID).First(&after).Error; err != nil {
		t.Fatalf("load completed operation: %v", err)
	}
	if after.Phase != completed.Phase || after.Version != completed.Version || !after.Terminal {
		t.Fatal("terminal callback changed the completed operation")
	}
}

func TestESIMSwitchReconciliationIsOwnedByPoolLifecycle(t *testing.T) {
	store := &blockingReconciliationJournal{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-test"
	worker := &Worker{ID: "device-test", generation: 1}
	p.workers[worker.ID] = worker
	if !p.scheduleESIMSwitchReconciliation(worker) {
		t.Fatal("reconciliation task was not accepted")
	}
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("reconciliation task did not start")
	}

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- p.ShutdownContext(context.Background())
	}()
	select {
	case err := <-shutdownDone:
		t.Fatalf("ShutdownContext returned before owned reconciliation exited: %v", err)
	default:
	}
	close(store.release)
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("ShutdownContext: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ShutdownContext did not join reconciliation task")
	}
}

type esimSwitchCrashTestEnv struct {
	database *gorm.DB
	store    *db.ESIMSwitchJournalStore
	pool     *Pool
	worker   *Worker
}

func newESIMSwitchCrashTestEnv(t *testing.T) esimSwitchCrashTestEnv {
	t.Helper()
	database, err := gorm.Open(glebarezsqlite.Open(filepath.Join(t.TempDir(), "switch-crash.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.RunESIMSwitchJournalMigration(database); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	store := db.NewESIMSwitchJournalStore(database)
	p := NewPool(&config.Config{})
	p.esimSwitchJournal = store
	p.ownerEpoch = "epoch-before-crash"
	worker := &Worker{
		ID:         "device-test",
		generation: 21,
		Config:     config.DeviceConfig{ID: "device-test"},
		Backend: &esimSwitchRestoreBackendStub{
			mode:    backend.BackendQMI,
			getMode: backend.ModeOnline,
		},
	}
	p.workers[worker.ID] = worker
	p.voWiFiHost().LifecycleControllerForTest().TestRun = func(context.Context, vowifihost.LifecycleCommand) error {
		return nil
	}
	return esimSwitchCrashTestEnv{database: database, store: store, pool: p, worker: worker}
}

func TestESIMSwitchCrashAtEachWriteAheadBoundaryNeverReappliesUnknownAPDU(t *testing.T) {
	for _, tc := range []struct {
		name           string
		point          esimSwitchFailpoint
		wantPhase      db.ESIMSwitchPhase
		wantFinalPhase db.ESIMSwitchPhase
		wantAPDUCalls  int
	}{
		{name: "intent", point: esimSwitchFailpointAfterIntent, wantPhase: db.ESIMSwitchPhaseIntentPersisted, wantFinalPhase: db.ESIMSwitchPhaseFailedBeforePhysicalApply},
		{name: "teardown_planned", point: esimSwitchFailpointAfterTeardownPlanned, wantPhase: db.ESIMSwitchPhaseTeardownPlanned, wantFinalPhase: db.ESIMSwitchPhaseSucceeded},
		{name: "teardown_complete", point: esimSwitchFailpointAfterTeardown, wantPhase: db.ESIMSwitchPhaseTeardownPlanned, wantFinalPhase: db.ESIMSwitchPhaseSucceeded},
		{name: "apply_planned", point: esimSwitchFailpointAfterApplyPlanned, wantPhase: db.ESIMSwitchPhaseApplyPlanned, wantFinalPhase: db.ESIMSwitchPhaseSucceeded},
		{name: "physical_apply_returned", point: esimSwitchFailpointAfterPhysicalApply, wantPhase: db.ESIMSwitchPhaseApplyPlanned, wantFinalPhase: db.ESIMSwitchPhaseSucceeded, wantAPDUCalls: 1},
		{name: "accepted", point: esimSwitchFailpointAfterAccepted, wantPhase: db.ESIMSwitchPhaseAccepted, wantFinalPhase: db.ESIMSwitchPhaseSucceeded, wantAPDUCalls: 1},
		{name: "restoring", point: esimSwitchFailpointDuringRecovery, wantPhase: db.ESIMSwitchPhaseRestoring, wantFinalPhase: db.ESIMSwitchPhaseSucceeded, wantAPDUCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newESIMSwitchCrashTestEnv(t)
			crashErr := errors.New("synthetic crash window")
			env.pool.esimSwitchFailpoint = func(point esimSwitchFailpoint) error {
				if point == tc.point {
					return crashErr
				}
				return nil
			}
			onBefore, onBeforePhysical, onAccepted, _, _, _, _ := env.pool.newESIMSwitchCallbacksForWorker(env.worker)
			token, err := onBefore(esim.SwitchOperationEnableProfile, "synthetic-target")
			apduCalls := 0
			if err == nil {
				err = onBeforePhysical(esim.SwitchOperationEnableProfile, token)
			}
			if err == nil && (tc.point == esimSwitchFailpointAfterPhysicalApply ||
				tc.point == esimSwitchFailpointAfterAccepted || tc.point == esimSwitchFailpointDuringRecovery) {
				apduCalls++
				err = env.pool.hitESIMSwitchFailpoint(esimSwitchFailpointAfterPhysicalApply)
			}
			if err == nil && (tc.point == esimSwitchFailpointAfterAccepted || tc.point == esimSwitchFailpointDuringRecovery) {
				err = onAccepted(esim.SwitchOperationEnableProfile, token)
			}
			if err == nil && tc.point == esimSwitchFailpointDuringRecovery {
				err = env.pool.beginESIMSwitchRecovery(env.worker.ID, token)
			}
			if !errors.Is(err, crashErr) {
				t.Fatalf("crash boundary error=%v", err)
			}
			if apduCalls != tc.wantAPDUCalls {
				t.Fatalf("APDU calls before restart=%d, want %d", apduCalls, tc.wantAPDUCalls)
			}
			operation, err := env.store.GetBlockingByDevice(context.Background(), env.worker.ID)
			if err != nil {
				t.Fatalf("load crash state: %v", err)
			}
			if operation.Phase != tc.wantPhase || operation.Terminal {
				t.Fatalf("crash phase=%q terminal=%v", operation.Phase, operation.Terminal)
			}

			restarted := NewPool(&config.Config{})
			restarted.esimSwitchJournal = env.store
			restarted.ownerEpoch = "epoch-after-crash"
			restartedWorker := &Worker{
				ID:         env.worker.ID,
				generation: 1,
				Config:     config.DeviceConfig{ID: env.worker.ID},
				Backend: &esimSwitchRestoreBackendStub{
					mode:      backend.BackendQMI,
					getMode:   backend.ModeOnline,
					liveICCID: "synthetic-target",
				},
			}
			restarted.workers[restartedWorker.ID] = restartedWorker
			if err := restarted.reconcileESIMSwitchForWorker(restartedWorker); err != nil {
				t.Fatalf("restart reconcile: %v", err)
			}
			if apduCalls != tc.wantAPDUCalls {
				t.Fatalf("APDU calls after restart=%d, want unchanged %d", apduCalls, tc.wantAPDUCalls)
			}
			var completed db.ESIMSwitchOperation
			if err := env.database.Where("operation_id = ?", operation.OperationID).First(&completed).Error; err != nil {
				t.Fatalf("load reconciled operation: %v", err)
			}
			if completed.Phase != tc.wantFinalPhase || !completed.Terminal {
				t.Fatalf("reconciled phase=%q terminal=%v, want phase=%q terminal=true",
					completed.Phase, completed.Terminal, tc.wantFinalPhase)
			}
		})
	}
}
