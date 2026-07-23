package device

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/db"
)

const esimSwitchReconcileReadTimeout = 5 * time.Second

type esimSwitchActiveProfileReader interface {
	GetICCIDLive(context.Context) (string, error)
}

func (p *Pool) scheduleESIMSwitchReconciliation(worker *Worker) bool {
	if p == nil || worker == nil {
		return false
	}
	return p.startOwnedBackground(func(context.Context) {
		_ = p.reconcileESIMSwitchForWorker(worker)
	})
}

func (p *Pool) reconcileESIMSwitchForWorker(worker *Worker) error {
	if p == nil || worker == nil || strings.TrimSpace(worker.ID) == "" || worker.generation == 0 {
		return db.ErrESIMSwitchOperationInvalid
	}
	store, ok := p.esimSwitchJournal.(esimSwitchReconciliationStore)
	if !ok || strings.TrimSpace(p.ownerEpoch) == "" {
		return db.ErrESIMSwitchJournalUnavailable
	}
	p.mu.RLock()
	currentWorker := p.workers[worker.ID]
	p.mu.RUnlock()
	if currentWorker != worker || currentWorker.generation != worker.generation {
		return db.ErrESIMSwitchOperationStale
	}
	operationLease, ok := worker.acquireESIMOperationLease(p.ctx)
	if !ok {
		return db.ErrESIMSwitchOperationStale
	}
	defer operationLease.Release()

	operation, err := store.GetBlockingByDevice(p.ctx, worker.ID)
	if errors.Is(err, db.ErrESIMSwitchOperationNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	operation, err = store.ClaimForReconciliation(p.ctx, db.ClaimESIMSwitchOperationInput{
		OperationID:              operation.OperationID,
		ExpectedOwnerEpoch:       operation.OwnerEpoch,
		ExpectedWorkerGeneration: operation.WorkerGeneration,
		ExpectedPhase:            operation.Phase,
		ExpectedVersion:          operation.Version,
		NewOwnerEpoch:            p.ownerEpoch,
		NewWorkerGeneration:      worker.generation,
		Now:                      time.Now().UTC(),
	})
	if errors.Is(err, db.ErrESIMSwitchOperationStale) {
		return nil
	}
	if err != nil {
		return err
	}

	if operation.Phase == db.ESIMSwitchPhaseIntentPersisted {
		_, err = p.transitionReconciledESIMSwitch(operation,
			db.ESIMSwitchPhaseFailedBeforePhysicalApply,
			db.ESIMSwitchAcceptanceUnknown,
			db.ESIMSwitchErrorNone,
		)
		return err
	}

	if operation.Phase != db.ESIMSwitchPhaseAccepted && operation.Phase != db.ESIMSwitchPhaseRestoring {
		reader, ok := worker.Backend.(esimSwitchActiveProfileReader)
		if !ok {
			return nil
		}
		readCtx, cancel := context.WithTimeout(p.ctx, esimSwitchReconcileReadTimeout)
		activeICCID, readErr := reader.GetICCIDLive(readCtx)
		cancel()
		if readErr != nil {
			return nil
		}
		activeICCID = normalizeSIMIdentityForCompare(activeICCID)
		targetICCID := normalizeSIMIdentityForCompare(operation.TargetICCID)
		if activeICCID == "" || targetICCID == "" || activeICCID != targetICCID {
			return p.markReconciledESIMSwitchAmbiguous(operation)
		}
		operation, err = p.transitionReconciledESIMSwitch(operation,
			db.ESIMSwitchPhaseAccepted,
			db.ESIMSwitchAcceptanceAccepted,
			db.ESIMSwitchErrorNone,
		)
		if err != nil {
			return err
		}
	}

	if operation.Phase == db.ESIMSwitchPhaseAccepted {
		operation, err = p.transitionReconciledESIMSwitch(operation,
			db.ESIMSwitchPhaseRestoring,
			db.ESIMSwitchAcceptanceAccepted,
			db.ESIMSwitchErrorNone,
		)
		if err != nil {
			return err
		}
	}
	if operation.Phase != db.ESIMSwitchPhaseRestoring {
		return db.ErrESIMSwitchOperationStale
	}
	if err := p.hitESIMSwitchFailpoint(esimSwitchFailpointDuringRecovery); err != nil {
		return err
	}
	if err := operationLease.RunPhysical(func() error {
		return p.restoreReconciledESIMSwitch(operationLease.Context(), worker, operation)
	}); err != nil {
		return err
	}
	_, err = p.transitionReconciledESIMSwitch(operation,
		db.ESIMSwitchPhaseSucceeded,
		db.ESIMSwitchAcceptanceAccepted,
		db.ESIMSwitchErrorNone,
	)
	return err
}

func (p *Pool) transitionReconciledESIMSwitch(
	operation db.ESIMSwitchOperation,
	nextPhase db.ESIMSwitchPhase,
	acceptance db.ESIMSwitchAcceptanceState,
	errorCode string,
) (db.ESIMSwitchOperation, error) {
	return p.transitionOwnedESIMSwitch(operation.DeviceID, esimSwitchContext{
		OwnerEpoch:       operation.OwnerEpoch,
		WorkerGeneration: operation.WorkerGeneration,
	}, db.TransitionESIMSwitchOperationInput{
		OperationID:         operation.OperationID,
		OwnerEpoch:          operation.OwnerEpoch,
		WorkerGeneration:    operation.WorkerGeneration,
		ExpectedPhase:       operation.Phase,
		ExpectedVersion:     operation.Version,
		NextPhase:           nextPhase,
		NextAcceptanceState: acceptance,
		ErrorCode:           errorCode,
		Now:                 time.Now().UTC(),
	})
}

func (p *Pool) markReconciledESIMSwitchAmbiguous(operation db.ESIMSwitchOperation) error {
	if operation.Phase == db.ESIMSwitchPhaseNeedsReconciliation {
		return nil
	}
	acceptance := operation.AcceptanceState
	if acceptance != db.ESIMSwitchAcceptanceAccepted {
		acceptance = db.ESIMSwitchAcceptanceUnknown
	}
	_, err := p.transitionReconciledESIMSwitch(operation,
		db.ESIMSwitchPhaseNeedsReconciliation,
		acceptance,
		db.ESIMSwitchErrorProfileAmbiguous,
	)
	return err
}

func (p *Pool) restoreReconciledESIMSwitch(ctx context.Context, worker *Worker, operation db.ESIMSwitchOperation) error {
	if worker == nil || worker.Backend == nil {
		return fmt.Errorf("eSIM switch recovery device unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	switch operation.PreRadioState {
	case db.ESIMSwitchRadioFlight:
		if err := worker.Backend.SetOperatingMode(ctx, backend.ModeRFOff); err != nil {
			return fmt.Errorf("eSIM switch recovery radio failed")
		}
	case db.ESIMSwitchRadioOnline:
		if err := worker.Backend.SetOperatingMode(ctx, backend.ModeOnline); err != nil {
			return fmt.Errorf("eSIM switch recovery radio failed")
		}
	}

	wantNetwork := operation.PreNetworkConnected || operation.PreNetworkEnabled
	if controller := worker.NetworkController(); controller != nil {
		if wantNetwork && !controller.IsConnected() {
			if err := worker.StartNetwork(); err != nil {
				return fmt.Errorf("eSIM switch recovery network failed")
			}
		} else if !wantNetwork && controller.IsConnected() {
			if err := worker.StopNetwork(); err != nil {
				return fmt.Errorf("eSIM switch recovery network failed")
			}
		}
	} else if wantNetwork {
		return fmt.Errorf("eSIM switch recovery network unavailable")
	}

	if operation.PreVoWiFiActive {
		if err := p.voWiFiHost().SwitchEnd(ctx, worker.ID, true); err != nil {
			return fmt.Errorf("eSIM switch recovery VoWiFi failed")
		}
	}
	return nil
}
