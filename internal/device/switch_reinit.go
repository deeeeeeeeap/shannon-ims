package device

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// QMI UIM refresh stage values (QMI spec: 0x01 START / 0x02 END_WITH_SUCCESS / 0x03 END_WITH_FAILURE).
const (
	uimRefreshStageStart          uint8 = 0x01
	uimRefreshStageEndWithSuccess uint8 = 0x02
	uimRefreshStageEndWithFailure uint8 = 0x03
)

type switchEventKind int

const (
	switchEventRefresh switchEventKind = iota
	switchEventSlotStatus
)

type switchEvent struct {
	Kind         switchEventKind
	RefreshStage uint8
}

type reinitResult int

const (
	reinitConverged reinitResult = iota
	reinitTimeout
)

func (r reinitResult) String() string {
	if r == reinitConverged {
		return "reinitConverged"
	}
	return "reinitTimeout"
}

// switchEventSource forwards UIM indications to the active switch convergence flow.
// Each switch gets its own instance.
type switchEventSource struct {
	mu     sync.Mutex
	ch     chan switchEvent
	closed bool
}

func newSwitchEventSource() *switchEventSource {
	return &switchEventSource{ch: make(chan switchEvent, 16)}
}

func (s *switchEventSource) Events() <-chan switchEvent { return s.ch }

func (s *switchEventSource) publish(ev switchEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- ev:
	default:
	}
}

func (s *switchEventSource) PublishRefresh(stage uint8) {
	s.publish(switchEvent{Kind: switchEventRefresh, RefreshStage: stage})
}

func (s *switchEventSource) PublishSlotStatus() {
	s.publish(switchEvent{Kind: switchEventSlotStatus})
}

func (s *switchEventSource) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
}

func awaitReinitConverged(ctx context.Context, src *switchEventSource, rdy postSwitchReadinessProvider, targetICCID string, window time.Duration) reinitResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if src == nil || rdy == nil || window <= 0 {
		return reinitTimeout
	}

	waitCtx, cancel := context.WithTimeout(ctx, window)
	defer cancel()

	events := src.Events()
	for {
		select {
		case <-waitCtx.Done():
			return reinitTimeout
		case ev, ok := <-events:
			if !ok {
				return reinitTimeout
			}
			if !isReinitConvergenceEvent(ev) {
				continue
			}
			if confirmReinitReadiness(waitCtx, rdy, targetICCID) {
				return reinitConverged
			}
		}
	}
}

func isReinitConvergenceEvent(ev switchEvent) bool {
	return ev.Kind == switchEventSlotStatus ||
		(ev.Kind == switchEventRefresh && ev.RefreshStage == uimRefreshStageEndWithSuccess)
}

func confirmReinitReadiness(ctx context.Context, rdy postSwitchReadinessProvider, targetICCID string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	readiness, _ := rdy.GetUIMReadiness(probeCtx)
	return classifyPostSwitchReadiness(readiness, targetICCID).Action == postSwitchActionRestoreRuntime
}

// triggerPowerCycleFallback 做一次受控 UIM 重启（off→短暂等待→on），不触发整机复位。
func triggerPowerCycleFallback(ctx context.Context, power postSwitchSIMPowerController, slot uint8) error {
	if power == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var firstErr error
	if err := power.UIMPowerOffSIM(ctx, slot); err != nil {
		firstErr = err
	}
	select {
	case <-ctx.Done():
		if firstErr != nil {
			return firstErr
		}
		return ctx.Err()
	case <-time.After(500 * time.Millisecond):
	}
	onErr := power.UIMPowerOnSIM(ctx, slot)
	if firstErr != nil && onErr != nil {
		return fmt.Errorf("power off failed: %v; power on failed: %w", firstErr, onErr)
	}
	if onErr != nil {
		return onErr
	}
	return firstErr
}
