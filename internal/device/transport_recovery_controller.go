package device

import (
	"strings"
	"sync"
	"time"
)

const (
	rebuildWindow      = 30 * time.Minute
	rebuildMaxInWindow = 5
)

type TransportRecoveryEventKind string

const (
	TransportRecoveryEventRecoveryExhausted TransportRecoveryEventKind = "recovery_exhausted"
	TransportRecoveryEventHealthSuspect     TransportRecoveryEventKind = "health_suspect"
	TransportRecoveryEventMissingWorker     TransportRecoveryEventKind = "missing_worker"
	TransportRecoveryEventManualReboot      TransportRecoveryEventKind = "manual_reboot"
	TransportRecoveryEventUdevWake          TransportRecoveryEventKind = "udev_wake"
)

type TransportRecoveryEvent struct {
	DeviceID         string
	WorkerGeneration uint64
	Kind             TransportRecoveryEventKind
	Source           string
	Err              error
	At               time.Time
}

type TransportRecoveryController struct {
	pool *Pool

	mu                sync.Mutex
	active            map[string]TransportRecoveryEvent
	workerGenerations map[string]uint64
	rebuildTimes      map[string][]time.Time
}

func NewTransportRecoveryController(pool *Pool) *TransportRecoveryController {
	return &TransportRecoveryController{
		pool:              pool,
		active:            make(map[string]TransportRecoveryEvent),
		workerGenerations: make(map[string]uint64),
		rebuildTimes:      make(map[string][]time.Time),
	}
}

func (c *TransportRecoveryController) Observe(event TransportRecoveryEvent) bool {
	if c == nil {
		return false
	}
	event.DeviceID = strings.TrimSpace(event.DeviceID)
	if event.DeviceID == "" || !event.startsRecovery() {
		return false
	}
	if event.At.IsZero() {
		event.At = time.Now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if currentGeneration := c.workerGenerations[event.DeviceID]; currentGeneration != 0 && event.WorkerGeneration != 0 && event.WorkerGeneration != currentGeneration {
		return false
	}
	if _, exists := c.active[event.DeviceID]; exists {
		return false
	}
	c.active[event.DeviceID] = event
	return true
}

func (c *TransportRecoveryController) Finish(deviceID string) {
	if c == nil {
		return
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return
	}
	c.mu.Lock()
	delete(c.active, deviceID)
	c.mu.Unlock()
}

func (c *TransportRecoveryController) SetWorkerGeneration(deviceID string, generation uint64) {
	if c == nil {
		return
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return
	}
	c.mu.Lock()
	if c.workerGenerations[deviceID] != generation {
		delete(c.rebuildTimes, deviceID)
	}
	c.workerGenerations[deviceID] = generation
	c.mu.Unlock()
}

func (c *TransportRecoveryController) SetWorkerGenerationForTest(deviceID string, generation uint64) {
	c.SetWorkerGeneration(deviceID, generation)
}

// AllowRebuild reports whether a worker rebuild for deviceID is permitted under
// the sliding-window cap, recording the attempt when allowed.
func (c *TransportRecoveryController) AllowRebuild(deviceID string) bool {
	return c.allowRebuildAt(strings.TrimSpace(deviceID), time.Now())
}

func (c *TransportRecoveryController) allowRebuildAt(deviceID string, now time.Time) bool {
	if c == nil || deviceID == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-rebuildWindow)
	kept := c.rebuildTimes[deviceID][:0]
	for _, ts := range c.rebuildTimes[deviceID] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= rebuildMaxInWindow {
		c.rebuildTimes[deviceID] = kept
		return false
	}
	kept = append(kept, now)
	c.rebuildTimes[deviceID] = kept
	return true
}

func (event TransportRecoveryEvent) startsRecovery() bool {
	switch event.Kind {
	case TransportRecoveryEventRecoveryExhausted, TransportRecoveryEventHealthSuspect,
		TransportRecoveryEventMissingWorker, TransportRecoveryEventManualReboot, TransportRecoveryEventUdevWake:
		return true
	default:
		return false
	}
}
