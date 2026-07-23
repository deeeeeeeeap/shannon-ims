package device

type ReadinessSnapshot struct {
	Ready            bool   `json:"ready"`
	Initialized      bool   `json:"initialized"`
	Degraded         bool   `json:"degraded"`
	Reason           string `json:"reason"`
	TotalWorkers     int    `json:"total_workers"`
	AvailableWorkers int    `json:"available_workers"`
}

func (p *Pool) beginInitialization(attempts int) {
	if p == nil {
		return
	}
	if attempts < 0 {
		attempts = 0
	}
	p.initializationMu.Lock()
	p.initializationPending = attempts
	p.initializationComplete = attempts == 0
	p.initializationMu.Unlock()
}

func (p *Pool) finishInitializationAttempt() {
	if p == nil {
		return
	}
	p.initializationMu.Lock()
	defer p.initializationMu.Unlock()
	if p.initializationPending <= 0 {
		return
	}
	p.initializationPending--
	if p.initializationPending == 0 {
		p.initializationComplete = true
	}
}

func (p *Pool) ReadinessSnapshot() ReadinessSnapshot {
	if p == nil {
		return ReadinessSnapshot{Reason: "initializing"}
	}
	p.initializationMu.RLock()
	initialized := p.initializationComplete
	p.initializationMu.RUnlock()

	p.mu.RLock()
	workers := make([]*Worker, 0, len(p.workers))
	for _, worker := range p.workers {
		workers = append(workers, worker)
	}
	p.mu.RUnlock()
	totalWorkers := len(workers)
	if !initialized {
		return ReadinessSnapshot{
			Reason:       "initializing",
			TotalWorkers: totalWorkers,
		}
	}
	if totalWorkers == 0 {
		return ReadinessSnapshot{
			Initialized: true,
			Reason:      "no_workers",
		}
	}
	availableWorkers := 0
	controlDegraded := false
	for _, worker := range workers {
		if worker.GetCachedHealthy() {
			availableWorkers++
		}
		switch worker.HealthSnapshot().State {
		case HealthStateInvalid, HealthStateFailed:
			controlDegraded = true
		}
	}
	if controlDegraded {
		return ReadinessSnapshot{
			Initialized:      true,
			Degraded:         true,
			Reason:           "control_degraded",
			TotalWorkers:     totalWorkers,
			AvailableWorkers: availableWorkers,
		}
	}
	if availableWorkers > 0 {
		return ReadinessSnapshot{
			Ready:            true,
			Initialized:      true,
			Reason:           "ready",
			TotalWorkers:     totalWorkers,
			AvailableWorkers: availableWorkers,
		}
	}
	return ReadinessSnapshot{
		Initialized:      true,
		Reason:           "no_available_workers",
		TotalWorkers:     totalWorkers,
		AvailableWorkers: availableWorkers,
	}
}
