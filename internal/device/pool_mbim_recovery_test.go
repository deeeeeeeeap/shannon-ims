package device

import (
	"errors"
	"testing"
)

// Over-cap MBIM exhausted events must NOT schedule a rebuild; instead the
// worker is marked Failed.
func TestMBIMRecoveryExhaustedRespectsRebuildGuard(t *testing.T) {
	p := &Pool{}
	p.transportRecovery = NewTransportRecoveryController(p)
	worker := &Worker{ID: "mbim-dev", generation: 1}
	p.transportRecovery.SetWorkerGeneration(worker.ID, 1)

	for i := 0; i < rebuildMaxInWindow; i++ {
		if !p.transportRecovery.AllowRebuild(worker.ID) {
			t.Fatalf("pre-fill attempt %d should be allowed", i+1)
		}
	}

	scheduled := p.maybeScheduleTransportRebuild(worker, HealthLayerMBIM, "still_hung", errors.New("hung"))
	if scheduled {
		t.Fatal("rebuild should be refused once the window cap is hit")
	}
	if got := worker.HealthSnapshot().State; got != HealthStateFailed {
		t.Fatalf("worker state = %v, want Failed after guard refusal", got)
	}
}
