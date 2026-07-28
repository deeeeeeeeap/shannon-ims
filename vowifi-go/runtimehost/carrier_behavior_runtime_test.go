//go:build linux

package runtimehost

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/1239t/vowifi-go/runtimehost/identity"
)

type carrierBehaviorTestSIM struct{}

func (carrierBehaviorTestSIM) GetIMSI() (string, error) {
	return "000000000000000", nil
}

func (carrierBehaviorTestSIM) CalculateAKA([]byte, []byte) (sim.AKAResult, error) {
	return sim.AKAResult{}, nil
}

func (carrierBehaviorTestSIM) Close() error {
	return nil
}

func TestStartResolvesCarrierBehaviorOncePerRuntimeAttempt(t *testing.T) {
	var resolveCalls atomic.Int32
	var shouldRunCalls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inst, err := Start(ctx, StartRequest{
		DeviceID: "synthetic-device",
		Profile: Profile{
			IMSI: "000000000000000",
			MCC:  "310",
			MNC:  "240",
		},
		Prepared: &identity.PreparedSession{
			Profile: identity.Profile{
				IMSI: "000000000000000",
				MCC:  "310",
				MNC:  "240",
			},
		},
		SIM: carrierBehaviorTestSIM{},
		ShouldRun: func() bool {
			return shouldRunCalls.Add(1) == 1
		},
		carrierBehaviorResolver: func(mcc, mnc string) policy.CarrierBehavior {
			resolveCalls.Add(1)
			return policy.ResolveCarrierBehavior(mcc, mnc)
		},
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if got := resolveCalls.Load(); got != 1 {
		t.Fatalf("CarrierBehavior resolution calls = %d, want 1", got)
	}
	if got := inst.carrierBehavior.RegisterTemplate.ID; got != "3gpp-default" {
		t.Fatalf("RuntimeInstance CarrierBehavior template = %q, want 3gpp-default", got)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := inst.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if got := resolveCalls.Load(); got != 1 {
		t.Fatalf("CarrierBehavior lifetime resolution calls = %d, want 1", got)
	}
}
