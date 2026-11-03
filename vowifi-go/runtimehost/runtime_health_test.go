package runtimehost

import (
	"context"
	"testing"
	"time"
)

func TestRuntimeFailureClearsReadiness(t *testing.T) {
	i := &Instance{lifecycleGeneration: 1, state: State{IMSReady: true, SMSReady: true, TunnelReady: true}}
	i.failStageForGeneration(context.Background(), 1, "ims", "IMS channel closed", "ims_channel_closed")
	state := i.State()
	if state.IMSReady || state.SMSReady || !state.TunnelReady {
		t.Fatal("failed IMS channel still appears ready")
	}
}

func TestRuntimeHealthPublishesChannelLoss(t *testing.T) {
	i := &Instance{lifecycleGeneration: 1, state: State{IMSReady: true, SMSReady: true, TunnelReady: true}}
	channelDone := make(chan struct{})
	close(channelDone)
	i.watchIMSHealth(context.Background(), 1, channelDone, nil, nil)
	state := i.State()
	if state.IMSReady || state.SMSReady || state.LastReason != "ims_channel_closed" {
		t.Fatal("channel closure did not revoke messaging readiness")
	}
}

func TestRuntimeHealthExpiryAndStaleAttempt(t *testing.T) {
	expired := make(chan time.Time, 1)
	expired <- time.Now()
	i := &Instance{lifecycleGeneration: 2, state: State{IMSReady: true, SMSReady: true}}
	i.watchIMSHealth(context.Background(), 1, nil, nil, expired)
	if !i.State().SMSReady {
		t.Fatal("old attempt revoked current messaging capability")
	}
	expired <- time.Now()
	i.watchIMSHealth(context.Background(), 2, nil, nil, expired)
	if i.State().SMSReady || i.State().LastReason != "ims_registration_expired" {
		t.Fatal("expired registration remains ready")
	}
}
