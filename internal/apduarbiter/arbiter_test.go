package apduarbiter

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestArbiterFIFO(t *testing.T) {
	arb := New("dev-1", Options{})

	first, err := arb.AcquireSession(context.Background(), "first", "AT")
	if err != nil {
		t.Fatalf("AcquireSession(first) failed: %v", err)
	}
	defer first.Release()

	order := make(chan string, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		lease, acquireErr := arb.AcquireSession(context.Background(), "second", "AT")
		if acquireErr != nil {
			t.Errorf("AcquireSession(second) failed: %v", acquireErr)
			return
		}
		order <- "second"
		lease.Release()
	}()

	time.Sleep(20 * time.Millisecond)

	go func() {
		defer wg.Done()
		lease, acquireErr := arb.AcquireSession(context.Background(), "third", "AT")
		if acquireErr != nil {
			t.Errorf("AcquireSession(third) failed: %v", acquireErr)
			return
		}
		order <- "third"
		lease.Release()
	}()

	time.Sleep(80 * time.Millisecond)
	first.Release()
	wg.Wait()
	close(order)

	got := make([]string, 0, 2)
	for entry := range order {
		got = append(got, entry)
	}
	if len(got) != 2 {
		t.Fatalf("unexpected order length: %d", len(got))
	}
	if got[0] != "second" || got[1] != "third" {
		t.Fatalf("unexpected FIFO order: %v", got)
	}
}

func TestArbiterTimeout(t *testing.T) {
	arb := New("dev-1", Options{})

	lease, err := arb.AcquireSession(context.Background(), "holder", "QMI")
	if err != nil {
		t.Fatalf("AcquireSession(holder) failed: %v", err)
	}
	defer lease.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err = arb.AcquireSession(ctx, "waiter", "QMI")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, ErrAPDUBusy) {
		t.Fatalf("expected ErrAPDUBusy, got %v", err)
	}
}

func TestArbiterWaitIdle(t *testing.T) {
	arb := New("dev-1", Options{})
	lease, err := arb.AcquireSession(context.Background(), "holder", "AT")
	if err != nil {
		t.Fatalf("AcquireSession(holder) failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(60 * time.Millisecond)
		lease.Release()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := arb.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle failed: %v", err)
	}
	<-done
}

func TestTransportUSIMAKAAcquiresBetweenEUICCTransports(t *testing.T) {
	arb := New("dev-1", Options{})
	first, err := arb.AcquireTransport(context.Background(), Request{
		Owner: "download",
		Mode:  "QMI",
		Class: APDUClassEUICCWrite,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(first) error=%v", err)
	}

	order := make(chan string, 2)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		lease, acquireErr := arb.AcquireTransport(ctx, Request{Owner: "download-next", Mode: "QMI", Class: APDUClassEUICCWrite})
		if acquireErr != nil {
			t.Errorf("AcquireTransport(euicc) error=%v", acquireErr)
			return
		}
		order <- "euicc"
		lease.Release()
	}()
	time.Sleep(20 * time.Millisecond)
	go func() {
		lease, acquireErr := arb.AcquireTransport(ctx, Request{Owner: "vowifi_aka", Mode: "QMI", Class: APDUClassUSIMAKA})
		if acquireErr != nil {
			t.Errorf("AcquireTransport(aka) error=%v", acquireErr)
			return
		}
		order <- "aka"
		lease.Release()
	}()

	time.Sleep(40 * time.Millisecond)
	first.Release()
	select {
	case got := <-order:
		if got != "aka" {
			t.Fatalf("first acquired transport=%q want aka", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first transport")
	}
	select {
	case got := <-order:
		if got != "euicc" {
			t.Fatalf("second acquired transport=%q want euicc", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for second transport")
	}
}

func TestTransportPriorityAgingPreventsEUICCStarvation(t *testing.T) {
	arb := New("dev-1", Options{})
	first, err := arb.AcquireTransport(context.Background(), Request{
		Owner: "holder",
		Mode:  "QMI",
		Class: APDUClassEUICCWrite,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(first) error=%v", err)
	}

	order := make(chan string, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		lease, acquireErr := arb.AcquireTransport(ctx, Request{Owner: "aged-euicc", Mode: "QMI", Class: APDUClassEUICCWrite})
		if acquireErr != nil {
			t.Errorf("AcquireTransport(euicc) error=%v", acquireErr)
			return
		}
		order <- "euicc"
		lease.Release()
	}()
	time.Sleep(transportPriorityAging + 80*time.Millisecond)
	go func() {
		lease, acquireErr := arb.AcquireTransport(ctx, Request{Owner: "vowifi_aka", Mode: "QMI", Class: APDUClassUSIMAKA})
		if acquireErr != nil {
			t.Errorf("AcquireTransport(aka) error=%v", acquireErr)
			return
		}
		order <- "aka"
		lease.Release()
	}()

	time.Sleep(40 * time.Millisecond)
	first.Release()
	select {
	case got := <-order:
		if got != "euicc" {
			t.Fatalf("first acquired transport=%q want euicc", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first transport")
	}
}

func TestQMIChannelTransportsAcquireConcurrentlyAcrossChannels(t *testing.T) {
	arb := New("dev-1", Options{MaxQMITransports: 3})
	first, err := arb.AcquireTransport(context.Background(), Request{
		Owner:   "profile-a",
		Mode:    "QMI",
		Class:   APDUClassEUICCWrite,
		Channel: 2,
		Scope:   TransportScopeQMIChannel,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(first) error=%v", err)
	}
	defer first.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	second, err := arb.AcquireTransport(ctx, Request{
		Owner:   "profile-b",
		Mode:    "QMI",
		Class:   APDUClassEUICCWrite,
		Channel: 3,
		Scope:   TransportScopeQMIChannel,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(second different channel) error=%v", err)
	}
	defer second.Release()

	if stats := arb.Stats(); stats.ActiveTransports != 2 {
		t.Fatalf("ActiveTransports=%d want 2: %+v", stats.ActiveTransports, stats)
	}
}

func TestQMIChannelTransportSerializesSameChannel(t *testing.T) {
	arb := New("dev-1", Options{MaxQMITransports: 3})
	first, err := arb.AcquireTransport(context.Background(), Request{
		Owner:   "profile-a",
		Mode:    "QMI",
		Class:   APDUClassEUICCWrite,
		Channel: 2,
		Scope:   TransportScopeQMIChannel,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(first) error=%v", err)
	}
	defer first.Release()

	acquired := make(chan struct{})
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		defer close(done)
		lease, acquireErr := arb.AcquireTransport(ctx, Request{
			Owner:   "profile-a-next",
			Mode:    "QMI",
			Class:   APDUClassEUICCWrite,
			Channel: 2,
			Scope:   TransportScopeQMIChannel,
		})
		if acquireErr != nil {
			t.Errorf("AcquireTransport(waiter) error=%v", acquireErr)
			return
		}
		close(acquired)
		lease.Release()
	}()

	select {
	case <-acquired:
		t.Fatal("same-channel QMI transport acquired while channel was active")
	case <-time.After(80 * time.Millisecond):
	}

	first.Release()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("same-channel QMI transport did not acquire after release")
	}
	<-done
}

func TestExclusiveTransportWaitsForActiveQMIChannelTransport(t *testing.T) {
	arb := New("dev-1", Options{MaxQMITransports: 3})
	first, err := arb.AcquireTransport(context.Background(), Request{
		Owner:   "profile-a",
		Mode:    "QMI",
		Class:   APDUClassEUICCWrite,
		Channel: 2,
		Scope:   TransportScopeQMIChannel,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(first) error=%v", err)
	}
	defer first.Release()

	acquired := make(chan struct{})
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		defer close(done)
		lease, acquireErr := arb.AcquireTransport(ctx, Request{
			Owner:   "qmi_channel_close",
			Mode:    "QMI",
			Class:   APDUClassRecovery,
			Channel: 2,
		})
		if acquireErr != nil {
			t.Errorf("AcquireTransport(exclusive) error=%v", acquireErr)
			return
		}
		close(acquired)
		lease.Release()
	}()

	select {
	case <-acquired:
		t.Fatal("exclusive transport acquired while QMI channel transport was active")
	case <-time.After(80 * time.Millisecond):
	}

	first.Release()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("exclusive transport did not acquire after active QMI transport release")
	}
	<-done
}

func TestQueuedExclusiveTransportGatesLaterQMIChannelTransport(t *testing.T) {
	arb := New("dev-1", Options{MaxQMITransports: 3})
	first, err := arb.AcquireTransport(context.Background(), Request{
		Owner:   "profile-a",
		Mode:    "QMI",
		Class:   APDUClassEUICCWrite,
		Channel: 2,
		Scope:   TransportScopeQMIChannel,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(first) error=%v", err)
	}
	defer first.Release()

	exclusiveAcquired := make(chan struct{})
	releaseExclusive := make(chan struct{})
	exclusiveDone := make(chan struct{})
	qmiAcquired := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		defer close(exclusiveDone)
		lease, acquireErr := arb.AcquireTransport(ctx, Request{
			Owner:   "qmi_channel_close",
			Mode:    "QMI",
			Class:   APDUClassRecovery,
			Channel: 2,
		})
		if acquireErr != nil {
			t.Errorf("AcquireTransport(exclusive) error=%v", acquireErr)
			return
		}
		close(exclusiveAcquired)
		<-releaseExclusive
		lease.Release()
	}()

	time.Sleep(20 * time.Millisecond)
	go func() {
		lease, acquireErr := arb.AcquireTransport(ctx, Request{
			Owner:   "profile-b",
			Mode:    "QMI",
			Class:   APDUClassEUICCWrite,
			Channel: 3,
			Scope:   TransportScopeQMIChannel,
		})
		if acquireErr != nil {
			return
		}
		close(qmiAcquired)
		lease.Release()
	}()

	select {
	case <-qmiAcquired:
		t.Fatal("later QMI channel transport passed queued exclusive transport")
	case <-time.After(80 * time.Millisecond):
	}

	first.Release()
	select {
	case <-exclusiveAcquired:
	case <-time.After(time.Second):
		t.Fatal("exclusive transport did not acquire after active QMI transport release")
	}
	select {
	case <-qmiAcquired:
		t.Fatal("later QMI channel transport acquired while exclusive transport was active")
	case <-time.After(80 * time.Millisecond):
	}
	close(releaseExclusive)
	<-exclusiveDone
	select {
	case <-qmiAcquired:
	case <-time.After(time.Second):
		t.Fatal("later QMI channel transport did not acquire after exclusive transport release")
	}
}

func TestSwitchBarrierBlocksUSIMAKAAndAllowsEUICC(t *testing.T) {
	arb := New("dev-1", Options{})
	first, err := arb.AcquireTransport(context.Background(), Request{Owner: "holder", Mode: "QMI", Class: APDUClassEUICCWrite})
	if err != nil {
		t.Fatalf("AcquireTransport(first) error=%v", err)
	}

	barrierCh := make(chan *Barrier, 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		barrier, beginErr := arb.BeginBarrier(ctx, Request{Owner: "switch", Mode: "QMI", Class: APDUClassSwitchBarrier}, BarrierPolicy{})
		if beginErr != nil {
			errCh <- beginErr
			return
		}
		barrierCh <- barrier
	}()

	waitForQueuedClass(t, arb, APDUClassSwitchBarrier, LeaseTypeBarrier)

	akaAcquired := make(chan struct{})
	go func() {
		lease, acquireErr := arb.AcquireTransport(ctx, Request{Owner: "vowifi_aka", Mode: "QMI", Class: APDUClassUSIMAKA})
		if acquireErr != nil {
			return
		}
		close(akaAcquired)
		lease.Release()
	}()

	first.Release()
	var barrier *Barrier
	select {
	case barrier = <-barrierCh:
	case err := <-errCh:
		t.Fatalf("BeginBarrier() error=%v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for barrier")
	}
	defer barrier.Release()

	select {
	case <-akaAcquired:
		t.Fatal("USIMAKA acquired while switch barrier was active")
	default:
	}

	euicc, err := arb.AcquireTransport(ctx, Request{Owner: "switch-apdu", Mode: "QMI", Class: APDUClassEUICCWrite})
	if err != nil {
		t.Fatalf("EUICC transport under barrier error=%v", err)
	}
	euicc.Release()
	select {
	case <-akaAcquired:
		t.Fatal("USIMAKA acquired after unrelated EUICC transport while barrier active")
	default:
	}

	barrier.Release()
	select {
	case <-akaAcquired:
	case <-time.After(time.Second):
		t.Fatal("USIMAKA did not acquire after barrier release")
	}
}

func waitForQueuedClass(t *testing.T, arb *Arbiter, class APDUClass, leaseType LeaseType) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		for _, entry := range arb.Snapshot().Queue {
			if entry.Class == class && entry.LeaseType == leaseType {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for queued class=%s lease_type=%s", class, leaseType)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSnapshotReportsTransportAndBarrier(t *testing.T) {
	arb := New("dev-1", Options{})
	barrier, err := arb.BeginBarrier(context.Background(), Request{Owner: "switch", Mode: "QMI", Class: APDUClassSwitchBarrier}, BarrierPolicy{})
	if err != nil {
		t.Fatalf("BeginBarrier() error=%v", err)
	}
	defer barrier.Release()

	lease, err := arb.AcquireTransport(context.Background(), Request{Owner: "switch-apdu", Mode: "QMI", Class: APDUClassEUICCWrite, Channel: 2})
	if err != nil {
		t.Fatalf("AcquireTransport() error=%v", err)
	}
	defer lease.Release()

	snap := arb.Snapshot()
	if len(snap.Active) != 2 {
		t.Fatalf("active entries=%d want 2: %+v", len(snap.Active), snap.Active)
	}
}

func TestLeaseTouchExtendsSessionWatchdog(t *testing.T) {
	arb := New("dev-1", Options{MaxLeaseHold: 40 * time.Millisecond})

	lease, err := arb.AcquireSession(context.Background(), "holder", "QMI")
	if err != nil {
		t.Fatalf("AcquireSession(holder) failed: %v", err)
	}
	defer lease.Release()

	acquired := make(chan struct{})
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go func() {
		defer close(done)
		waiter, acquireErr := arb.AcquireOneShot(ctx, "waiter", "AT")
		if acquireErr != nil {
			return
		}
		close(acquired)
		waiter.Release()
	}()

	deadline := time.After(130 * time.Millisecond)
	ticker := time.NewTicker(15 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			lease.Touch()
		case <-deadline:
			goto touchedEnough
		}
	}

touchedEnough:
	select {
	case <-acquired:
		t.Fatal("oneshot acquired while session lease was being touched")
	default:
	}
	stats := arb.Stats()
	if stats.ForcedReleases != 0 {
		t.Fatalf("ForcedReleases=%d want 0", stats.ForcedReleases)
	}
	if stats.ActiveSessions != 1 || stats.ActiveOneshot {
		t.Fatalf("unexpected stats after touch: %+v", stats)
	}

	lease.Release()
	select {
	case <-acquired:
	case <-time.After(150 * time.Millisecond):
		t.Fatal("oneshot did not acquire after session release")
	}
	<-done
}

func TestLeaseTouchExtendsOneShotWatchdog(t *testing.T) {
	arb := New("dev-1", Options{MaxLeaseHold: 40 * time.Millisecond})

	lease, err := arb.AcquireOneShot(context.Background(), "holder", "AT")
	if err != nil {
		t.Fatalf("AcquireOneShot(holder) failed: %v", err)
	}
	defer lease.Release()

	deadline := time.After(130 * time.Millisecond)
	ticker := time.NewTicker(15 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			lease.Touch()
		case <-deadline:
			stats := arb.Stats()
			if stats.ForcedReleases != 0 {
				t.Fatalf("ForcedReleases=%d want 0", stats.ForcedReleases)
			}
			if !stats.ActiveOneshot || stats.ActiveSessions != 0 {
				t.Fatalf("unexpected stats after touch: %+v", stats)
			}
			return
		}
	}
}

func TestLeaseWatchdogMarksSuspectWithoutForceRelease(t *testing.T) {
	tests := []struct {
		name    string
		acquire func(*Arbiter) (*Lease, error)
	}{
		{
			name: "session",
			acquire: func(arb *Arbiter) (*Lease, error) {
				return arb.AcquireSession(context.Background(), "holder", "QMI")
			},
		},
		{
			name: "oneshot",
			acquire: func(arb *Arbiter) (*Lease, error) {
				return arb.AcquireOneShot(context.Background(), "holder", "AT")
			},
		},
		{
			name: "transport",
			acquire: func(arb *Arbiter) (*Lease, error) {
				return arb.AcquireTransport(context.Background(), Request{Owner: "holder", Mode: "QMI", Class: APDUClassEUICCWrite})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arb := New("dev-1", Options{MaxLeaseHold: 30 * time.Millisecond})
			lease, err := tt.acquire(arb)
			if err != nil {
				t.Fatalf("acquire failed: %v", err)
			}
			t.Cleanup(lease.Release)

			deadline := time.Now().Add(time.Second)
			for arb.Stats().SuspectLeases != 1 {
				if time.Now().After(deadline) {
					t.Fatalf("watchdog did not mark lease suspect: %+v", arb.Stats())
				}
				time.Sleep(time.Millisecond)
			}
			stats := arb.Stats()
			if stats.ForcedReleases != 0 {
				t.Fatalf("ForcedReleases=%d want 0", stats.ForcedReleases)
			}
			if !lease.Active() {
				t.Fatal("lease.Active()=false after watchdog, want suspect ownership to remain active")
			}
			if lease.Touch() {
				t.Fatal("lease.Touch()=true for suspect lease, want false")
			}

			idleCtx, cancelIdle := context.WithTimeout(context.Background(), 20*time.Millisecond)
			if err := arb.WaitIdle(idleCtx); !errors.Is(err, ErrAPDUBusy) {
				cancelIdle()
				t.Fatalf("WaitIdle() error=%v, want ErrAPDUBusy while suspect", err)
			}
			cancelIdle()
			lease.Release()
			finalCtx, cancelFinal := context.WithTimeout(context.Background(), time.Second)
			defer cancelFinal()
			if err := arb.WaitIdle(finalCtx); err != nil {
				t.Fatalf("WaitIdle() after owner done error=%v", err)
			}
		})
	}
}

func TestTransportWatchdogKeepsSuspectOwnershipUntilOwnerDone(t *testing.T) {
	arb := New("dev-1", Options{MaxLeaseHold: 25 * time.Millisecond})
	first, err := arb.AcquireTransport(context.Background(), Request{
		Owner: "operation-a",
		Mode:  "QMI",
		Class: APDUClassEUICCWrite,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(operation-a) error=%v", err)
	}
	defer first.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Millisecond)
	defer cancel()
	second, err := arb.AcquireTransport(ctx, Request{
		Owner: "operation-b",
		Mode:  "QMI",
		Class: APDUClassEUICCWrite,
	})
	if err == nil {
		second.Release()
		t.Fatal("operation-b acquired transport while timed-out operation-a had not reported done")
	}
	if !errors.Is(err, ErrAPDUBusy) {
		t.Fatalf("AcquireTransport(operation-b) error=%v, want ErrAPDUBusy", err)
	}
	if !first.Active() {
		t.Fatal("operation-a lease is inactive after watchdog, want suspect ownership to remain active")
	}
	if first.Touch() {
		t.Fatal("Touch() revived a suspect lease, want false")
	}

	first.Release()
	thirdCtx, thirdCancel := context.WithTimeout(context.Background(), time.Second)
	defer thirdCancel()
	third, err := arb.AcquireTransport(thirdCtx, Request{
		Owner: "operation-c",
		Mode:  "QMI",
		Class: APDUClassEUICCWrite,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(operation-c) after owner done error=%v", err)
	}
	third.Release()
}

func TestQMIChannelTransportWatchdogBlocksAllChannelsUntilOwnerRelease(t *testing.T) {
	arb := New("dev-1", Options{
		MaxLeaseHold:     20 * time.Millisecond,
		MaxQMITransports: 2,
	})
	first, err := arb.AcquireTransport(context.Background(), Request{
		Owner:   "operation-a",
		Mode:    "QMI",
		Class:   APDUClassEUICCWrite,
		Channel: 1,
		Scope:   TransportScopeQMIChannel,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(channel 1) error=%v", err)
	}
	defer first.Release()

	deadline := time.Now().Add(time.Second)
	for arb.Stats().SuspectLeases != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("channel 1 lease did not become suspect: %+v", arb.Stats())
		}
		time.Sleep(time.Millisecond)
	}

	blockedCtx, cancelBlocked := context.WithTimeout(context.Background(), 50*time.Millisecond)
	second, err := arb.AcquireTransport(blockedCtx, Request{
		Owner:   "operation-b",
		Mode:    "QMI",
		Class:   APDUClassEUICCWrite,
		Channel: 2,
		Scope:   TransportScopeQMIChannel,
	})
	cancelBlocked()
	if err == nil {
		second.Release()
		t.Fatal("channel 2 acquired while channel 1 remained suspect")
	}
	if !errors.Is(err, ErrAPDUBusy) {
		t.Fatalf("AcquireTransport(channel 2) error=%v, want ErrAPDUBusy", err)
	}

	first.Release()
	reopenedCtx, cancelReopened := context.WithTimeout(context.Background(), time.Second)
	defer cancelReopened()
	second, err = arb.AcquireTransport(reopenedCtx, Request{
		Owner:   "operation-b",
		Mode:    "QMI",
		Class:   APDUClassEUICCWrite,
		Channel: 2,
		Scope:   TransportScopeQMIChannel,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(channel 2) after owner release error=%v", err)
	}
	second.Release()
}

func TestTransportWatchdogExposesSuspectState(t *testing.T) {
	arb := New("dev-1", Options{MaxLeaseHold: 20 * time.Millisecond})
	lease, err := arb.AcquireTransport(context.Background(), Request{
		Owner: "operation-a",
		Mode:  "QMI",
		Class: APDUClassEUICCWrite,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(operation-a) error=%v", err)
	}
	defer lease.Release()

	deadline := time.Now().Add(time.Second)
	for {
		stats := arb.Stats()
		snapshot := arb.Snapshot()
		if stats.SuspectLeases == 1 && len(snapshot.Active) == 1 && snapshot.Active[0].Suspect {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("suspect state not exposed: stats=%+v snapshot=%+v", stats, snapshot)
		}
		time.Sleep(time.Millisecond)
	}

	lease.Release()
	if got := arb.Stats().SuspectLeases; got != 0 {
		t.Fatalf("SuspectLeases after owner done = %d, want 0", got)
	}
}

func TestTransportWatchdogReopensOnlyAfterRecoverySucceeds(t *testing.T) {
	recoveryStarted := make(chan struct{})
	allowRecovery := make(chan struct{})
	arb := New("dev-1", Options{
		MaxLeaseHold:     20 * time.Millisecond,
		MaxQMITransports: 2,
		RecoveryTimeout:  time.Second,
		RecoverTransport: func(ctx context.Context, req Request) error {
			close(recoveryStarted)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-allowRecovery:
				return nil
			}
		},
	})
	first, err := arb.AcquireTransport(context.Background(), Request{
		Owner:   "operation-a",
		Mode:    "QMI",
		Class:   APDUClassEUICCWrite,
		Channel: 1,
		Scope:   TransportScopeQMIChannel,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(operation-a) error=%v", err)
	}
	defer first.Release()

	select {
	case <-recoveryStarted:
	case <-time.After(time.Second):
		t.Fatal("recovery callback did not start")
	}
	secondDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		second, acquireErr := arb.AcquireTransport(ctx, Request{
			Owner:   "operation-b",
			Mode:    "QMI",
			Class:   APDUClassEUICCWrite,
			Channel: 2,
			Scope:   TransportScopeQMIChannel,
		})
		if acquireErr == nil {
			second.Release()
		}
		secondDone <- acquireErr
	}()
	select {
	case acquireErr := <-secondDone:
		t.Fatalf("operation-b finished before recovery success: %v", acquireErr)
	case <-time.After(20 * time.Millisecond):
	}

	close(allowRecovery)
	select {
	case acquireErr := <-secondDone:
		if acquireErr != nil {
			t.Fatalf("operation-b after recovery success error=%v", acquireErr)
		}
	case <-time.After(time.Second):
		t.Fatal("operation-b did not acquire after recovery success")
	}
	if first.Active() {
		t.Fatal("operation-a lease remained active after recovery success")
	}
}

func TestTransportRecoveryWaitsForOwnerReleaseToFinishBeforeReopen(t *testing.T) {
	recoveryStarted := make(chan struct{})
	allowRecovery := make(chan struct{})
	arb := New("dev-1", Options{
		MaxLeaseHold:     20 * time.Millisecond,
		MaxQMITransports: 2,
		RecoveryTimeout:  time.Second,
		RecoverTransport: func(context.Context, Request) error {
			close(recoveryStarted)
			<-allowRecovery
			return nil
		},
	})
	first, err := arb.AcquireTransport(context.Background(), Request{
		Owner:   "operation-a",
		Mode:    "QMI",
		Class:   APDUClassEUICCWrite,
		Channel: 1,
		Scope:   TransportScopeQMIChannel,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(operation-a) error=%v", err)
	}
	defer first.Release()

	select {
	case <-recoveryStarted:
	case <-time.After(time.Second):
		t.Fatal("recovery callback did not start")
	}
	first.Release()

	secondDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		second, acquireErr := arb.AcquireTransport(ctx, Request{
			Owner:   "operation-b",
			Mode:    "QMI",
			Class:   APDUClassEUICCWrite,
			Channel: 2,
			Scope:   TransportScopeQMIChannel,
		})
		if acquireErr == nil {
			second.Release()
		}
		secondDone <- acquireErr
	}()
	select {
	case acquireErr := <-secondDone:
		t.Fatalf("operation-b acquired before recovery callback ended: %v", acquireErr)
	case <-time.After(20 * time.Millisecond):
	}

	close(allowRecovery)
	select {
	case acquireErr := <-secondDone:
		if acquireErr != nil {
			t.Fatalf("operation-b after recovery completion error=%v", acquireErr)
		}
	case <-time.After(time.Second):
		t.Fatal("operation-b did not acquire after recovery callback completed")
	}
}

func TestTransportWatchdogRecoveryFailureRemainsSuspect(t *testing.T) {
	recoveryCalled := make(chan struct{})
	arb := New("dev-1", Options{
		MaxLeaseHold:    20 * time.Millisecond,
		RecoveryTimeout: time.Second,
		RecoverTransport: func(context.Context, Request) error {
			close(recoveryCalled)
			return errors.New("synthetic reset failure")
		},
	})
	first, err := arb.AcquireTransport(context.Background(), Request{
		Owner: "operation-a",
		Mode:  "QMI",
		Class: APDUClassEUICCWrite,
	})
	if err != nil {
		t.Fatalf("AcquireTransport(operation-a) error=%v", err)
	}
	defer first.Release()

	select {
	case <-recoveryCalled:
	case <-time.After(time.Second):
		t.Fatal("recovery callback was not called")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	second, err := arb.AcquireTransport(ctx, Request{
		Owner: "operation-b",
		Mode:  "QMI",
		Class: APDUClassEUICCWrite,
	})
	if err == nil {
		second.Release()
		t.Fatal("operation-b acquired after failed recovery")
	}
	if !errors.Is(err, ErrAPDUBusy) {
		t.Fatalf("AcquireTransport(operation-b) error=%v, want ErrAPDUBusy", err)
	}
	if !first.Active() || arb.Stats().SuspectLeases != 1 {
		t.Fatalf("failed recovery did not retain suspect ownership: active=%v stats=%+v", first.Active(), arb.Stats())
	}
}

func TestBarrierOwnerContextLossRemainsActiveAndSuspect(t *testing.T) {
	arb := New("dev-1", Options{})
	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	barrier, err := arb.BeginBarrier(ownerCtx, Request{
		Owner: "switch-owner",
		Mode:  "QMI",
		Class: APDUClassSwitchBarrier,
	}, BarrierPolicy{})
	if err != nil {
		t.Fatalf("BeginBarrier() error=%v", err)
	}
	defer barrier.Release()
	cancelOwner()

	deadline := time.Now().Add(time.Second)
	for {
		snapshot := arb.Snapshot()
		if len(snapshot.Active) == 1 && snapshot.Active[0].LeaseType == LeaseTypeBarrier && snapshot.Active[0].Suspect {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("owner context loss did not mark barrier suspect: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}

	waitCtx, cancelWait := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancelWait()
	lease, err := arb.AcquireTransport(waitCtx, Request{
		Owner: "vowifi-aka",
		Mode:  "QMI",
		Class: APDUClassUSIMAKA,
	})
	if err == nil {
		lease.Release()
		t.Fatal("USIMAKA acquired after barrier owner context loss")
	}
	if !errors.Is(err, ErrAPDUBusy) {
		t.Fatalf("AcquireTransport() error=%v, want ErrAPDUBusy", err)
	}

	barrier.Release()
	finalCtx, cancelFinal := context.WithTimeout(context.Background(), time.Second)
	defer cancelFinal()
	lease, err = arb.AcquireTransport(finalCtx, Request{
		Owner: "vowifi-aka",
		Mode:  "QMI",
		Class: APDUClassUSIMAKA,
	})
	if err != nil {
		t.Fatalf("AcquireTransport() after barrier owner release error=%v", err)
	}
	lease.Release()
}

func TestShouldLogEvent(t *testing.T) {
	tests := []struct {
		name     string
		phase    string
		queueLen int
		waitMs   int64
		holdMs   int64
		want     bool
	}{
		{name: "suppress zero wait acquire", phase: "acquire", queueLen: 0, waitMs: 0, holdMs: 0, want: false},
		{name: "suppress short release", phase: "release", queueLen: 0, waitMs: 0, holdMs: 27, want: false},
		{name: "log waited event", phase: "acquire", queueLen: 0, waitMs: 1, holdMs: 0, want: true},
		{name: "suppress ordinary qmi release", phase: "release", queueLen: 0, waitMs: 0, holdMs: 95, want: false},
		{name: "log long hold release", phase: "release", queueLen: 0, waitMs: 0, holdMs: 500, want: true},
		{name: "log deeper queue", phase: "wait", queueLen: 2, waitMs: 0, holdMs: 0, want: true},
		{name: "always log timeout", phase: "timeout", queueLen: 0, waitMs: 0, holdMs: 0, want: true},
		{name: "always log force release", phase: "force-release", queueLen: 0, waitMs: 0, holdMs: 0, want: true},
		{name: "boundary suppress single queued wait", phase: "wait", queueLen: 1, waitMs: 0, holdMs: 0, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldLogEvent(tt.phase, tt.queueLen, tt.waitMs, tt.holdMs)
			if got != tt.want {
				t.Fatalf("shouldLogEvent(%q, %d, %d, %d) = %v, want %v", tt.phase, tt.queueLen, tt.waitMs, tt.holdMs, got, tt.want)
			}
		})
	}
}

func TestSIMAuthReadyGateCoalescesConcurrentProbes(t *testing.T) {
	arb := New("dev-1", Options{})
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	errs := make(chan error, 2)
	var probes atomic.Int32

	probe := func(ctx context.Context) error {
		probes.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	}

	for i := 0; i < 2; i++ {
		go func() {
			errs <- arb.WaitSIMAuthReady(context.Background(), probe)
		}()
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("SIMAuth probe did not start")
	}
	time.Sleep(20 * time.Millisecond)
	close(release)

	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("WaitSIMAuthReady() error=%v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("WaitSIMAuthReady() did not return")
		}
	}
	if got := probes.Load(); got != 1 {
		t.Fatalf("probe count=%d want 1", got)
	}

	if err := arb.WaitSIMAuthReady(context.Background(), func(context.Context) error {
		probes.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("cached WaitSIMAuthReady() error=%v", err)
	}
	if got := probes.Load(); got != 1 {
		t.Fatalf("probe count after cached wait=%d want 1", got)
	}
}

func TestSIMAuthReadyGateInvalidationForcesNewProbe(t *testing.T) {
	arb := New("dev-1", Options{})
	var probes atomic.Int32
	probe := func(context.Context) error {
		probes.Add(1)
		return nil
	}

	if err := arb.WaitSIMAuthReady(context.Background(), probe); err != nil {
		t.Fatalf("first WaitSIMAuthReady() error=%v", err)
	}
	if err := arb.WaitSIMAuthReady(context.Background(), probe); err != nil {
		t.Fatalf("cached WaitSIMAuthReady() error=%v", err)
	}
	if got := probes.Load(); got != 1 {
		t.Fatalf("probe count before invalidate=%d want 1", got)
	}

	arb.InvalidateSIMAuthReady("switch")
	if err := arb.WaitSIMAuthReady(context.Background(), probe); err != nil {
		t.Fatalf("post-invalidate WaitSIMAuthReady() error=%v", err)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("probe count after invalidate=%d want 2", got)
	}
}
