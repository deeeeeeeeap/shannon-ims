package vowifihost

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost"
	"github.com/1239t/vowifi-go/runtimehost/carrier"
)

type manualDesiredRecoverClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*manualDesiredRecoverTimer
	created chan struct{}
	stopped chan struct{}
}

type manualDesiredRecoverTimer struct {
	clock   *manualDesiredRecoverClock
	when    time.Time
	c       chan time.Time
	stopped bool
	fired   bool
}

func newManualDesiredRecoverClock(now time.Time) *manualDesiredRecoverClock {
	return &manualDesiredRecoverClock{
		now:     now,
		created: make(chan struct{}, 16),
		stopped: make(chan struct{}, 16),
	}
}

func (c *manualDesiredRecoverClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualDesiredRecoverClock) NewTimer(delay time.Duration) desiredRecoverTimer {
	c.mu.Lock()
	timer := &manualDesiredRecoverTimer{
		clock: c,
		when:  c.now.Add(delay),
		c:     make(chan time.Time, 1),
	}
	c.timers = append(c.timers, timer)
	c.mu.Unlock()
	c.created <- struct{}{}
	return timer
}

func (c *manualDesiredRecoverClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	now := c.now
	due := make([]*manualDesiredRecoverTimer, 0, len(c.timers))
	for _, timer := range c.timers {
		if timer == nil || timer.stopped || timer.fired || timer.when.After(now) {
			continue
		}
		timer.fired = true
		due = append(due, timer)
	}
	c.mu.Unlock()
	for _, timer := range due {
		timer.c <- now
	}
}

func (c *manualDesiredRecoverClock) ActiveTimerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for _, timer := range c.timers {
		if timer != nil && !timer.stopped && !timer.fired {
			count++
		}
	}
	return count
}

func (t *manualDesiredRecoverTimer) C() <-chan time.Time {
	return t.c
}

func (t *manualDesiredRecoverTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.stopped || t.fired {
		return false
	}
	t.stopped = true
	t.clock.stopped <- struct{}{}
	return true
}

func waitForDesiredRecoverIdle(t *testing.T, manager *Manager, deviceID string) DesiredRecoverSnapshot {
	t.Helper()
	for range 100000 {
		state, ok := manager.DesiredRecoverState(deviceID)
		if ok && !state.InFlight {
			return state
		}
		runtime.Gosched()
	}
	state, _ := manager.DesiredRecoverState(deviceID)
	t.Fatalf("desired recover did not become idle: %+v", state)
	return DesiredRecoverSnapshot{}
}

func waitForNoDesiredRecoverState(t *testing.T, manager *Manager, deviceID string) {
	t.Helper()
	for range 100000 {
		if !manager.HasDesiredRecoverState(deviceID) {
			return
		}
		runtime.Gosched()
	}
	state, _ := manager.DesiredRecoverState(deviceID)
	t.Fatalf("desired recover state remained visible: %+v", state)
}

func waitForDesiredRecoverInFlight(t *testing.T, manager *Manager, deviceID string) {
	t.Helper()
	for range 100000 {
		state, ok := manager.DesiredRecoverState(deviceID)
		if ok && state.InFlight {
			return
		}
		runtime.Gosched()
	}
	state, _ := manager.DesiredRecoverState(deviceID)
	t.Fatalf("desired recover did not enter in-flight state: %+v", state)
}

func assertNoDesiredRecoverAttempt(t *testing.T, attempts <-chan int) {
	t.Helper()
	select {
	case attempt := <-attempts:
		t.Fatalf("unexpected desired recover attempt %d", attempt)
	default:
	}
}

func TestAPDUBusyRecoverUsesThreeShortOpportunitiesBeforeGenericBackoff(t *testing.T) {
	manager := NewManager()
	clock := newManualDesiredRecoverClock(time.Unix(1700000000, 0))
	manager.recoverClock = clock
	attempts := make(chan int, 3)
	results := make(chan error, 3)
	attemptNumber := 0
	manager.SetLifecycleRunForTest(func(ctx context.Context, _ LifecycleCommand) error {
		attemptNumber++
		attempts <- attemptNumber
		select {
		case err := <-results:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	defer manager.ForgetDesiredRecover("dev-apdu-short")

	if !manager.ScheduleAPDUBusyRecover(context.Background(), APDUBusyRecoverRequest{DeviceID: "dev-apdu-short"}) {
		t.Fatal("ScheduleAPDUBusyRecover() = false, want true")
	}
	<-clock.created
	assertNoDesiredRecoverAttempt(t, attempts)

	clock.Advance(2 * time.Second)
	assertNoDesiredRecoverAttempt(t, attempts)
	clock.Advance(time.Second)
	if got := <-attempts; got != 1 {
		t.Fatalf("first attempt = %d, want 1", got)
	}
	results <- context.DeadlineExceeded
	state := waitForDesiredRecoverIdle(t, manager, "dev-apdu-short")
	if state.Attempt != 0 || state.Delay != 2*time.Second || !state.NextAt.Equal(clock.Now().Add(2*time.Second)) {
		t.Fatalf("state after first short failure = %+v, want second opportunity at absolute 5s", state)
	}

	<-clock.created
	clock.Advance(2 * time.Second)
	if got := <-attempts; got != 2 {
		t.Fatalf("second attempt = %d, want 2", got)
	}
	results <- errors.New("synthetic APDU busy retry failure")
	state = waitForDesiredRecoverIdle(t, manager, "dev-apdu-short")
	if state.Attempt != 0 || state.Delay != 5*time.Second || !state.NextAt.Equal(clock.Now().Add(5*time.Second)) {
		t.Fatalf("state after second short failure = %+v, want third opportunity at absolute 10s", state)
	}

	<-clock.created
	clock.Advance(5 * time.Second)
	if got := <-attempts; got != 3 {
		t.Fatalf("third attempt = %d, want 3", got)
	}
	results <- errors.New("synthetic APDU busy retry failure")
	state = waitForDesiredRecoverIdle(t, manager, "dev-apdu-short")
	if state.Attempt != 1 || state.Delay != 30*time.Second || !state.NextAt.Equal(clock.Now().Add(30*time.Second)) {
		t.Fatalf("state after third short failure = %+v, want first generic 30s backoff", state)
	}
	assertNoDesiredRecoverAttempt(t, attempts)
}

func TestAPDUBusyRecoverSuccessfulClaimCancelsPendingSchedule(t *testing.T) {
	manager := NewManager()
	clock := newManualDesiredRecoverClock(time.Unix(1700000000, 0))
	manager.recoverClock = clock
	deviceID := "dev-apdu-success"
	claim := manager.BeginStart(deviceID)
	if !claim.Accepted {
		t.Fatalf("BeginStart() = %+v, want accepted", claim)
	}
	defer manager.ForgetDesiredRecover(deviceID)

	if !manager.ScheduleAPDUBusyRecover(context.Background(), APDUBusyRecoverRequest{DeviceID: deviceID}) {
		t.Fatal("ScheduleAPDUBusyRecover() = false, want true")
	}
	<-clock.created
	if !manager.ClaimStarted(deviceID, claim.Epoch, &runtimehost.Instance{}) {
		t.Fatal("ClaimStarted() = false, want true")
	}
	<-clock.stopped
	if got := clock.ActiveTimerCount(); got != 0 {
		t.Fatalf("active retry timers after successful claim = %d, want 0", got)
	}
	if manager.HasDesiredRecoverState(deviceID) {
		t.Fatal("successful claim retained APDU busy recover state")
	}
}

func TestAPDUBusyRecoverDuplicateSharesOneSchedule(t *testing.T) {
	manager := NewManager()
	clock := newManualDesiredRecoverClock(time.Unix(1700000000, 0))
	manager.recoverClock = clock
	deviceID := "dev-apdu-dedupe"

	if !manager.ScheduleAPDUBusyRecover(context.Background(), APDUBusyRecoverRequest{DeviceID: deviceID}) {
		t.Fatal("first ScheduleAPDUBusyRecover() = false, want true")
	}
	<-clock.created
	if manager.ScheduleAPDUBusyRecover(context.Background(), APDUBusyRecoverRequest{DeviceID: deviceID}) {
		t.Fatal("duplicate ScheduleAPDUBusyRecover() = true, want false")
	}
	if got := clock.ActiveTimerCount(); got != 1 {
		t.Fatalf("active retry timers after duplicate = %d, want 1", got)
	}
	manager.ForgetDesiredRecover(deviceID)
	if got := clock.ActiveTimerCount(); got != 0 {
		t.Fatalf("active retry timers after forget = %d, want 0", got)
	}
}

func TestAPDUBusyRecoverTerminalResultStopsRemainingOpportunities(t *testing.T) {
	tests := []struct {
		name   string
		result error
	}{
		{name: "success"},
		{name: "policy_blocked", result: carrier.NewVoWiFiBlockedMCCError("001")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager()
			clock := newManualDesiredRecoverClock(time.Unix(1700000000, 0))
			manager.recoverClock = clock
			deviceID := "dev-apdu-terminal-" + tt.name
			attempts := make(chan struct{}, 2)
			manager.SetLifecycleRunForTest(func(context.Context, LifecycleCommand) error {
				attempts <- struct{}{}
				return tt.result
			})

			if !manager.ScheduleAPDUBusyRecover(context.Background(), APDUBusyRecoverRequest{DeviceID: deviceID}) {
				t.Fatal("ScheduleAPDUBusyRecover() = false, want true")
			}
			<-clock.created
			clock.Advance(3 * time.Second)
			<-attempts
			waitForNoDesiredRecoverState(t, manager, deviceID)
			if got := clock.ActiveTimerCount(); got != 0 {
				t.Fatalf("active retry timers after terminal result = %d, want 0", got)
			}
			select {
			case <-clock.created:
				t.Fatal("terminal result created another retry timer")
			default:
			}
			clock.Advance(10 * time.Second)
			select {
			case <-attempts:
				t.Fatal("terminal result allowed another recover attempt")
			default:
			}
		})
	}
}

func TestAPDUBusyRecoverSwitchCancelsAndJoinsPendingSchedule(t *testing.T) {
	manager := NewManager()
	clock := newManualDesiredRecoverClock(time.Unix(1700000000, 0))
	manager.recoverClock = clock
	deviceID := "dev-apdu-switch"
	manager.SetLifecycleRunForTest(func(_ context.Context, cmd LifecycleCommand) error {
		if cmd.Kind != LifecycleCommandSwitchBegin {
			t.Fatalf("lifecycle command kind = %s, want switch_begin", cmd.Kind.String())
		}
		return nil
	})
	defer manager.ForgetDesiredRecover(deviceID)

	if !manager.ScheduleAPDUBusyRecover(context.Background(), APDUBusyRecoverRequest{DeviceID: deviceID}) {
		t.Fatal("ScheduleAPDUBusyRecover() = false, want true")
	}
	<-clock.created
	if err := manager.SwitchBegin(context.Background(), deviceID); err != nil {
		t.Fatalf("SwitchBegin() error = %v", err)
	}
	if got := clock.ActiveTimerCount(); got != 0 {
		t.Fatalf("active retry timers after SwitchBegin = %d, want 0", got)
	}
	if manager.HasDesiredRecoverState(deviceID) {
		t.Fatal("SwitchBegin retained APDU busy recover state")
	}
}

func TestAPDUBusyRecoverTeardownCancelsAndJoinsPendingSchedule(t *testing.T) {
	manager := NewManager()
	clock := newManualDesiredRecoverClock(time.Unix(1700000000, 0))
	manager.recoverClock = clock
	deviceID := "dev-apdu-teardown"
	defer manager.ForgetDesiredRecover(deviceID)

	if !manager.ScheduleAPDUBusyRecover(context.Background(), APDUBusyRecoverRequest{DeviceID: deviceID}) {
		t.Fatal("ScheduleAPDUBusyRecover() = false, want true")
	}
	<-clock.created
	if manager.TeardownSession(context.Background(), deviceID, TeardownOptions{Reason: "test"}) {
		t.Fatal("TeardownSession() = true without an instance, want false")
	}
	if got := clock.ActiveTimerCount(); got != 0 {
		t.Fatalf("active retry timers after teardown = %d, want 0", got)
	}
	if manager.HasDesiredRecoverState(deviceID) {
		t.Fatal("teardown retained APDU busy recover state")
	}
}

func TestForgetAPDUBusyRecoverCancelsAndJoinsInFlightAttempt(t *testing.T) {
	manager := NewManager()
	clock := newManualDesiredRecoverClock(time.Unix(1700000000, 0))
	manager.recoverClock = clock
	deviceID := "dev-apdu-inflight-cancel"
	started := make(chan struct{})
	exited := make(chan struct{})
	manager.SetLifecycleRunForTest(func(ctx context.Context, _ LifecycleCommand) error {
		close(started)
		<-ctx.Done()
		close(exited)
		return ctx.Err()
	})

	if !manager.ScheduleAPDUBusyRecover(context.Background(), APDUBusyRecoverRequest{DeviceID: deviceID}) {
		t.Fatal("ScheduleAPDUBusyRecover() = false, want true")
	}
	<-clock.created
	clock.Advance(3 * time.Second)
	<-started
	manager.ForgetDesiredRecover(deviceID)
	select {
	case <-exited:
	default:
		t.Fatal("ForgetDesiredRecover returned before the in-flight attempt exited")
	}
	if manager.HasDesiredRecoverState(deviceID) {
		t.Fatal("forgotten in-flight APDU busy recover state remained visible")
	}
}

func TestForgottenQueuedAPDUBusyRecoverCannotEnterPhysicalRun(t *testing.T) {
	manager := NewManager()
	clock := newManualDesiredRecoverClock(time.Unix(1700000000, 0))
	manager.recoverClock = clock
	deviceID := "dev-apdu-queued-stale"
	enableStarted := make(chan struct{})
	releaseEnable := make(chan struct{})
	enableDone := make(chan error, 1)
	recoverRan := make(chan struct{}, 1)
	manager.SetLifecycleRunForTest(func(_ context.Context, cmd LifecycleCommand) error {
		switch cmd.Kind {
		case LifecycleCommandEnable:
			close(enableStarted)
			<-releaseEnable
		case LifecycleCommandRecover:
			recoverRan <- struct{}{}
		}
		return nil
	})
	go func() {
		enableDone <- manager.Enable(context.Background(), deviceID)
	}()
	<-enableStarted

	if !manager.ScheduleAPDUBusyRecover(context.Background(), APDUBusyRecoverRequest{DeviceID: deviceID}) {
		t.Fatal("ScheduleAPDUBusyRecover() = false, want true")
	}
	<-clock.created
	clock.Advance(3 * time.Second)
	waitForDesiredRecoverInFlight(t, manager, deviceID)
	forgetDone := make(chan struct{})
	go func() {
		manager.ForgetDesiredRecover(deviceID)
		close(forgetDone)
	}()
	waitForNoDesiredRecoverState(t, manager, deviceID)
	select {
	case <-forgetDone:
		t.Fatal("ForgetDesiredRecover returned before the queued schedule joined")
	default:
	}
	close(releaseEnable)
	if err := <-enableDone; err != nil {
		t.Fatalf("Enable() error = %v", err)
	}
	<-forgetDone
	select {
	case <-recoverRan:
		t.Fatal("forgotten queued APDU busy recover entered physical lifecycle run")
	default:
	}
}
