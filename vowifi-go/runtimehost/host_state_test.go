package runtimehost

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/internal/vowifi/runtimecore"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

type lifecycleMessagingService struct {
	sendCalls        atomic.Int32
	closeCalls       atomic.Int32
	sending          atomic.Bool
	closed           atomic.Bool
	closedWhileSend  atomic.Bool
	closeCtxCanceled atomic.Bool
	closeCtxDeadline atomic.Bool
	sendStarted      chan struct{}
	releaseSend      chan struct{}
}

func (s *lifecycleMessagingService) SendSMS(context.Context, string, string, []messaging.SMSPart) (messaging.SendOutcome, error) {
	s.sendCalls.Add(1)
	s.sending.Store(true)
	defer s.sending.Store(false)
	if s.sendStarted != nil {
		close(s.sendStarted)
	}
	if s.releaseSend != nil {
		<-s.releaseSend
	}
	return messaging.SendOutcome{MessageID: "synthetic"}, nil
}
func (s *lifecycleMessagingService) SendUSSD(context.Context, string) (*messaging.USSDResult, error) {
	return nil, errors.New("synthetic unsupported")
}
func (s *lifecycleMessagingService) ContinueUSSD(context.Context, string, string) (*messaging.USSDResult, error) {
	return nil, errors.New("synthetic unsupported")
}
func (s *lifecycleMessagingService) CancelUSSD(context.Context, string) error {
	return errors.New("synthetic unsupported")
}
func (s *lifecycleMessagingService) Close(ctx context.Context) error {
	s.closeCalls.Add(1)
	s.closed.Store(true)
	if ctx == nil || ctx.Err() != nil {
		s.closeCtxCanceled.Store(true)
	}
	if ctx != nil {
		_, hasDeadline := ctx.Deadline()
		s.closeCtxDeadline.Store(hasDeadline)
	}
	if s.sending.Load() {
		s.closedWhileSend.Store(true)
	}
	return nil
}

func TestInstanceStopWaitsForInFlightIMSStatus(t *testing.T) {
	service := &lifecycleMessagingService{}
	statusStarted := make(chan struct{})
	releaseStatus := make(chan struct{})
	var statusObservedClosed atomic.Bool
	instance := &Instance{
		svc: service,
		session: &runtimecore.SessionResult{IMSStatus: func() map[string]interface{} {
			close(statusStarted)
			<-releaseStatus
			statusObservedClosed.Store(service.closed.Load())
			return map[string]interface{}{"synthetic": true}
		}},
	}
	obsDone := make(chan struct{})
	go func() {
		_ = instance.Obs()
		close(obsDone)
	}()
	select {
	case <-statusStarted:
	case <-time.After(time.Second):
		t.Fatal("Obs() did not enter IMSStatus")
	}

	stopDone := make(chan error, 1)
	go func() {
		stopDone <- instance.Stop(context.Background())
	}()
	returnedEarly := false
	select {
	case <-stopDone:
		returnedEarly = true
	case <-time.After(20 * time.Millisecond):
	}
	closedEarly := service.closeCalls.Load() != 0

	close(releaseStatus)
	select {
	case <-obsDone:
	case <-time.After(time.Second):
		t.Fatal("Obs() did not return")
	}
	if !returnedEarly {
		select {
		case err := <-stopDone:
			if err != nil {
				t.Fatalf("Stop() error=%v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Stop() did not return after IMSStatus completed")
		}
	}
	if returnedEarly || closedEarly || statusObservedClosed.Load() {
		t.Fatalf("IMS service lifecycle invalid: stop_returned_early=%v closed_early=%v status_observed_closed=%v", returnedEarly, closedEarly, statusObservedClosed.Load())
	}
}

func TestInstanceSendSMSRejectsAfterStop(t *testing.T) {
	service := &lifecycleMessagingService{}
	instance := &Instance{svc: service}
	if err := instance.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error=%v", err)
	}

	if _, err := instance.SendSMS(context.Background(), "sip:safe.invalid", "synthetic", nil); err == nil {
		t.Fatal("SendSMS() error=nil after Stop(), want stopped rejection")
	}
	if got := service.sendCalls.Load(); got != 0 {
		t.Fatalf("fake SendSMS calls=%d after Stop(), want 0", got)
	}
}

func TestInstanceStopWaitsForInFlightSendSMS(t *testing.T) {
	service := &lifecycleMessagingService{
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}
	instance := &Instance{svc: service}
	sendDone := make(chan error, 1)
	go func() {
		_, err := instance.SendSMS(context.Background(), "sip:safe.invalid", "synthetic", nil)
		sendDone <- err
	}()
	select {
	case <-service.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("SendSMS() did not start")
	}

	stopDone := make(chan error, 1)
	go func() {
		stopDone <- instance.Stop(context.Background())
	}()
	select {
	case err := <-stopDone:
		t.Fatalf("Stop() returned while SendSMS was in flight: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if service.closeCalls.Load() != 0 || service.closedWhileSend.Load() {
		t.Fatalf("service closed during SendSMS: close_calls=%d closed_while_send=%v", service.closeCalls.Load(), service.closedWhileSend.Load())
	}

	close(service.releaseSend)
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("SendSMS() error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SendSMS() did not finish")
	}
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop() error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop() did not finish after SendSMS")
	}
	if service.closeCalls.Load() != 1 || service.closedWhileSend.Load() {
		t.Fatalf("service close lifecycle invalid: close_calls=%d closed_while_send=%v", service.closeCalls.Load(), service.closedWhileSend.Load())
	}
}

func TestInstanceStopHonorsCanceledContextWhileSendSMSIsBlocked(t *testing.T) {
	service := &lifecycleMessagingService{
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}
	instance := &Instance{svc: service}
	sendDone := make(chan error, 1)
	go func() {
		_, err := instance.SendSMS(context.Background(), "sip:safe.invalid", "synthetic", nil)
		sendDone <- err
	}()
	select {
	case <-service.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("SendSMS() did not start")
	}

	stopCtx, cancelStop := context.WithCancel(context.Background())
	cancelStop()
	stopDone := make(chan error, 1)
	go func() {
		stopDone <- instance.Stop(stopCtx)
	}()
	var stopErr error
	select {
	case stopErr = <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop() ignored canceled context while SendSMS was blocked")
	}
	if !errors.Is(stopErr, context.Canceled) {
		t.Fatalf("Stop() error=%v, want context.Canceled", stopErr)
	}
	if got := service.closeCalls.Load(); got != 0 {
		t.Fatalf("service Close calls while SendSMS remained active=%d, want 0", got)
	}
	if service.closedWhileSend.Load() {
		t.Fatal("service was closed while canceled Stop still had an active SendSMS user")
	}

	cleanupDone := make(chan error, 1)
	go func() {
		cleanupDone <- instance.Stop(context.Background())
	}()
	select {
	case err := <-cleanupDone:
		t.Fatalf("repeated Stop() returned before active service user completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(service.releaseSend)
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("SendSMS() error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SendSMS() did not finish")
	}
	select {
	case err := <-cleanupDone:
		if err != nil {
			t.Fatalf("repeated Stop() cleanup error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("repeated Stop() did not join deferred cleanup")
	}
	if got := service.closeCalls.Load(); got != 1 {
		t.Fatalf("service Close calls after deferred cleanup=%d, want exactly 1", got)
	}
	if service.closedWhileSend.Load() {
		t.Fatal("deferred cleanup closed service before SendSMS finished")
	}
}

func TestInstanceStopCleanupUsesIndependentBoundedContext(t *testing.T) {
	service := &lifecycleMessagingService{
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}
	instance := &Instance{svc: service}
	sendDone := make(chan error, 1)
	go func() {
		_, err := instance.SendSMS(context.Background(), "sip:safe.invalid", "synthetic", nil)
		sendDone <- err
	}()
	select {
	case <-service.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("SendSMS() did not start")
	}

	stopCtx, cancelStop := context.WithCancel(context.Background())
	cancelStop()
	if err := instance.Stop(stopCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop() error=%v, want context.Canceled", err)
	}
	close(service.releaseSend)
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("SendSMS() error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SendSMS() did not finish")
	}
	if err := instance.Stop(context.Background()); err != nil {
		t.Fatalf("repeated Stop() cleanup error=%v", err)
	}
	if service.closeCtxCanceled.Load() {
		t.Fatal("service Close received nil or canceled caller context")
	}
	if !service.closeCtxDeadline.Load() {
		t.Fatal("service Close context had no cleanup deadline")
	}
}

func TestInstanceStopTreatsNilContextAsBackground(t *testing.T) {
	service := &lifecycleMessagingService{}
	instance := &Instance{svc: service}
	stopWithoutPanic := func() (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("Stop(nil) panicked: %v", recovered)
			}
		}()
		return instance.Stop(nil)
	}

	if err := stopWithoutPanic(); err != nil {
		t.Fatalf("Stop(nil) error=%v", err)
	}
	if err := stopWithoutPanic(); err != nil {
		t.Fatalf("repeated Stop(nil) error=%v", err)
	}
	if got := service.closeCalls.Load(); got != 1 {
		t.Fatalf("service Close calls after repeated Stop(nil)=%d, want exactly 1", got)
	}
}

func TestInstanceRejectsStalePipelineServiceAfterStop(t *testing.T) {
	instance := &Instance{lifecycleGeneration: 1}
	if err := instance.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error=%v", err)
	}
	staleService := &lifecycleMessagingService{}
	if instance.installService(context.Background(), 1, staleService, nil, "", "") {
		t.Fatal("installService() accepted stale generation after Stop()")
	}
	if got := staleService.closeCalls.Load(); got != 1 {
		t.Fatalf("stale service close calls=%d, want 1", got)
	}
	if instance.Service() != nil {
		t.Fatal("Service() retained stale pipeline service")
	}
}

func TestInstanceObsConcurrentSessionSwapIsRaceFree(t *testing.T) {
	instance := &Instance{}
	stopReads := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stopReads:
				return
			default:
				_ = instance.Obs()
			}
		}
	}()

	for i := 0; i < 1000; i++ {
		instance.mu.Lock()
		if i%2 == 0 {
			instance.session = &runtimecore.SessionResult{}
		} else {
			instance.session = nil
		}
		instance.mu.Unlock()
	}
	close(stopReads)
	select {
	case <-readerDone:
	case <-time.After(time.Second):
		t.Fatal("Obs() reader did not stop")
	}
}

func TestInstanceObsConcurrentSessionMutationIsRaceFree(t *testing.T) {
	instance := &Instance{session: &runtimecore.SessionResult{}}
	stopReads := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stopReads:
				return
			default:
				_ = instance.Obs()
			}
		}
	}()

	for i := 0; i < 1000; i++ {
		instance.mu.Lock()
		runtimecore.AttachIMSService(instance.session, nil, func() map[string]interface{} {
			return map[string]interface{}{"synthetic": true}
		}, "synthetic-local", "synthetic-pcscf")
		instance.mu.Unlock()
	}
	close(stopReads)
	select {
	case <-readerDone:
	case <-time.After(time.Second):
		t.Fatal("Obs() reader did not stop")
	}
}

func TestInstanceStopClearsSessionSnapshot(t *testing.T) {
	instance := &Instance{session: &runtimecore.SessionResult{}}
	if got := instance.Obs()["runtimecore"]; got != true {
		t.Fatalf("runtimecore before Stop() = %v, want true", got)
	}
	if err := instance.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error=%v", err)
	}
	if got := instance.Obs()["runtimecore"]; got != false {
		t.Fatalf("runtimecore after Stop() = %v, want false", got)
	}
}

func TestInstanceStopClearsSessionBeforePipelineExit(t *testing.T) {
	pipelineDone := make(chan struct{})
	instance := &Instance{
		session:   &runtimecore.SessionResult{},
		watchDone: pipelineDone,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := instance.Stop(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop() error=%v, want context.Canceled", err)
	}
	if got := instance.Obs()["runtimecore"]; got != false {
		t.Fatalf("runtimecore after canceled Stop() = %v, want false before pipeline exit", got)
	}
	close(pipelineDone)
}

func TestStalePipelineCannotUpdateStateOrNotifyAfterStop(t *testing.T) {
	shouldRunEntered := make(chan struct{})
	releaseShouldRun := make(chan struct{})
	instance := &Instance{
		lifecycleGeneration: 1,
		watchDone:           make(chan struct{}),
		state:               State{LastReason: "before-stop"},
		shouldRun: func() bool {
			close(shouldRunEntered)
			<-releaseShouldRun
			return false
		},
	}
	var notifications atomic.Int32
	instance.AddObserver(ObserverFunc(func(context.Context, Event) {
		notifications.Add(1)
	}))

	go instance.runStagedPipeline(context.Background(), StartRequest{}, 1)
	select {
	case <-shouldRunEntered:
	case <-time.After(time.Second):
		t.Fatal("pipeline did not reach controlled shouldRun check")
	}
	stopCtx, cancelStop := context.WithCancel(context.Background())
	cancelStop()
	if err := instance.Stop(stopCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop() error=%v, want context.Canceled", err)
	}
	close(releaseShouldRun)
	select {
	case <-instance.watchDone:
	case <-time.After(time.Second):
		t.Fatal("stale pipeline did not exit")
	}

	if got := instance.State().LastReason; got != "before-stop" {
		t.Fatalf("state changed by stale pipeline after Stop(): LastReason=%q", got)
	}
	if got := notifications.Load(); got != 0 {
		t.Fatalf("stale pipeline observer notifications=%d, want 0", got)
	}
}
