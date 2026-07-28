//go:build linux

package runtimehost

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	externalswu "github.com/1239t/swu-go/pkg/swu"
	swusim "github.com/1239t/vowifi-go/engine/sim"
)

type inertSWuSIM struct{}

func (inertSWuSIM) GetIMSI() (string, error) { return "synthetic-imsi", nil }
func (inertSWuSIM) CalculateAKA([]byte, []byte) (swusim.AKAResult, error) {
	return swusim.AKAResult{}, nil
}

type lateReadySWuSession struct {
	cfg     *externalswu.Config
	started chan struct{}
	exited  chan struct{}
	inner   chan []byte
}

func (s *lateReadySWuSession) Connect(ctx context.Context) error {
	close(s.started)
	<-ctx.Done()
	s.cfg.OnReady()
	close(s.exited)
	return ctx.Err()
}
func (*lateReadySWuSession) Snapshot() externalswu.SessionSnapshot {
	return externalswu.SessionSnapshot{}
}
func (*lateReadySWuSession) UpdateAddresses(string, string) error { return nil }
func (*lateReadySWuSession) SendInnerPacket([]byte) error         { return nil }
func (s *lateReadySWuSession) InnerPackets() <-chan []byte        { return s.inner }
func (*lateReadySWuSession) Shutdown()                            {}
func (s *lateReadySWuSession) WaitDone()                          { <-s.exited }

type readySWuSession struct {
	cfg        *externalswu.Config
	started    chan struct{}
	exited     chan struct{}
	inner      chan []byte
	connectCtx context.Context
}

type stopJoinedSWuSession struct {
	cfg            *externalswu.Config
	shutdownCalled chan struct{}
	releaseConnect chan struct{}
	connectDone    chan struct{}
	done           chan struct{}
	inner          chan []byte
	mobikeCalls    atomic.Int32
	mobikeEntered  chan struct{}
	releaseMOBIKE  chan struct{}
	mobikeExited   chan struct{}
}

func (s *stopJoinedSWuSession) Connect(ctx context.Context) error {
	s.cfg.OnReady()
	<-ctx.Done()
	<-s.releaseConnect
	close(s.done)
	close(s.connectDone)
	return ctx.Err()
}

func (s *stopJoinedSWuSession) Shutdown() {
	select {
	case <-s.shutdownCalled:
	default:
		close(s.shutdownCalled)
	}
}

func (s *stopJoinedSWuSession) WaitDone() { <-s.done }

func (*stopJoinedSWuSession) Snapshot() externalswu.SessionSnapshot {
	return externalswu.SessionSnapshot{Established: true, IPv4: net.ParseIP("198.51.100.10")}
}
func (s *stopJoinedSWuSession) UpdateAddresses(string, string) error {
	s.mobikeCalls.Add(1)
	if s.mobikeEntered != nil {
		select {
		case <-s.mobikeEntered:
		default:
			close(s.mobikeEntered)
		}
	}
	if s.releaseMOBIKE != nil {
		<-s.releaseMOBIKE
	}
	if s.mobikeExited != nil {
		select {
		case <-s.mobikeExited:
		default:
			close(s.mobikeExited)
		}
	}
	return nil
}
func (*stopJoinedSWuSession) SendInnerPacket([]byte) error  { return nil }
func (s *stopJoinedSWuSession) InnerPackets() <-chan []byte { return s.inner }

func (s *readySWuSession) Connect(ctx context.Context) error {
	s.connectCtx = ctx
	close(s.started)
	s.cfg.OnReady()
	<-ctx.Done()
	close(s.exited)
	return ctx.Err()
}

func TestEstablishedSWuOutlivesPipelineContext(t *testing.T) {
	session := &readySWuSession{started: make(chan struct{}), exited: make(chan struct{}), inner: make(chan []byte)}
	instance := &Instance{lifecycleGeneration: 1}
	req := StartRequest{
		Profile: Profile{MCC: "001", MNC: "01"},
		SIM:     inertSWuSIM{},
		epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
		}},
		outboundIPDetector: func(net.IP, int) (net.IP, error) {
			return net.ParseIP("198.51.100.20"), nil
		},
		swuSessionFactory: func(cfg *externalswu.Config) swuSession {
			session.cfg = cfg
			return session
		},
	}
	pipelineCtx, finishPipeline := context.WithCancel(context.Background())
	lease, err := instance.establishSWu(pipelineCtx, req, "epdg.test.invalid", "500", 1)
	if err != nil {
		t.Fatalf("establishSWu() error = %v", err)
	}

	finishPipeline()
	if err := session.connectCtx.Err(); err != nil {
		t.Fatalf("established SWu session canceled with pipeline context: %v", err)
	}
	if err := lease.CancelAndJoin(); err != nil {
		t.Fatalf("lease.CancelAndJoin() error = %v", err)
	}
}

func TestCloneSWUSnapshotDeepCopiesNestedIPBytes(t *testing.T) {
	source := swuSnapshot{
		IPv4:    net.IP{192, 0, 2, 10},
		IPv6:    net.IP{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		PCSCFv4: []net.IP{{192, 0, 2, 20}, nil},
		PCSCFv6: []net.IP{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}},
	}
	cloned := cloneSWUSnapshot(source)

	source.IPv4[0] = 203
	source.IPv6[0] = 0x30
	source.PCSCFv4[0][0] = 203
	if cloned.IPv4[0] != 192 || cloned.IPv6[0] != 0x20 || cloned.PCSCFv4[0][0] != 192 {
		t.Fatal("cloneSWUSnapshot() retained source IP byte aliases")
	}

	cloned.PCSCFv6[0][0] = 0x30
	if source.PCSCFv6[0][0] != 0x20 {
		t.Fatal("cloneSWUSnapshot() retained reverse P-CSCF IP byte aliases")
	}
	if cloned.PCSCFv4[1] != nil {
		t.Fatal("cloneSWUSnapshot() changed a nil P-CSCF entry")
	}
}

func TestInstanceStopCancelsAndJoinsEstablishedSWuSession(t *testing.T) {
	session := &stopJoinedSWuSession{
		shutdownCalled: make(chan struct{}),
		releaseConnect: make(chan struct{}),
		connectDone:    make(chan struct{}),
		done:           make(chan struct{}),
		inner:          make(chan []byte),
	}
	watchDone := make(chan struct{})
	close(watchDone)
	instance := &Instance{lifecycleGeneration: 1, watchDone: watchDone}
	req := StartRequest{
		Profile: Profile{MCC: "001", MNC: "01"},
		SIM:     inertSWuSIM{},
		epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
		}},
		outboundIPDetector: func(net.IP, int) (net.IP, error) {
			return net.ParseIP("198.51.100.20"), nil
		},
		swuSessionFactory: func(cfg *externalswu.Config) swuSession {
			session.cfg = cfg
			return session
		},
	}
	if _, err := instance.establishSWu(context.Background(), req, "epdg.test.invalid", "500", 1); err != nil {
		t.Fatalf("establishSWu() error = %v", err)
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- instance.Stop(context.Background()) }()

	select {
	case err := <-stopDone:
		close(session.releaseConnect)
		<-session.connectDone
		t.Fatalf("Stop() returned before asking the established SWu session to shut down: %v", err)
	case <-session.shutdownCalled:
	}
	select {
	case err := <-stopDone:
		close(session.releaseConnect)
		<-session.connectDone
		t.Fatalf("Stop() returned before the established SWu Connect task exited: %v", err)
	default:
	}

	close(session.releaseConnect)
	if err := <-stopDone; err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	select {
	case <-session.connectDone:
	default:
		t.Fatal("Stop() returned before the established SWu Connect task joined")
	}
}

func TestInstanceStopReportsEstablishedSWuJoinTimeout(t *testing.T) {
	session := &stopJoinedSWuSession{
		shutdownCalled: make(chan struct{}),
		releaseConnect: make(chan struct{}),
		connectDone:    make(chan struct{}),
		done:           make(chan struct{}),
		inner:          make(chan []byte),
	}
	joinTimeout := make(chan time.Time, 1)
	watchDone := make(chan struct{})
	close(watchDone)
	instance := &Instance{lifecycleGeneration: 1, watchDone: watchDone}
	req := StartRequest{
		Profile: Profile{MCC: "001", MNC: "01"},
		SIM:     inertSWuSIM{},
		epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
		}},
		outboundIPDetector: func(net.IP, int) (net.IP, error) {
			return net.ParseIP("198.51.100.20"), nil
		},
		swuConnectJoinDeadline: joinTimeout,
		swuSessionFactory: func(cfg *externalswu.Config) swuSession {
			session.cfg = cfg
			return session
		},
	}
	if _, err := instance.establishSWu(context.Background(), req, "epdg.test.invalid", "500", 1); err != nil {
		t.Fatalf("establishSWu() error = %v", err)
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- instance.Stop(context.Background()) }()
	<-session.shutdownCalled
	joinTimeout <- time.Now()

	err := <-stopDone
	close(session.releaseConnect)
	<-session.connectDone
	if !errors.Is(err, errSWuConnectJoinTimeout) {
		t.Fatalf("Stop() error = %v, want errSWuConnectJoinTimeout", err)
	}
}

func TestStaleReadySWuLeaseCannotPublishOrBecomeDataplaneOwner(t *testing.T) {
	session := &stopJoinedSWuSession{
		shutdownCalled: make(chan struct{}),
		releaseConnect: make(chan struct{}),
		connectDone:    make(chan struct{}),
		done:           make(chan struct{}),
		inner:          make(chan []byte),
	}
	readyBeforeAdopt := make(chan struct{})
	releaseAdoption := make(chan struct{})
	watchDone := make(chan struct{})
	instance := &Instance{
		lifecycleGeneration: 1,
		watchDone:           watchDone,
		state:               State{LastReason: "before-stale-ready"},
	}
	var tunnelReadyPublications atomic.Int32
	instance.AddObserver(ObserverFunc(func(_ context.Context, event Event) {
		if event.State.TunnelReady {
			tunnelReadyPublications.Add(1)
		}
	}))
	req := StartRequest{
		Profile: Profile{MCC: "001", MNC: "01"},
		epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
		}},
		swuStarter: func(_ context.Context, _ StartRequest, candidate epdgCandidate, _ string) (*swuSessionLease, error) {
			lease := newSWUSessionLease(candidate.IP.String(), candidate, nil)
			session.cfg = &externalswu.Config{OnReady: lease.markReady}
			if err := lease.start(session); err != nil {
				return nil, err
			}
			<-lease.ready
			close(readyBeforeAdopt)
			<-releaseAdoption
			return lease, nil
		},
	}

	go instance.runStagedPipeline(context.Background(), req, 1)
	<-readyBeforeAdopt
	stopCtx, cancelStop := context.WithCancel(context.Background())
	cancelStop()
	if err := instance.Stop(stopCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop() error = %v, want context.Canceled", err)
	}
	close(releaseAdoption)
	<-session.shutdownCalled
	close(session.releaseConnect)
	<-session.connectDone
	<-watchDone
	if err := instance.Stop(context.Background()); err != nil {
		t.Fatalf("repeated Stop() error = %v", err)
	}

	if got := tunnelReadyPublications.Load(); got != 0 {
		t.Fatalf("stale ready lease TunnelReady publications = %d, want 0", got)
	}
	if state := instance.State(); state.TunnelReady {
		t.Fatal("stale ready lease changed TunnelReady state")
	}
	instance.mu.Lock()
	installed := instance.swuLease
	instance.mu.Unlock()
	if installed != nil {
		t.Fatal("stale ready lease became the Instance dataplane owner")
	}
}

func TestInstanceAdoptsOnlyOneSuccessfulSWuDataplaneOwner(t *testing.T) {
	newSession := func() *stopJoinedSWuSession {
		return &stopJoinedSWuSession{
			shutdownCalled: make(chan struct{}),
			releaseConnect: make(chan struct{}),
			connectDone:    make(chan struct{}),
			done:           make(chan struct{}),
			inner:          make(chan []byte),
		}
	}
	requestFor := func(session *stopJoinedSWuSession) StartRequest {
		return StartRequest{
			Profile: Profile{MCC: "001", MNC: "01"},
			SIM:     inertSWuSIM{},
			epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
				{IP: net.ParseIP("192.0.2.10")},
			}},
			outboundIPDetector: func(net.IP, int) (net.IP, error) {
				return net.ParseIP("198.51.100.20"), nil
			},
			swuSessionFactory: func(cfg *externalswu.Config) swuSession {
				session.cfg = cfg
				return session
			},
		}
	}

	watchDone := make(chan struct{})
	close(watchDone)
	instance := &Instance{lifecycleGeneration: 1, watchDone: watchDone}
	firstSession := newSession()
	firstLease, err := instance.establishSWu(context.Background(), requestFor(firstSession), "epdg.test.invalid", "500", 1)
	if err != nil {
		t.Fatalf("first establishSWu() error = %v", err)
	}

	secondSession := newSession()
	secondResult := make(chan error, 1)
	go func() {
		_, err := instance.establishSWu(context.Background(), requestFor(secondSession), "epdg.test.invalid", "500", 1)
		secondResult <- err
	}()
	<-secondSession.shutdownCalled

	instance.mu.Lock()
	installed := instance.swuLease
	instance.mu.Unlock()
	if installed != firstLease {
		t.Fatal("second successful candidate replaced the active SWu lease")
	}
	if err := instance.TriggerMOBIKE("", "198.51.100.30"); err != nil {
		t.Fatalf("TriggerMOBIKE() error = %v", err)
	}
	if got := firstSession.mobikeCalls.Load(); got != 1 {
		t.Fatalf("active session MOBIKE calls = %d, want 1", got)
	}
	if got := secondSession.mobikeCalls.Load(); got != 0 {
		t.Fatalf("rejected session MOBIKE calls = %d, want 0", got)
	}

	close(secondSession.releaseConnect)
	<-secondSession.connectDone
	if err := <-secondResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("second establishSWu() error = %v, want context.Canceled", err)
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- instance.Stop(context.Background()) }()
	<-firstSession.shutdownCalled
	close(firstSession.releaseConnect)
	<-firstSession.connectDone
	if err := <-stopDone; err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestInstanceStopSerializesWithInFlightMOBIKE(t *testing.T) {
	session := &stopJoinedSWuSession{
		shutdownCalled: make(chan struct{}),
		releaseConnect: make(chan struct{}),
		connectDone:    make(chan struct{}),
		done:           make(chan struct{}),
		inner:          make(chan []byte),
		mobikeEntered:  make(chan struct{}),
		releaseMOBIKE:  make(chan struct{}),
		mobikeExited:   make(chan struct{}),
	}
	watchDone := make(chan struct{})
	close(watchDone)
	instance := &Instance{lifecycleGeneration: 1, watchDone: watchDone}
	req := StartRequest{
		Profile: Profile{MCC: "001", MNC: "01"},
		SIM:     inertSWuSIM{},
		epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
		}},
		outboundIPDetector: func(net.IP, int) (net.IP, error) {
			return net.ParseIP("198.51.100.20"), nil
		},
		swuSessionFactory: func(cfg *externalswu.Config) swuSession {
			session.cfg = cfg
			return session
		},
	}
	if _, err := instance.establishSWu(context.Background(), req, "epdg.test.invalid", "500", 1); err != nil {
		t.Fatalf("establishSWu() error = %v", err)
	}

	mobikeDone := make(chan error, 1)
	go func() { mobikeDone <- instance.TriggerMOBIKE("", "198.51.100.30") }()
	<-session.mobikeEntered

	stopCtx, cancelStop := context.WithCancel(context.Background())
	cancelStop()
	if err := instance.Stop(stopCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop() error = %v, want context.Canceled", err)
	}
	if err := instance.TriggerMOBIKE("", "198.51.100.40"); err == nil {
		t.Fatal("TriggerMOBIKE() accepted a new operation after Stop began")
	}
	if got := session.mobikeCalls.Load(); got != 1 {
		t.Fatalf("MOBIKE calls after Stop = %d, want exactly 1 in-flight call", got)
	}

	select {
	case <-session.shutdownCalled:
		close(session.releaseMOBIKE)
		<-mobikeDone
		close(session.releaseConnect)
		<-session.connectDone
		_ = instance.Stop(context.Background())
		t.Fatal("SWu Shutdown ran concurrently with an in-flight MOBIKE operation")
	default:
	}

	close(session.releaseMOBIKE)
	if err := <-mobikeDone; err != nil {
		t.Fatalf("in-flight TriggerMOBIKE() error = %v", err)
	}
	<-session.mobikeExited
	<-session.shutdownCalled
	close(session.releaseConnect)
	<-session.connectDone
	if err := instance.Stop(context.Background()); err != nil {
		t.Fatalf("repeated Stop() cleanup error = %v", err)
	}
}

func TestInstanceStopMOBIKEJoinTimeoutIsBoundedAndFailClosed(t *testing.T) {
	session := &stopJoinedSWuSession{
		shutdownCalled: make(chan struct{}),
		releaseConnect: make(chan struct{}),
		connectDone:    make(chan struct{}),
		done:           make(chan struct{}),
		inner:          make(chan []byte),
		mobikeEntered:  make(chan struct{}),
		releaseMOBIKE:  make(chan struct{}),
		mobikeExited:   make(chan struct{}),
	}
	joinTimeout := make(chan time.Time, 1)
	watchDone := make(chan struct{})
	close(watchDone)
	instance := &Instance{lifecycleGeneration: 1, watchDone: watchDone}
	req := StartRequest{
		Profile: Profile{MCC: "001", MNC: "01"},
		SIM:     inertSWuSIM{},
		epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
		}},
		outboundIPDetector: func(net.IP, int) (net.IP, error) {
			return net.ParseIP("198.51.100.20"), nil
		},
		swuConnectJoinDeadline: joinTimeout,
		swuSessionFactory: func(cfg *externalswu.Config) swuSession {
			session.cfg = cfg
			return session
		},
	}
	if _, err := instance.establishSWu(context.Background(), req, "epdg.test.invalid", "500", 1); err != nil {
		t.Fatalf("establishSWu() error = %v", err)
	}

	mobikeDone := make(chan error, 1)
	go func() { mobikeDone <- instance.TriggerMOBIKE("", "198.51.100.30") }()
	<-session.mobikeEntered
	joinTimeout <- time.Now()
	stopDone := make(chan error, 1)
	go func() { stopDone <- instance.Stop(context.Background()) }()

	var stopErr error
	select {
	case stopErr = <-stopDone:
	case <-time.After(time.Second):
		close(session.releaseMOBIKE)
		<-mobikeDone
		<-session.shutdownCalled
		close(session.releaseConnect)
		<-session.connectDone
		stopErr = <-stopDone
		t.Fatalf("Stop() did not honor the injected MOBIKE join timeout; eventual error=%v", stopErr)
	}
	if !errors.Is(stopErr, errSWuMOBIKEJoinTimeout) {
		t.Fatalf("Stop() error = %v, want errSWuMOBIKEJoinTimeout", stopErr)
	}
	select {
	case <-session.shutdownCalled:
		close(session.releaseMOBIKE)
		<-mobikeDone
		close(session.releaseConnect)
		<-session.connectDone
		t.Fatal("MOBIKE timeout triggered concurrent SWu Shutdown")
	default:
	}
	if err := instance.TriggerMOBIKE("", "198.51.100.40"); err == nil {
		t.Fatal("TriggerMOBIKE() accepted a new operation after timed-out Stop")
	}

	close(session.releaseMOBIKE)
	if err := <-mobikeDone; err != nil {
		t.Fatalf("in-flight TriggerMOBIKE() error = %v", err)
	}
	<-session.mobikeExited
	<-session.shutdownCalled
	close(session.releaseConnect)
	<-session.connectDone
}
func (*readySWuSession) Snapshot() externalswu.SessionSnapshot {
	return externalswu.SessionSnapshot{Established: true, IPv4: net.ParseIP("198.51.100.10")}
}
func (*readySWuSession) UpdateAddresses(string, string) error { return nil }
func (*readySWuSession) SendInnerPacket([]byte) error         { return nil }
func (s *readySWuSession) InnerPackets() <-chan []byte        { return s.inner }
func (*readySWuSession) Shutdown()                            {}
func (s *readySWuSession) WaitDone()                          { <-s.exited }
func (inertSWuSIM) Close() error                              { return nil }

type cancelAwareSWuSession struct {
	started  chan struct{}
	canceled chan struct{}
	exited   chan struct{}
	inner    chan []byte
}

type stubbornSWuSession struct {
	started chan struct{}
	release chan struct{}
	exited  chan struct{}
	inner   chan []byte
}

func (s *stubbornSWuSession) Connect(context.Context) error {
	close(s.started)
	<-s.release
	close(s.exited)
	return nil
}
func (*stubbornSWuSession) Snapshot() externalswu.SessionSnapshot {
	return externalswu.SessionSnapshot{}
}
func (*stubbornSWuSession) UpdateAddresses(string, string) error { return nil }
func (*stubbornSWuSession) SendInnerPacket([]byte) error         { return nil }
func (s *stubbornSWuSession) InnerPackets() <-chan []byte        { return s.inner }
func (*stubbornSWuSession) Shutdown()                            {}
func (s *stubbornSWuSession) WaitDone()                          { <-s.exited }

func newCancelAwareSWuSession() *cancelAwareSWuSession {
	return &cancelAwareSWuSession{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
		exited:   make(chan struct{}),
		inner:    make(chan []byte),
	}
}

func (s *cancelAwareSWuSession) Connect(ctx context.Context) error {
	close(s.started)
	<-ctx.Done()
	close(s.canceled)
	close(s.exited)
	return ctx.Err()
}

func (*cancelAwareSWuSession) Snapshot() externalswu.SessionSnapshot {
	return externalswu.SessionSnapshot{}
}

func (*cancelAwareSWuSession) UpdateAddresses(string, string) error { return nil }
func (*cancelAwareSWuSession) SendInnerPacket([]byte) error         { return nil }
func (s *cancelAwareSWuSession) InnerPackets() <-chan []byte        { return s.inner }
func (*cancelAwareSWuSession) Shutdown()                            {}
func (s *cancelAwareSWuSession) WaitDone()                          { <-s.exited }

func TestStartSWuSessionTimeoutCancelsAndJoinsConnect(t *testing.T) {
	session := newCancelAwareSWuSession()
	timeout := make(chan time.Time, 1)
	req := StartRequest{
		Profile: Profile{MCC: "001", MNC: "01"},
		SIM:     inertSWuSIM{},
		swuSessionFactory: func(*externalswu.Config) swuSession {
			return session
		},
		swuConnectDeadline: timeout,
	}
	result := make(chan error, 1)
	go func() {
		_, err := (&Instance{}).startSWuSession(context.Background(), req, "192.0.2.10", "500")
		result <- err
	}()

	<-session.started
	timeout <- time.Now()

	err := <-result
	if err == nil || !errors.Is(err, errSWuConnectTimeout) {
		t.Fatalf("startSWuSession() error = %v, want errSWuConnectTimeout", err)
	}
	select {
	case <-session.canceled:
	default:
		t.Fatal("startSWuSession() returned before cancel reached Connect")
	}
	select {
	case <-session.exited:
	default:
		t.Fatal("startSWuSession() returned before Connect exited")
	}
}

func TestStartSWuSessionCancellationCancelsAndJoinsConnect(t *testing.T) {
	session := newCancelAwareSWuSession()
	ctx, cancel := context.WithCancel(context.Background())
	req := StartRequest{
		Profile: Profile{MCC: "001", MNC: "01"},
		SIM:     inertSWuSIM{},
		swuSessionFactory: func(*externalswu.Config) swuSession {
			return session
		},
	}
	result := make(chan error, 1)
	go func() {
		_, err := (&Instance{}).startSWuSession(ctx, req, "192.0.2.10", "500")
		result <- err
	}()

	<-session.started
	cancel()
	err := <-result
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("startSWuSession() error = %v, want context.Canceled", err)
	}
	select {
	case <-session.canceled:
	default:
		t.Fatal("startSWuSession() returned before cancellation reached Connect")
	}
	select {
	case <-session.exited:
	default:
		t.Fatal("startSWuSession() returned before canceled Connect joined")
	}
}

func TestEstablishSWuCanceledReadyLeaseCannotBeAdopted(t *testing.T) {
	session := &stopJoinedSWuSession{
		shutdownCalled: make(chan struct{}),
		releaseConnect: make(chan struct{}),
		connectDone:    make(chan struct{}),
		done:           make(chan struct{}),
		inner:          make(chan []byte),
	}
	readyBeforeReturn := make(chan struct{})
	releaseStarter := make(chan struct{})
	instance := &Instance{lifecycleGeneration: 1}
	req := StartRequest{
		epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
		}},
		swuStarter: func(_ context.Context, _ StartRequest, candidate epdgCandidate, _ string) (*swuSessionLease, error) {
			lease := newSWUSessionLease(candidate.IP.String(), candidate, nil)
			session.cfg = &externalswu.Config{OnReady: lease.markReady}
			if err := lease.start(session); err != nil {
				return nil, err
			}
			<-lease.ready
			close(readyBeforeReturn)
			<-releaseStarter
			return lease, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	type establishResult struct {
		lease *swuSessionLease
		err   error
	}
	result := make(chan establishResult, 1)
	go func() {
		lease, err := instance.establishSWu(ctx, req, "epdg.test.invalid", "500", 1)
		result <- establishResult{lease: lease, err: err}
	}()

	<-readyBeforeReturn
	cancel()
	close(releaseStarter)
	select {
	case got := <-result:
		if got.lease != nil {
			close(session.releaseConnect)
			_ = got.lease.CancelAndJoin()
		}
		t.Fatalf("establishSWu() adopted a ready lease after cancellation: err=%v", got.err)
	case <-session.shutdownCalled:
	}
	close(session.releaseConnect)
	<-session.connectDone
	got := <-result
	if !errors.Is(got.err, context.Canceled) {
		t.Fatalf("establishSWu() error = %v, want context.Canceled", got.err)
	}
	if got.lease != nil {
		t.Fatal("establishSWu() returned a canceled lease")
	}
	instance.mu.Lock()
	installed := instance.swuLease
	instance.mu.Unlock()
	if installed != nil {
		t.Fatal("canceled ready lease became the Instance owner")
	}
}

func TestEstablishSWuLateReadyFromCanceledCandidateCannotWinNextAttempt(t *testing.T) {
	timeout := make(chan time.Time, 1)
	first := &lateReadySWuSession{started: make(chan struct{}), exited: make(chan struct{}), inner: make(chan []byte)}
	second := &readySWuSession{started: make(chan struct{}), exited: make(chan struct{}), inner: make(chan []byte)}
	factoryCalls := 0
	firstJoinedBeforeSecond := false
	instance := &Instance{lifecycleGeneration: 1}
	req := StartRequest{
		Profile: Profile{MCC: "001", MNC: "01"},
		SIM:     inertSWuSIM{},
		epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
			{IP: net.ParseIP("192.0.2.20")},
		}},
		outboundIPDetector: func(net.IP, int) (net.IP, error) {
			return net.ParseIP("198.51.100.20"), nil
		},
		swuConnectDeadline: timeout,
		swuSessionFactory: func(cfg *externalswu.Config) swuSession {
			factoryCalls++
			if factoryCalls == 1 {
				first.cfg = cfg
				return first
			}
			select {
			case <-first.exited:
				firstJoinedBeforeSecond = true
			default:
			}
			second.cfg = cfg
			return second
		},
	}
	type result struct {
		lease *swuSessionLease
		err   error
	}
	done := make(chan result, 1)
	go func() {
		lease, err := instance.establishSWu(context.Background(), req, "epdg.test.invalid", "500", 1)
		done <- result{lease: lease, err: err}
	}()

	<-first.started
	timeout <- time.Now()
	got := <-done
	if got.err != nil {
		t.Fatalf("establishSWu() error = %v", got.err)
	}
	if winner := got.lease.Candidate(); winner.Index != 2 {
		t.Fatalf("winning candidate index = %d, want 2", winner.Index)
	}
	if !firstJoinedBeforeSecond {
		t.Fatal("second candidate started before the canceled first candidate exited")
	}
	if err := got.lease.CancelAndJoin(); err != nil {
		t.Fatalf("winning lease CancelAndJoin() error = %v", err)
	}
}

func TestEstablishSWuJoinTimeoutDoesNotStartNextCandidate(t *testing.T) {
	timeout := make(chan time.Time, 1)
	joinTimeout := make(chan time.Time, 1)
	first := &stubbornSWuSession{
		started: make(chan struct{}),
		release: make(chan struct{}),
		exited:  make(chan struct{}),
		inner:   make(chan []byte),
	}
	second := &readySWuSession{started: make(chan struct{}), exited: make(chan struct{}), inner: make(chan []byte)}
	factoryCalls := 0
	instance := &Instance{lifecycleGeneration: 1}
	req := StartRequest{
		Profile: Profile{MCC: "001", MNC: "01"},
		SIM:     inertSWuSIM{},
		epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
			{IP: net.ParseIP("192.0.2.20")},
		}},
		outboundIPDetector: func(net.IP, int) (net.IP, error) {
			return net.ParseIP("198.51.100.20"), nil
		},
		swuConnectDeadline:     timeout,
		swuConnectJoinDeadline: joinTimeout,
		swuSessionFactory: func(cfg *externalswu.Config) swuSession {
			factoryCalls++
			if factoryCalls == 1 {
				return first
			}
			second.cfg = cfg
			return second
		},
	}
	done := make(chan error, 1)
	go func() {
		_, err := instance.establishSWu(context.Background(), req, "epdg.test.invalid", "500", 1)
		done <- err
	}()

	<-first.started
	timeout <- time.Now()
	joinTimeout <- time.Now()
	err := <-done
	if !errors.Is(err, errSWuConnectJoinTimeout) {
		t.Fatalf("establishSWu() error = %v, want errSWuConnectJoinTimeout", err)
	}
	if factoryCalls != 1 {
		t.Fatalf("session factory calls = %d, want 1", factoryCalls)
	}
	close(first.release)
	<-first.exited
}
