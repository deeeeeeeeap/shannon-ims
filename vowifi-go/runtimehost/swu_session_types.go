package runtimehost

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	swulogger "github.com/1239t/swu-go/pkg/logger"
	externalswu "github.com/1239t/swu-go/pkg/swu"
)

var (
	errSWuConnectJoinTimeout = errors.New("SWu Connect did not exit after cancellation")
	errSWuMOBIKEJoinTimeout  = errors.New("SWu MOBIKE did not exit before session cleanup")
)

const swuConnectJoinTimeout = 2 * time.Second

type swuSession interface {
	Connect(context.Context) error
	Snapshot() externalswu.SessionSnapshot
	UpdateAddresses(string, string) error
	SendInnerPacket([]byte) error
	InnerPackets() <-chan []byte
	Shutdown()
	WaitDone()
}

type swuSessionFactory func(*externalswu.Config) swuSession

type swuInnerDataplane interface {
	SendInnerPacket([]byte) error
	InnerPackets() <-chan []byte
}

// swuSessionLease is the sole runtimehost owner of one candidate-scoped SWu
// session and its Connect task. A lease is adopted by at most one Instance.
type swuSessionLease struct {
	mu sync.Mutex

	session       swuSession
	remoteIP      string
	candidate     epdgCandidate
	cancel        context.CancelFunc
	cancelOnce    sync.Once
	readyOnce     sync.Once
	ready         chan struct{}
	readySeen     bool
	connectDone   chan struct{}
	joined        chan struct{}
	connectErr    error
	snapshot      swuSnapshot
	localIP       net.IP
	joinDeadline  <-chan time.Time
	stopping      bool
	mobikeUsers   int
	mobikeIdle    chan struct{}
	cleanupOnce   sync.Once
	mobikeDrained chan struct{}
	cleanupDone   chan struct{}
}

func newSWUSessionLease(remoteIP string, candidate epdgCandidate, joinDeadline <-chan time.Time) *swuSessionLease {
	return &swuSessionLease{
		remoteIP:      remoteIP,
		candidate:     candidate,
		ready:         make(chan struct{}),
		connectDone:   make(chan struct{}),
		joined:        make(chan struct{}),
		joinDeadline:  joinDeadline,
		mobikeDrained: make(chan struct{}),
		cleanupDone:   make(chan struct{}),
	}
}

func (l *swuSessionLease) markReady() {
	if l == nil {
		return
	}
	l.readyOnce.Do(func() {
		l.mu.Lock()
		l.readySeen = true
		l.mu.Unlock()
		close(l.ready)
	})
}

func (l *swuSessionLease) start(session swuSession) error {
	if l == nil || session == nil {
		return errors.New("SWu session lease requires a session")
	}
	sessionCtx, cancel := context.WithCancel(context.Background())
	l.mu.Lock()
	l.session = session
	l.cancel = cancel
	l.mu.Unlock()
	go func() {
		err := session.Connect(sessionCtx)
		l.mu.Lock()
		l.connectErr = err
		readySeen := l.readySeen
		l.mu.Unlock()
		close(l.connectDone)
		if readySeen {
			session.WaitDone()
		}
		close(l.joined)
	}()
	return nil
}

func (l *swuSessionLease) cancelSession() {
	if l == nil {
		return
	}
	l.cancelOnce.Do(func() {
		l.mu.Lock()
		cancel := l.cancel
		session := l.session
		readySeen := l.readySeen
		l.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		// The concrete swu-go Session installs its internal cancel function
		// during Connect. Before OnReady, the lease context cancellation is the
		// safe teardown path; after readiness Connect has initialized the
		// session and Shutdown can be used to join its dataplane lifecycle.
		if session != nil && readySeen {
			session.Shutdown()
		}
	})
}

func (l *swuSessionLease) BeginStop() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.stopping = true
	l.mu.Unlock()
}

func (l *swuSessionLease) acquireMOBIKE() (swuSession, string, error) {
	if l == nil {
		return nil, "", errors.New("runtimehost: active tunnel does not support MOBIKE")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopping || l.session == nil {
		return nil, "", errors.New("runtimehost: active tunnel does not support MOBIKE")
	}
	if l.mobikeUsers == 0 {
		l.mobikeIdle = make(chan struct{})
	}
	l.mobikeUsers++
	return l.session, l.remoteIP, nil
}

func (l *swuSessionLease) releaseMOBIKE() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.mobikeUsers <= 0 {
		return
	}
	l.mobikeUsers--
	if l.mobikeUsers == 0 && l.mobikeIdle != nil {
		close(l.mobikeIdle)
		l.mobikeIdle = nil
	}
}

func (l *swuSessionLease) CancelAndJoin() error {
	if l == nil {
		return nil
	}
	mobikeDrained, cleanupDone := l.startCleanup()
	if err := waitForSWULeaseStage(mobikeDrained, l.joinDeadline, errSWuMOBIKEJoinTimeout); err != nil {
		return err
	}
	return waitForSWULeaseStage(cleanupDone, l.joinDeadline, errSWuConnectJoinTimeout)
}

func (l *swuSessionLease) startCleanup() (<-chan struct{}, <-chan struct{}) {
	l.BeginStop()
	l.cleanupOnce.Do(func() {
		l.mu.Lock()
		if l.mobikeDrained == nil {
			l.mobikeDrained = make(chan struct{})
		}
		if l.cleanupDone == nil {
			l.cleanupDone = make(chan struct{})
		}
		mobikeDrained := l.mobikeDrained
		cleanupDone := l.cleanupDone
		mobikeIdle := l.mobikeIdle
		if mobikeIdle == nil {
			close(mobikeDrained)
		}
		l.mu.Unlock()
		go func() {
			if mobikeIdle != nil {
				<-mobikeIdle
				close(mobikeDrained)
			}
			l.cancelSession()
			<-l.joined
			close(cleanupDone)
		}()
	})
	l.mu.Lock()
	mobikeDrained := l.mobikeDrained
	cleanupDone := l.cleanupDone
	l.mu.Unlock()
	return mobikeDrained, cleanupDone
}

func waitForSWULeaseStage(done <-chan struct{}, deadlineC <-chan time.Time, timeoutErr error) error {
	select {
	case <-done:
		return nil
	default:
	}
	var timer *time.Timer
	if deadlineC == nil {
		timer = time.NewTimer(swuConnectJoinTimeout)
		deadlineC = timer.C
		defer timer.Stop()
	}
	select {
	case <-done:
		return nil
	case <-deadlineC:
		return timeoutErr
	}
}

func (l *swuSessionLease) connectResult() error {
	if l == nil {
		return errors.New("SWu session lease unavailable")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.connectErr
}

func (l *swuSessionLease) setReadySnapshot(snapshot swuSnapshot) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.snapshot = snapshot
	l.localIP = append(net.IP(nil), preferTunnelLocalIP(snapshot)...)
	l.mu.Unlock()
}

func (l *swuSessionLease) Snapshot() swuSnapshot {
	if l == nil {
		return swuSnapshot{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return cloneSWUSnapshot(l.snapshot)
}

func (l *swuSessionLease) LocalIP() net.IP {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append(net.IP(nil), l.localIP...)
}

func (l *swuSessionLease) Dataplane() swuInnerDataplane {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.session
}

func (l *swuSessionLease) Candidate() epdgCandidate {
	if l == nil {
		return epdgCandidate{}
	}
	return l.candidate
}

func cloneSWUSnapshot(snapshot swuSnapshot) swuSnapshot {
	return swuSnapshot{
		Established: snapshot.Established,
		TUNName:     snapshot.TUNName,
		IPv4:        append(net.IP(nil), snapshot.IPv4...),
		IPv6:        append(net.IP(nil), snapshot.IPv6...),
		PCSCFv4:     cloneIPList(snapshot.PCSCFv4),
		PCSCFv6:     cloneIPList(snapshot.PCSCFv6),
	}
}

func cloneIPList(ips []net.IP) []net.IP {
	if ips == nil {
		return nil
	}
	cloned := make([]net.IP, len(ips))
	for index, ip := range ips {
		cloned[index] = append(net.IP(nil), ip...)
	}
	return cloned
}

func preferTunnelLocalIP(snapshot swuSnapshot) net.IP {
	if snapshot.IPv4 != nil {
		return snapshot.IPv4
	}
	if snapshot.IPv6 != nil {
		return snapshot.IPv6
	}
	return nil
}

func newExternalSWUSession(cfg *externalswu.Config) *externalswu.Session {
	return externalswu.NewSession(cfg, swulogger.Get())
}
