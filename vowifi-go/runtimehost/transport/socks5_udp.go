package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Socks5UDPEventKind names a change in the state of a SOCKS5 UDP association.
type Socks5UDPEventKind string

const (
	// Socks5UDPAssociated: the first association is up.
	Socks5UDPAssociated Socks5UDPEventKind = "associated"
	// Socks5UDPAssociationLost: the control connection, and with it the relay,
	// is gone. A replacement is requested on the next send or receive.
	Socks5UDPAssociationLost Socks5UDPEventKind = "association_lost"
	// Socks5UDPReassociated: a replacement association is up. The relay
	// endpoint and the local port differ from the previous one, so the remote
	// peer sees traffic arrive from a new address.
	Socks5UDPReassociated Socks5UDPEventKind = "reassociated"
	// Socks5UDPAttemptFailed: an association attempt failed and will be retried.
	Socks5UDPAttemptFailed Socks5UDPEventKind = "attempt_failed"
	// Socks5UDPFailed: the transport gave up. Every later call fails.
	Socks5UDPFailed Socks5UDPEventKind = "failed"
)

// Socks5UDPEvent reports an association state change.
type Socks5UDPEvent struct {
	Kind Socks5UDPEventKind
	// Attempt counts consecutive failures including this one.
	Attempt int
	// Relay describes the relay of a new association.
	Relay Socks5Relay
	// CredentialsIgnored is set on a new association when the proxy does not
	// support username/password and the configured credentials went unused.
	CredentialsIgnored bool
	Err                error
}

// Socks5UDPStats counts what happened on a SOCKS5 datagram transport.
type Socks5UDPStats struct {
	// Associations counts successful associations, the first one included.
	Associations uint64
	// FailedAttempts counts association attempts that failed.
	FailedAttempts uint64
	// MalformedDropped counts received datagrams that were not valid relay
	// datagrams and were discarded.
	MalformedDropped uint64
}

// Socks5UDPObservable is implemented by the SOCKS5 datagram transport.
type Socks5UDPObservable interface {
	// SetEventHandler installs the receiver of association events. It runs on
	// the transport's goroutines and must not block. An event is delivered
	// after the state change it describes, so a send or receive may observe
	// the new state before the handler has run.
	SetEventHandler(func(Socks5UDPEvent))
	Stats() Socks5UDPStats
	RelayAddr() *net.UDPAddr
}

// Socks5UDPOptions configures a SOCKS5 datagram transport.
type Socks5UDPOptions struct {
	ProxyAddr string
	Username  string
	Password  string

	// Timeout bounds the TCP connect and every control exchange.
	// Zero means DefaultSocks5Timeout.
	Timeout time.Duration
	// MaxAttempts is the number of consecutive failed association attempts
	// after which the transport gives up. Zero means 5.
	MaxAttempts int
	// BackoffBase is the delay after the first failed attempt; it doubles
	// with every further failure up to BackoffMax. Zero means 500ms and 8s.
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// MinStable is how long an association must survive to count as a
	// success. One that dies sooner counts as a failed attempt, so a proxy
	// that accepts and immediately drops associations cannot cause a
	// reconnect storm. Zero means 2s.
	MinStable time.Duration

	OnEvent func(Socks5UDPEvent)
	// Dial replaces the TCP dialer. Optional.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

const (
	defaultSocks5UDPMaxAttempts = 5
	defaultSocks5UDPBackoffBase = 500 * time.Millisecond
	defaultSocks5UDPBackoffMax  = 8 * time.Second
	defaultSocks5UDPMinStable   = 2 * time.Second

	// Largest UDP payload; a relay datagram cannot be longer.
	socks5MaxDatagram = 65535
)

// ErrSocks5RelayUnavailable is returned by SendTo while the association is
// down and the next attempt is not due yet. The datagram is not sent; the
// caller's own retransmission covers the gap.
var ErrSocks5RelayUnavailable = errors.New("socks5 udp: relay unavailable, association pending")

type socks5Association struct {
	ctrl  *Socks5Conn
	udp   *net.UDPConn
	relay Socks5Relay
	since time.Time
}

func (a *socks5Association) close() {
	_ = a.udp.Close()
	_ = a.ctrl.Close()
}

// socks5UDPTransport carries datagrams through a SOCKS5 UDP association.
//
// The association is made on first use. When the proxy drops the control
// connection the relay is gone (RFC 1928 section 7); the transport then makes
// a new association with bounded, backed-off attempts instead of failing the
// session, and gives up for good only after MaxAttempts consecutive failures.
type socks5UDPTransport struct {
	opts Socks5UDPOptions

	lifeCtx context.Context
	cancel  context.CancelFunc

	establishMu sync.Mutex // serialises association attempts

	recvMu  sync.Mutex // serialises RecvFrom, which owns recvBuf
	recvBuf []byte

	mu          sync.Mutex
	assoc       *socks5Association
	closed      bool
	failure     error // why the transport gave up; nil after a plain Close
	lastErr     error // most recent association failure
	failures    int   // consecutive failed attempts
	nextAttempt time.Time
	everUp      bool
	onEvent     func(Socks5UDPEvent)

	associations   atomic.Uint64
	failedAttempts atomic.Uint64
	malformed      atomic.Uint64
}

// NewSocks5UDPTransport creates a SOCKS5 UDP ASSOCIATE transport with default
// options. No connection is made until the first send or receive.
func NewSocks5UDPTransport(proxyAddr, username, password string) (DatagramTransport, error) {
	return NewSocks5UDPTransportWithOptions(Socks5UDPOptions{
		ProxyAddr: proxyAddr,
		Username:  username,
		Password:  password,
	})
}

// NewSocks5UDPTransportWithOptions creates a SOCKS5 UDP ASSOCIATE transport.
func NewSocks5UDPTransportWithOptions(opts Socks5UDPOptions) (DatagramTransport, error) {
	if opts.ProxyAddr == "" {
		return nil, errors.New("socks5 udp: proxy address is required")
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = defaultSocks5UDPMaxAttempts
	}
	if opts.BackoffBase <= 0 {
		opts.BackoffBase = defaultSocks5UDPBackoffBase
	}
	if opts.BackoffMax <= 0 {
		opts.BackoffMax = defaultSocks5UDPBackoffMax
	}
	if opts.BackoffMax < opts.BackoffBase {
		opts.BackoffMax = opts.BackoffBase
	}
	if opts.MinStable <= 0 {
		opts.MinStable = defaultSocks5UDPMinStable
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &socks5UDPTransport{
		opts:    opts,
		lifeCtx: ctx,
		cancel:  cancel,
		onEvent: opts.OnEvent,
	}, nil
}

func (s *socks5UDPTransport) SetEventHandler(fn func(Socks5UDPEvent)) {
	s.mu.Lock()
	s.onEvent = fn
	s.mu.Unlock()
}

func (s *socks5UDPTransport) emit(ev Socks5UDPEvent) {
	s.mu.Lock()
	fn := s.onEvent
	s.mu.Unlock()
	if fn != nil {
		fn(ev)
	}
}

func (s *socks5UDPTransport) Stats() Socks5UDPStats {
	return Socks5UDPStats{
		Associations:     s.associations.Load(),
		FailedAttempts:   s.failedAttempts.Load(),
		MalformedDropped: s.malformed.Load(),
	}
}

// terminalErrLocked returns the error for calls on a finished transport.
func (s *socks5UDPTransport) terminalErrLocked() error {
	if s.failure != nil {
		return s.failure
	}
	return fmt.Errorf("socks5 udp: %w", net.ErrClosed)
}

func (s *socks5UDPTransport) backoff(failures int) time.Duration {
	d := s.opts.BackoffBase
	for i := 1; i < failures && d < s.opts.BackoffMax; i++ {
		d *= 2
	}
	if d > s.opts.BackoffMax {
		d = s.opts.BackoffMax
	}
	return d
}

// current returns a usable association. With wait set it blocks through
// back-off periods and failed attempts and returns an error only once the
// transport is finished; without it, it fails fast while the relay is down.
func (s *socks5UDPTransport) current(wait bool) (*socks5Association, error) {
	for {
		s.mu.Lock()
		if s.closed {
			err := s.terminalErrLocked()
			s.mu.Unlock()
			return nil, err
		}
		if a := s.assoc; a != nil {
			s.mu.Unlock()
			return a, nil
		}
		delay := time.Until(s.nextAttempt)
		lastErr := s.lastErr
		s.mu.Unlock()

		if delay > 0 {
			if !wait {
				if lastErr != nil {
					return nil, fmt.Errorf("%w: %v", ErrSocks5RelayUnavailable, lastErr)
				}
				return nil, ErrSocks5RelayUnavailable
			}
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-s.lifeCtx.Done():
				timer.Stop()
			}
			continue
		}

		a, err := s.associate()
		if a != nil {
			return a, nil
		}
		if !wait {
			return nil, err
		}
	}
}

// associate makes one association attempt unless another caller already
// produced an association or scheduled a back-off.
func (s *socks5UDPTransport) associate() (*socks5Association, error) {
	s.establishMu.Lock()
	defer s.establishMu.Unlock()

	s.mu.Lock()
	if s.closed {
		err := s.terminalErrLocked()
		s.mu.Unlock()
		return nil, err
	}
	if a := s.assoc; a != nil {
		s.mu.Unlock()
		return a, nil
	}
	if time.Now().Before(s.nextAttempt) {
		s.mu.Unlock()
		return nil, ErrSocks5RelayUnavailable
	}
	s.mu.Unlock()

	a, err := s.dialAssociation()

	s.mu.Lock()
	if s.closed {
		terminal := s.terminalErrLocked()
		s.mu.Unlock()
		if a != nil {
			a.close()
		}
		return nil, terminal
	}
	if err != nil {
		events := s.recordFailureLocked(err)
		terminal := s.failure
		s.mu.Unlock()
		s.finishFailure(events)
		if terminal != nil {
			return nil, terminal
		}
		return nil, err
	}
	reassociated := s.everUp
	s.assoc = a
	s.everUp = true
	s.lastErr = nil
	s.mu.Unlock()

	s.associations.Add(1)
	go s.watchControl(a)

	kind := Socks5UDPAssociated
	if reassociated {
		kind = Socks5UDPReassociated
	}
	s.emit(Socks5UDPEvent{Kind: kind, Relay: a.relay, CredentialsIgnored: a.ctrl.CredentialsIgnored()})
	return a, nil
}

// recordFailureLocked counts a failed attempt and either schedules the next
// one or finishes the transport. It returns the events to emit once the lock
// is released.
func (s *socks5UDPTransport) recordFailureLocked(err error) []Socks5UDPEvent {
	s.failedAttempts.Add(1)
	s.failures++
	s.lastErr = err
	events := []Socks5UDPEvent{{Kind: Socks5UDPAttemptFailed, Attempt: s.failures, Err: err}}
	if s.failures >= s.opts.MaxAttempts {
		s.closed = true
		s.failure = fmt.Errorf("socks5 udp: giving up after %d failed association attempts: %w", s.failures, err)
		return append(events, Socks5UDPEvent{Kind: Socks5UDPFailed, Attempt: s.failures, Err: s.failure})
	}
	s.nextAttempt = time.Now().Add(s.backoff(s.failures))
	return events
}

func (s *socks5UDPTransport) finishFailure(events []Socks5UDPEvent) {
	for _, ev := range events {
		if ev.Kind == Socks5UDPFailed {
			s.cancel()
		}
		s.emit(ev)
	}
}

func (s *socks5UDPTransport) dialAssociation() (*socks5Association, error) {
	ctrl, err := DialSocks5(s.lifeCtx, s.opts.ProxyAddr, Socks5Options{
		Username: s.opts.Username,
		Password: s.opts.Password,
		Timeout:  s.opts.Timeout,
		Dial:     s.opts.Dial,
	})
	if err != nil {
		return nil, err
	}
	relay, err := ctrl.UDPAssociate(s.lifeCtx)
	if err != nil {
		_ = ctrl.Close()
		return nil, err
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		_ = ctrl.Close()
		return nil, fmt.Errorf("socks5 udp: open local socket: %w", err)
	}
	return &socks5Association{ctrl: ctrl, udp: udp, relay: relay, since: time.Now()}, nil
}

// watchControl blocks until the control connection ends, which is the only
// signal that the proxy dropped the relay.
func (s *socks5UDPTransport) watchControl(a *socks5Association) {
	buf := make([]byte, 64)
	for {
		if _, err := a.ctrl.Conn().Read(buf); err != nil {
			s.dropAssociation(a, fmt.Errorf("socks5 control connection closed: %w", err))
			return
		}
	}
}

// dropAssociation retires a if it is still the current association.
func (s *socks5UDPTransport) dropAssociation(a *socks5Association, cause error) {
	var events []Socks5UDPEvent
	s.mu.Lock()
	if s.assoc == a && !s.closed {
		s.assoc = nil
		events = append(events, Socks5UDPEvent{Kind: Socks5UDPAssociationLost, Err: cause})
		if time.Since(a.since) < s.opts.MinStable {
			events = append(events, s.recordFailureLocked(cause)...)
		} else {
			s.failures = 0
			s.nextAttempt = time.Time{}
			s.lastErr = cause
		}
	}
	s.mu.Unlock()

	a.close()
	s.finishFailure(events)
}

func (s *socks5UDPTransport) isCurrent(a *socks5Association) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.assoc == a
}

// SendTo sends payload to addr through the relay. While the association is
// down it fails with ErrSocks5RelayUnavailable instead of blocking.
func (s *socks5UDPTransport) SendTo(payload []byte, addr *net.UDPAddr) (int, error) {
	packet, err := EncodeSocks5UDPDatagram(addr, payload)
	if err != nil {
		return 0, err
	}
	a, err := s.current(false)
	if err != nil {
		return 0, err
	}
	if _, err := a.udp.WriteToUDP(packet, a.relay.Addr); err != nil {
		return 0, err
	}
	return len(payload), nil
}

// RecvFrom blocks until a datagram arrives through the relay and returns its
// payload and the address it came from. It keeps working across a lost
// association and returns an error only when the transport is closed or has
// given up. Datagrams that are not valid relay datagrams are discarded:
// anything can reach a UDP port, and one stray packet must not end a tunnel.
func (s *socks5UDPTransport) RecvFrom(buffer []byte) (int, *net.UDPAddr, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if s.recvBuf == nil {
		s.recvBuf = make([]byte, socks5MaxDatagram)
	}
	for {
		a, err := s.current(true)
		if err != nil {
			return 0, nil, err
		}
		n, _, err := a.udp.ReadFromUDP(s.recvBuf)
		if err != nil {
			if s.isCurrent(a) {
				s.dropAssociation(a, fmt.Errorf("socks5 udp socket: %w", err))
			}
			continue
		}
		src, payload, err := DecodeSocks5UDPDatagram(s.recvBuf[:n])
		if err != nil {
			s.malformed.Add(1)
			continue
		}
		return copy(buffer, payload), src.UDPAddr(), nil
	}
}

// Close ends the association and makes every later call fail.
func (s *socks5UDPTransport) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	a := s.assoc
	s.assoc = nil
	s.mu.Unlock()

	s.cancel()
	if a != nil {
		a.close()
	}
	return nil
}

// LocalAddr returns the local address of the current association's socket,
// or nil while there is none.
func (s *socks5UDPTransport) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.assoc == nil {
		return nil
	}
	return s.assoc.udp.LocalAddr()
}

// RelayAddr returns the relay endpoint of the current association, or nil.
func (s *socks5UDPTransport) RelayAddr() *net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.assoc == nil || s.assoc.relay.Addr == nil {
		return nil
	}
	relay := s.assoc.relay.Addr
	return &net.UDPAddr{
		IP:   append(net.IP(nil), relay.IP...),
		Port: relay.Port,
		Zone: relay.Zone,
	}
}
