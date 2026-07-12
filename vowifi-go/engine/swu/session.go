package swu

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/strongswan/govici/vici"
)

// Dial registers cfg.AKA with the shared akabridge under cfg.Identity, loads
// the connection into the shared charon, wires up event-driven state
// tracking, and kicks off initiate() in the background. It does not block
// for IKE_AUTH to complete: per spike/vicispike/MAPPING.md, the initiate
// command's own return value isn't authoritative anyway (the event stream
// is), and a real ePDG negotiation can legitimately take longer than a
// caller should have to block Dial for. Callers observe the real outcome
// via the returned Session's Events().
//
// Three separate vici sessions are used deliberately, not one shared
// connection: govici's Session serializes every Call/CallStreaming behind
// one mutex for the connection's lifetime, and initiate's CallStreaming can
// legitimately block for the entire IKE_AUTH negotiation. Sharing that
// connection with terminate/unload-conn (in Close) would make teardown wait
// on whatever initiate is still doing -- caught by actually running this
// end-to-end (spike/managertest): terminate failed with a vici protocol
// error and unload-conn hit its context deadline, both symptoms of the
// close call queuing up behind a still-running initiate on the same
// serialized connection.
func (m *Manager) Dial(ctx context.Context, cfg Config) (Session, error) {
	if cfg.AKA == nil {
		return nil, errors.New("swu: Config.AKA is required")
	}
	deviceID := strings.TrimSpace(cfg.DeviceID)
	identity := strings.TrimSpace(cfg.Identity)
	epdg := strings.TrimSpace(cfg.EPDGAddr)
	if deviceID == "" {
		return nil, errors.New("swu: Config.DeviceID is required")
	}
	if identity == "" {
		return nil, errors.New("swu: Config.Identity is required")
	}
	if epdg == "" {
		return nil, errors.New("swu: Config.EPDGAddr is required")
	}

	if len(cfg.CACerts) > 0 {
		caCerts, err := loadCACerts(cfg.CACerts)
		if err != nil {
			return nil, fmt.Errorf("swu: %w", err)
		}
		cfg.CACerts = caCerts
	}

	m.bridge.Register(identity, cfg.AKA)
	unregister := func() { m.bridge.Unregister(identity) }

	cmdSess, err := m.sup.Session()
	if err != nil {
		unregister()
		return nil, fmt.Errorf("swu: vici session (cmd): %w", err)
	}

	connName := connNameFor(deviceID)
	conn := buildViciConn(cfg)
	loadMsg, err := vici.MarshalMessage(map[string]*viciConn{connName: conn})
	if err != nil {
		cmdSess.Close()
		unregister()
		return nil, fmt.Errorf("swu: marshal conn config: %w", err)
	}

	resp, err := cmdSess.Call(ctx, "load-conn", loadMsg)
	if err != nil {
		cmdSess.Close()
		unregister()
		return nil, fmt.Errorf("swu: load-conn: %w", err)
	}
	if err := resp.Err(); err != nil {
		cmdSess.Close()
		unregister()
		return nil, fmt.Errorf("swu: load-conn rejected: %w", err)
	}

	eventSess, err := m.sup.Session()
	if err != nil {
		cmdSess.Close()
		unregister()
		return nil, fmt.Errorf("swu: vici session (events): %w", err)
	}
	if err := eventSess.Subscribe("ike-updown", "child-updown"); err != nil {
		eventSess.Close()
		cmdSess.Close()
		unregister()
		return nil, fmt.Errorf("swu: subscribe: %w", err)
	}

	initiateSess, err := m.sup.Session()
	if err != nil {
		eventSess.Close()
		cmdSess.Close()
		unregister()
		return nil, fmt.Errorf("swu: vici session (initiate): %w", err)
	}

	initiateTimeout := cfg.InitiateTimeout
	if initiateTimeout <= 0 {
		initiateTimeout = 30 * time.Second
	}

	s := &session{
		deviceID:        deviceID,
		identity:        identity,
		connName:        connName,
		bridge:          m.bridge,
		pcscfBridge:     m.pcscfBridge,
		cmdSess:         cmdSess,
		eventSess:       eventSess,
		initiateSess:    initiateSess,
		events:          make(chan Event, 32),
		enableMOBIKE:    cfg.EnableMOBIKE,
		initiateTimeout: initiateTimeout,
	}

	evCh := make(chan vici.Event, 32)
	eventSess.NotifyEvents(evCh)

	watchCtx, watchCancel := context.WithCancel(context.Background())
	s.stopWatch = watchCancel
	s.watchDone = make(chan struct{})
	go s.watchEvents(watchCtx, evCh)

	pcscfCtx, pcscfCancel := context.WithCancel(context.Background())
	s.stopPCSCFWatch = pcscfCancel
	s.pcscfWatchDone = make(chan struct{})
	go s.watchPCSCF(pcscfCtx)

	initiateCtx, initiateCancel := context.WithCancel(context.Background())
	s.initiateCancel = initiateCancel
	s.initiateDone = make(chan struct{})
	go s.initiate(initiateCtx)

	return s, nil
}

// session implements Session against one loaded vici connection.
type session struct {
	deviceID string
	identity string
	connName string

	bridge       akaBridge
	pcscfBridge  pcscfBridge
	cmdSess      *vici.Session // load-conn (Dial), terminate/unload-conn (Close), rekey (TriggerMOBIKE)
	eventSess    *vici.Session // ike-updown/child-updown subscription, for this Session's whole lifetime
	initiateSess *vici.Session // the potentially long-running initiate() call, isolated so Close never queues behind it

	events chan Event

	stopWatch context.CancelFunc
	watchDone chan struct{}

	stopPCSCFWatch context.CancelFunc
	pcscfWatchDone chan struct{}

	initiateCancel context.CancelFunc
	initiateDone   chan struct{}

	enableMOBIKE    bool
	initiateTimeout time.Duration

	mu         sync.Mutex
	localIP    net.IP
	pcscfAddr  net.IP
	sawChildUp bool
	closed     bool
}

// akaBridge is the subset of *akabridge.Bridge the session needs, declared
// locally so this file doesn't have to import akabridge just for a type
// name (manager.go already does, and passes the concrete *akabridge.Bridge
// through, which satisfies this structurally).
type akaBridge interface {
	Unregister(identity string)
}

// pcscfBridge is the subset of *pcscfbridge.Bridge the session needs,
// declared locally for the same reason as akaBridge above.
type pcscfBridge interface {
	WaitFor(connName string) <-chan net.IP
	Forget(connName string)
}

func (s *session) LocalIP() net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.localIP
}

// PCSCFAddr returns the P-CSCF address pushed by the p-cscf-vohive plugin
// for this session's connection, or nil if it hasn't arrived (or never
// will — some ePDGs may not send it).
func (s *session) PCSCFAddr() net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pcscfAddr
}

// watchPCSCF waits for the pcscfbridge push for this session's connName and
// records it, until one arrives or ctx is done (Close). A P-CSCF address
// doesn't change mid-session (see bridge.go's deliver doc comment), so this
// only ever needs to fire once.
func (s *session) watchPCSCF(ctx context.Context) {
	defer close(s.pcscfWatchDone)
	defer s.pcscfBridge.Forget(s.connName)

	select {
	case ip := <-s.pcscfBridge.WaitFor(s.connName):
		s.mu.Lock()
		s.pcscfAddr = ip
		s.mu.Unlock()
	case <-ctx.Done():
	}
}

func (s *session) InterfaceName() string {
	// kernel-libipsec's single, daemon-wide TUN device -- see the Session
	// interface doc in swu.go for why this can't be used to pick this
	// Session out from concurrent ones.
	return "ipsec0"
}

func (s *session) Events() <-chan Event {
	return s.events
}

// TriggerMOBIKE forces a rekey of the underlying IKE_SA as a best-effort
// stand-in for a real RFC 4555 address update: vici has no dedicated MOBIKE
// command (charon detects address/interface changes and re-routes on its
// own via kernel-netlink), so this is the closest available primitive, not
// a literal implementation of the RFC mechanism.
func (s *session) TriggerMOBIKE(oldIP, newIP string) error {
	if !s.enableMOBIKE {
		return fmt.Errorf("swu: TriggerMOBIKE: session for %s was not configured with EnableMOBIKE", s.deviceID)
	}
	msg := vici.NewMessage()
	_ = msg.Set("ike", s.connName)
	resp, err := s.cmdSess.Call(context.Background(), "rekey", msg)
	if err != nil {
		return fmt.Errorf("swu: TriggerMOBIKE (via rekey): %w", err)
	}
	return resp.Err()
}

// Close stops any in-flight initiate, tears down the IKE_SA (and with it,
// its child), unloads the connection config, stops the event watcher, and
// releases the akabridge registration. Best-effort throughout: a partial
// failure still frees everything it can rather than leaving the session
// half torn-down.
func (s *session) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	// Cancel a still-running initiate first. Its own session is separate
	// from cmdSess so terminate/unload-conn below wouldn't block on it
	// regardless, but there's no reason to let a doomed initiate keep
	// retrying after the caller already asked to tear down.
	s.initiateCancel()
	<-s.initiateDone

	var errs []error

	termMsg := vici.NewMessage()
	_ = termMsg.Set("ike", s.connName)
	var termErr error
	for _, err := range s.cmdSess.CallStreaming(ctx, "terminate", "control-log", termMsg) {
		if err != nil {
			termErr = err
			break
		}
	}
	if termErr != nil {
		errs = append(errs, fmt.Errorf("terminate: %w", termErr))
	}

	unloadMsg := vici.NewMessage()
	_ = unloadMsg.Set("name", s.connName)
	if resp, err := s.cmdSess.Call(ctx, "unload-conn", unloadMsg); err != nil {
		errs = append(errs, fmt.Errorf("unload-conn: %w", err))
	} else if err := resp.Err(); err != nil {
		errs = append(errs, fmt.Errorf("unload-conn rejected: %w", err))
	}

	s.stopWatch()
	<-s.watchDone

	s.stopPCSCFWatch()
	<-s.pcscfWatchDone

	s.eventSess.Close()
	s.cmdSess.Close()
	s.initiateSess.Close()

	s.bridge.Unregister(s.identity)
	close(s.events)

	if len(errs) > 0 {
		return fmt.Errorf("swu: close: %v", errs)
	}
	return nil
}

// initiate runs charon's initiate command for this connection until it
// completes, fails, or ctx is cancelled (Close). Its own outcome isn't
// treated as authoritative for whether the tunnel came up (see the Dial doc
// comment and MAPPING.md): a Down event is only emitted here if
// watchEvents hasn't already reported a successful child-updown for our
// child, so a failure that raced past an actual success (observed with the
// loopback spike, a self-connection artifact) doesn't overwrite a real Up
// with a spurious Down. A cancellation (deliberate Close) isn't reported as
// a failure either.
func (s *session) initiate(ctx context.Context) {
	defer close(s.initiateDone)

	initMsg := vici.NewMessage()
	_ = initMsg.Set("ike", s.connName)
	_ = initMsg.Set("child", childName)
	// Bounds charon's own retry loop (see Config.InitiateTimeout doc comment
	// for why this is required, not optional: without it, charon retries
	// indefinitely against an unresponsive ePDG and Session.Events() never
	// gets a definitive outcome). A Go-level deadline slightly longer than
	// this is a safety margin in case the vici-side timeout param doesn't
	// actually bound the call for some reason -- belt and suspenders, not
	// the primary mechanism.
	_ = initMsg.Set("timeout", strconv.FormatInt(s.initiateTimeout.Milliseconds(), 10))

	callCtx, cancel := context.WithTimeout(ctx, s.initiateTimeout+5*time.Second)
	defer cancel()

	var initErr error
	for _, err := range s.initiateSess.CallStreaming(callCtx, "initiate", "control-log", initMsg) {
		if err != nil {
			initErr = err
			break
		}
	}

	if initErr == nil || ctx.Err() != nil {
		return
	}

	s.mu.Lock()
	up := s.sawChildUp
	s.mu.Unlock()
	if up {
		return
	}

	s.emit(Event{DeviceID: s.deviceID, State: SessionDown, Err: fmt.Errorf("swu: initiate: %w", initErr)})
}

func (s *session) watchEvents(ctx context.Context, evCh chan vici.Event) {
	defer close(s.watchDone)
	defer s.eventSess.StopEvents(evCh)

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-evCh:
			if !ok {
				return
			}
			s.handleEvent(ev)
		}
	}
}

func (s *session) handleEvent(ev vici.Event) {
	connMsg, ok := ev.Message.Get(s.connName).(*vici.Message)
	if !ok {
		return // event is for a different device's connection
	}

	switch ev.Name {
	case "ike-updown":
		s.handleIKEUpdown(ev, connMsg)
	case "child-updown":
		s.handleChildUpdown(ev, connMsg)
	}
}

func (s *session) handleIKEUpdown(ev vici.Event, connMsg *vici.Message) {
	s.updateLocalIP(connMsg)

	up := ev.Message.Get("up") == "yes"
	if up {
		s.mu.Lock()
		childUp := s.sawChildUp
		s.mu.Unlock()
		if !childUp {
			// IKE_SA is up but the tunnel (child SA) may not be yet --
			// a real intermediate state, not collapsed into SessionUp.
			s.emit(Event{DeviceID: s.deviceID, State: SessionConnecting})
		}
		return
	}

	s.mu.Lock()
	s.sawChildUp = false
	s.mu.Unlock()
	s.emit(Event{DeviceID: s.deviceID, State: SessionDown})
}

func (s *session) handleChildUpdown(ev vici.Event, connMsg *vici.Message) {
	s.updateLocalIP(connMsg)

	up := ev.Message.Get("up") == "yes"
	state := s.childState(connMsg)

	if up && state == "INSTALLED" {
		s.mu.Lock()
		s.sawChildUp = true
		s.mu.Unlock()
		s.emit(Event{DeviceID: s.deviceID, State: SessionUp, LocalIP: s.LocalIP(), PCSCFAddr: s.PCSCFAddr()})
		return
	}

	s.mu.Lock()
	s.sawChildUp = false
	s.mu.Unlock()
	s.emit(Event{DeviceID: s.deviceID, State: SessionDown})
}

// childState finds our child SA's state within a connection's "child-sas"
// section, which keys each active/recent child SA by "<name>-<uniqueid>",
// not by its configured name directly -- have to scan for the entry whose
// "name" field matches childName.
func (s *session) childState(connMsg *vici.Message) string {
	childSAs, ok := connMsg.Get("child-sas").(*vici.Message)
	if !ok {
		return ""
	}
	for _, key := range childSAs.Keys() {
		entry, ok := childSAs.Get(key).(*vici.Message)
		if !ok {
			continue
		}
		if name, _ := entry.Get("name").(string); name == childName {
			state, _ := entry.Get("state").(string)
			return state
		}
	}
	return ""
}

func (s *session) updateLocalIP(connMsg *vici.Message) {
	raw := connMsg.Get("local-vips")
	var addrs []string
	switch v := raw.(type) {
	case []string:
		addrs = v
	case string:
		addrs = []string{v}
	default:
		return
	}
	for _, a := range addrs {
		if ip := net.ParseIP(strings.TrimSpace(a)); ip != nil {
			s.mu.Lock()
			s.localIP = ip
			s.mu.Unlock()
			return
		}
	}
}

func (s *session) emit(ev Event) {
	select {
	case s.events <- ev:
	default:
		// Caller isn't draining fast enough: drop rather than block the
		// event-watch goroutine indefinitely. LocalIP() and the next event
		// still reflect the latest real state.
	}
}
