// Package socks5sim is an in-process SOCKS5 proxy (RFC 1928, RFC 1929) with
// fault injection.
//
// It stands in for a real upstream proxy so the whole proxy chain can be
// exercised on one machine with no network and no hardware: normal operation,
// sustained load, and the failure modes real proxies show in the field
// (stalled or reset control connections, unusual relay addresses, datagram
// loss, delay, reordering and duplication, dropped associations).
//
// Everything binds to 127.0.0.1, so nothing here is reachable from outside
// the host and nothing is ever sent to an external address unless a test
// asks the proxy to relay to one.
package socks5sim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// AuthMode selects the authentication methods the proxy accepts.
type AuthMode int

const (
	// AuthNone accepts only "no authentication required".
	AuthNone AuthMode = iota
	// AuthUserPass accepts only username/password.
	AuthUserPass
	// AuthEither accepts both and selects username/password when offered.
	AuthEither
)

// RelayAdvertise selects the relay address put in the UDP ASSOCIATE reply.
// The relay itself always listens on 127.0.0.1.
type RelayAdvertise int

const (
	// AdvertiseActual advertises the real relay address.
	AdvertiseActual RelayAdvertise = iota
	// AdvertiseUnspecified advertises 0.0.0.0 with the real port, as proxies
	// bound to the wildcard address commonly do.
	AdvertiseUnspecified
	// AdvertiseDomain advertises a host name (Faults.AdvertiseHost, default
	// "localhost") with the real port.
	AdvertiseDomain
	// AdvertisePortZero advertises port 0, which is unusable.
	AdvertisePortZero
	// AdvertiseDeadPort advertises a port nothing listens on: the association
	// is granted but every datagram is lost.
	AdvertiseDeadPort
)

// Config is the fixed part of the proxy's behaviour.
type Config struct {
	Auth     AuthMode
	Username string
	Password string
}

// Faults is the adjustable misbehaviour. The zero value is a well-behaved
// proxy. Control-connection faults apply to connections handled after the
// change; datagram faults apply to live associations immediately.
type Faults struct {
	// StallGreeting reads the method offer and never answers.
	StallGreeting bool
	// CloseOnGreeting closes the connection instead of answering the offer.
	CloseOnGreeting bool
	// DropConnections closes the next N control connections instead of
	// answering the offer, the way a proxy does while it restarts; the
	// connections after those are served.
	DropConnections int
	// WrongVersion answers the offer with a non-SOCKS5 version byte.
	WrongVersion bool
	// ReplyDelay is waited before every control reply.
	ReplyDelay time.Duration
	// ByteAtATime writes control replies one byte per TCP segment.
	ByteAtATime bool
	// StallRequest reads a request and never answers.
	StallRequest bool
	// CloseOnRequest closes the connection instead of answering a request.
	CloseOnRequest bool
	// AssociateReply, when non-zero, is the failure code for UDP ASSOCIATE.
	AssociateReply byte
	// ConnectReply, when non-zero, is the failure code for CONNECT.
	ConnectReply byte
	// ConnectTrailer is written in the same TCP segment as the CONNECT reply,
	// as happens when the target speaks first and its bytes are coalesced
	// with the proxy's reply.
	ConnectTrailer []byte
	// Advertise selects the relay address in the UDP ASSOCIATE reply.
	Advertise RelayAdvertise
	// AdvertiseHost is the name used by AdvertiseDomain.
	AdvertiseHost string
	// AssociationLifetime, when positive, makes the proxy drop the control
	// connection this long after granting an association.
	AssociationLifetime time.Duration

	// DropOutbound drops the next N datagrams from the client.
	DropOutbound int
	// DropInbound drops the next N datagrams to the client.
	DropInbound int
	// DelayInbound delays every datagram to the client.
	DelayInbound time.Duration
	// ReorderInbound, when above 1, delivers datagrams to the client in
	// reversed groups of this size.
	ReorderInbound int
	// DuplicateInbound delivers every datagram to the client twice.
	DuplicateInbound bool
}

// Stats counts what the proxy saw.
type Stats struct {
	Connections         uint64 // accepted control connections
	AuthOK              uint64 // successful username/password logins
	AuthFailed          uint64 // rejected username/password logins
	NoAcceptable        uint64 // method offers refused with 0xFF
	Associations        uint64 // UDP associations granted
	ActiveAssociations  int    // UDP associations currently up
	Connects            uint64 // CONNECT tunnels opened
	DatagramsOut        uint64 // datagrams relayed from clients
	DatagramsIn         uint64 // datagrams relayed to clients
	DroppedOut          uint64 // datagrams from clients dropped by a fault
	DroppedIn           uint64 // datagrams to clients dropped by a fault
	MalformedFromClient uint64 // client datagrams without a valid relay header
}

// heldFlushAfter bounds how long a reorder group waits for its last member.
const heldFlushAfter = 40 * time.Millisecond

// Server is the simulated proxy.
type Server struct {
	cfg Config
	ln  net.Listener

	mu        sync.Mutex
	faults    Faults
	conns     map[net.Conn]struct{}
	assocs    map[*association]struct{}
	greetings [][]byte
	closed    bool

	wg sync.WaitGroup

	connections         atomic.Uint64
	authOK              atomic.Uint64
	authFailed          atomic.Uint64
	noAcceptable        atomic.Uint64
	associations        atomic.Uint64
	connects            atomic.Uint64
	datagramsOut        atomic.Uint64
	datagramsIn         atomic.Uint64
	droppedOut          atomic.Uint64
	droppedIn           atomic.Uint64
	malformedFromClient atomic.Uint64
}

// Start runs a proxy on a free port of 127.0.0.1.
func Start(cfg Config) (*Server, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("socks5sim: listen: %w", err)
	}
	s := &Server{
		cfg:    cfg,
		ln:     ln,
		conns:  make(map[net.Conn]struct{}),
		assocs: make(map[*association]struct{}),
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

// Addr returns the proxy's "host:port".
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close stops the proxy, drops every connection and association and waits
// for its goroutines.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	assocs := make([]*association, 0, len(s.assocs))
	for a := range s.assocs {
		assocs = append(assocs, a)
	}
	s.mu.Unlock()

	_ = s.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	for _, a := range assocs {
		a.close()
	}
	s.wg.Wait()
}

// SetFaults changes the injected misbehaviour.
func (s *Server) SetFaults(change func(*Faults)) {
	s.mu.Lock()
	change(&s.faults)
	s.mu.Unlock()
}

// Faults returns the current fault settings.
func (s *Server) Faults() Faults {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.faults
}

// Stats returns a snapshot of the counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	active := len(s.assocs)
	s.mu.Unlock()
	return Stats{
		Connections:         s.connections.Load(),
		AuthOK:              s.authOK.Load(),
		AuthFailed:          s.authFailed.Load(),
		NoAcceptable:        s.noAcceptable.Load(),
		Associations:        s.associations.Load(),
		ActiveAssociations:  active,
		Connects:            s.connects.Load(),
		DatagramsOut:        s.datagramsOut.Load(),
		DatagramsIn:         s.datagramsIn.Load(),
		DroppedOut:          s.droppedOut.Load(),
		DroppedIn:           s.droppedIn.Load(),
		MalformedFromClient: s.malformedFromClient.Load(),
	}
}

// Greetings returns the authentication methods offered by each control
// connection so far, in order of arrival.
func (s *Server) Greetings() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.greetings))
	for i, g := range s.greetings {
		out[i] = append([]byte(nil), g...)
	}
	return out
}

// DropControlConnections closes the control connection of every live UDP
// association, which also ends its relay, and returns how many it closed.
func (s *Server) DropControlConnections() int {
	s.mu.Lock()
	assocs := make([]*association, 0, len(s.assocs))
	for a := range s.assocs {
		assocs = append(assocs, a)
	}
	s.mu.Unlock()
	for _, a := range assocs {
		_ = a.ctrl.Close()
	}
	return len(assocs)
}

// InjectToClients sends raw, unmodified, from the relay socket of every live
// association to its client and returns how many clients it reached. It is
// how tests deliver datagrams that are not valid relay datagrams.
func (s *Server) InjectToClients(raw []byte) int {
	s.mu.Lock()
	assocs := make([]*association, 0, len(s.assocs))
	for a := range s.assocs {
		assocs = append(assocs, a)
	}
	s.mu.Unlock()
	sent := 0
	for _, a := range assocs {
		if client := a.clientAddr(); client != nil {
			if _, err := a.relay.WriteToUDP(raw, client); err == nil {
				sent++
			}
		}
	}
	return sent
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		if !s.track(conn) {
			_ = conn.Close()
			return
		}
		s.connections.Add(1)
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) forget(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
	_ = conn.Close()
}

// takeFault consumes one unit of a counted fault.
func (s *Server) takeFault(counter func(*Faults) *int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := counter(&s.faults)
	if *n <= 0 {
		return false
	}
	*n--
	return true
}

func (s *Server) reply(conn net.Conn, b []byte) bool {
	f := s.Faults()
	if f.ReplyDelay > 0 {
		time.Sleep(f.ReplyDelay)
	}
	if !f.ByteAtATime {
		_, err := conn.Write(b)
		return err == nil
	}
	for i := range b {
		if _, err := conn.Write(b[i : i+1]); err != nil {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
	return true
}

func blockUntilClosed(conn net.Conn) {
	_, _ = io.Copy(io.Discard, conn)
}

func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer s.forget(conn)

	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil || head[0] != 0x05 {
		return
	}
	offered := make([]byte, head[1])
	if _, err := io.ReadFull(conn, offered); err != nil {
		return
	}
	s.mu.Lock()
	s.greetings = append(s.greetings, append([]byte(nil), offered...))
	s.mu.Unlock()

	if s.takeFault(func(f *Faults) *int { return &f.DropConnections }) {
		return
	}
	f := s.Faults()
	switch {
	case f.StallGreeting:
		blockUntilClosed(conn)
		return
	case f.CloseOnGreeting:
		return
	case f.WrongVersion:
		s.reply(conn, []byte{0x04, 0x5a})
		return
	}

	method := s.selectMethod(offered)
	if !s.reply(conn, []byte{0x05, method}) {
		return
	}
	switch method {
	case 0xFF:
		s.noAcceptable.Add(1)
		return
	case 0x02:
		if !s.authenticate(conn) {
			return
		}
	}
	s.serveRequest(conn)
}

func (s *Server) selectMethod(offered []byte) byte {
	has := func(m byte) bool {
		for _, o := range offered {
			if o == m {
				return true
			}
		}
		return false
	}
	switch s.cfg.Auth {
	case AuthUserPass:
		if has(0x02) {
			return 0x02
		}
	case AuthEither:
		if has(0x02) {
			return 0x02
		}
		if has(0x00) {
			return 0x00
		}
	default:
		if has(0x00) {
			return 0x00
		}
	}
	return 0xFF
}

func (s *Server) authenticate(conn net.Conn) bool {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return false
	}
	user := make([]byte, head[1])
	if _, err := io.ReadFull(conn, user); err != nil {
		return false
	}
	var passLen [1]byte
	if _, err := io.ReadFull(conn, passLen[:]); err != nil {
		return false
	}
	pass := make([]byte, passLen[0])
	if _, err := io.ReadFull(conn, pass); err != nil {
		return false
	}
	if head[0] == 0x01 && string(user) == s.cfg.Username && string(pass) == s.cfg.Password {
		s.authOK.Add(1)
		return s.reply(conn, []byte{0x01, 0x00})
	}
	s.authFailed.Add(1)
	s.reply(conn, []byte{0x01, 0x01})
	return false
}

type target struct {
	ip     net.IP
	domain string
	port   int
}

func (t target) hostPort() string {
	host := t.domain
	if host == "" {
		host = t.ip.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(t.port))
}

func readTarget(r io.Reader, atyp byte) (target, error) {
	var t target
	var hostLen int
	switch atyp {
	case 0x01:
		hostLen = net.IPv4len
	case 0x04:
		hostLen = net.IPv6len
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return t, err
		}
		hostLen = int(l[0])
	default:
		return t, errors.New("unknown address type")
	}
	buf := make([]byte, hostLen+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return t, err
	}
	if atyp == 0x03 {
		t.domain = string(buf[:hostLen])
	} else {
		t.ip = net.IP(buf[:hostLen])
	}
	t.port = int(binary.BigEndian.Uint16(buf[hostLen:]))
	return t, nil
}

func failureReply(code byte) []byte {
	return []byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}

func successReply(ip net.IP, port int) []byte {
	b := []byte{0x05, 0x00, 0x00}
	if v4 := ip.To4(); v4 != nil {
		b = append(b, 0x01)
		b = append(b, v4...)
	} else {
		b = append(b, 0x04)
		b = append(b, ip.To16()...)
	}
	return append(b, byte(port>>8), byte(port))
}

func successReplyDomain(host string, port int) []byte {
	b := []byte{0x05, 0x00, 0x00, 0x03, byte(len(host))}
	b = append(b, host...)
	return append(b, byte(port>>8), byte(port))
}

func (s *Server) serveRequest(conn net.Conn) {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil || head[0] != 0x05 {
		return
	}
	dst, err := readTarget(conn, head[3])
	if err != nil {
		s.reply(conn, failureReply(0x08))
		return
	}

	f := s.Faults()
	switch {
	case f.StallRequest:
		blockUntilClosed(conn)
		return
	case f.CloseOnRequest:
		return
	}
	switch head[1] {
	case 0x01:
		s.serveConnect(conn, dst, f)
	case 0x03:
		s.serveAssociate(conn, f)
	default:
		s.reply(conn, failureReply(0x07))
	}
}

func (s *Server) serveConnect(conn net.Conn, dst target, f Faults) {
	if f.ConnectReply != 0 {
		s.reply(conn, failureReply(f.ConnectReply))
		return
	}
	upstream, err := net.DialTimeout("tcp", dst.hostPort(), 5*time.Second)
	if err != nil {
		s.reply(conn, failureReply(0x05))
		return
	}
	if !s.track(upstream) {
		_ = upstream.Close()
		return
	}
	defer s.forget(upstream)

	local, _ := upstream.LocalAddr().(*net.TCPAddr)
	if local == nil {
		return
	}
	if !s.reply(conn, append(successReply(local.IP, local.Port), f.ConnectTrailer...)) {
		return
	}
	s.connects.Add(1)

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	_ = conn.Close()
	_ = upstream.Close()
	<-done
}

// association is one UDP relay: a client-facing socket, a target-facing
// socket and the control connection whose lifetime bounds both.
type association struct {
	srv   *Server
	ctrl  net.Conn
	relay *net.UDPConn
	out   *net.UDPConn

	mu        sync.Mutex
	client    *net.UDPAddr
	held      [][]byte
	closed    bool
	flushing  *time.Timer
	closeOnce sync.Once
}

func (a *association) close() {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		if a.flushing != nil {
			a.flushing.Stop()
		}
		a.mu.Unlock()
		_ = a.relay.Close()
		_ = a.out.Close()
		_ = a.ctrl.Close()
	})
}

func (a *association) clientAddr() *net.UDPAddr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.client
}

func listenLoopbackUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

func (s *Server) serveAssociate(conn net.Conn, f Faults) {
	if f.AssociateReply != 0 {
		s.reply(conn, failureReply(f.AssociateReply))
		return
	}
	relay, err := listenLoopbackUDP()
	if err != nil {
		s.reply(conn, failureReply(0x01))
		return
	}
	out, err := listenLoopbackUDP()
	if err != nil {
		_ = relay.Close()
		s.reply(conn, failureReply(0x01))
		return
	}
	a := &association{srv: s, ctrl: conn, relay: relay, out: out}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		a.close()
		return
	}
	s.assocs[a] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.assocs, a)
		s.mu.Unlock()
		a.close()
	}()

	loopback := net.IPv4(127, 0, 0, 1)
	port := relay.LocalAddr().(*net.UDPAddr).Port
	var rep []byte
	switch f.Advertise {
	case AdvertiseUnspecified:
		rep = successReply(net.IPv4zero, port)
	case AdvertiseDomain:
		host := f.AdvertiseHost
		if host == "" {
			host = "localhost"
		}
		rep = successReplyDomain(host, port)
	case AdvertisePortZero:
		rep = successReply(loopback, 0)
	case AdvertiseDeadPort:
		dead, err := listenLoopbackUDP()
		if err != nil {
			s.reply(conn, failureReply(0x01))
			return
		}
		deadPort := dead.LocalAddr().(*net.UDPAddr).Port
		_ = dead.Close()
		rep = successReply(loopback, deadPort)
	default:
		rep = successReply(loopback, port)
	}
	if !s.reply(conn, rep) {
		return
	}
	s.associations.Add(1)

	s.wg.Add(2)
	go a.clientToTarget()
	go a.targetToClient()

	if f.AssociationLifetime > 0 {
		expire := time.AfterFunc(f.AssociationLifetime, func() { _ = conn.Close() })
		defer expire.Stop()
	}
	// RFC 1928: the association ends when its control connection does.
	blockUntilClosed(conn)
}

func (a *association) clientToTarget() {
	defer a.srv.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		a.mu.Lock()
		a.client = from
		a.mu.Unlock()

		dst, payload, ok := splitDatagram(buf[:n])
		if !ok {
			a.srv.malformedFromClient.Add(1)
			continue
		}
		if a.srv.takeFault(func(f *Faults) *int { return &f.DropOutbound }) {
			a.srv.droppedOut.Add(1)
			continue
		}
		if _, err := a.out.WriteToUDP(payload, dst); err == nil {
			a.srv.datagramsOut.Add(1)
		}
	}
}

func (a *association) targetToClient() {
	defer a.srv.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := a.out.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if a.srv.takeFault(func(f *Faults) *int { return &f.DropInbound }) {
			a.srv.droppedIn.Add(1)
			continue
		}
		pkt := joinDatagram(from, buf[:n])
		f := a.srv.Faults()
		if f.ReorderInbound > 1 {
			a.hold(pkt, f)
			continue
		}
		a.deliver(pkt, f)
	}
}

// hold collects datagrams into a group and releases the group in reverse.
func (a *association) hold(pkt []byte, f Faults) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.held = append(a.held, pkt)
	if len(a.held) < f.ReorderInbound {
		if len(a.held) == 1 {
			a.flushing = time.AfterFunc(heldFlushAfter, func() { a.flush(f) })
		}
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()
	a.flush(f)
}

func (a *association) flush(f Faults) {
	a.mu.Lock()
	group := a.held
	a.held = nil
	if a.flushing != nil {
		a.flushing.Stop()
		a.flushing = nil
	}
	a.mu.Unlock()
	for i := len(group) - 1; i >= 0; i-- {
		a.deliver(group[i], f)
	}
}

func (a *association) deliver(pkt []byte, f Faults) {
	send := func() {
		client := a.clientAddr()
		if client == nil {
			return
		}
		copies := 1
		if f.DuplicateInbound {
			copies = 2
		}
		for i := 0; i < copies; i++ {
			if _, err := a.relay.WriteToUDP(pkt, client); err == nil {
				a.srv.datagramsIn.Add(1)
			}
		}
	}
	if f.DelayInbound > 0 {
		time.AfterFunc(f.DelayInbound, send)
		return
	}
	send()
}

// splitDatagram parses the RFC 1928 section 7 header of a client datagram.
// Fragments are refused, as most proxies do.
func splitDatagram(b []byte) (*net.UDPAddr, []byte, bool) {
	if len(b) < 4 || b[2] != 0x00 {
		return nil, nil, false
	}
	rest := b[4:]
	var hostLen int
	switch b[3] {
	case 0x01:
		hostLen = net.IPv4len
	case 0x04:
		hostLen = net.IPv6len
	case 0x03:
		if len(rest) < 1 {
			return nil, nil, false
		}
		hostLen = int(rest[0])
		rest = rest[1:]
	default:
		return nil, nil, false
	}
	if len(rest) < hostLen+2 {
		return nil, nil, false
	}
	port := int(binary.BigEndian.Uint16(rest[hostLen:]))
	payload := rest[hostLen+2:]
	if b[3] == 0x03 {
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(string(rest[:hostLen]), strconv.Itoa(port)))
		if err != nil {
			return nil, nil, false
		}
		return addr, payload, true
	}
	return &net.UDPAddr{IP: append(net.IP(nil), rest[:hostLen]...), Port: port}, payload, true
}

func joinDatagram(from *net.UDPAddr, payload []byte) []byte {
	b := make([]byte, 3, 3+1+net.IPv6len+2+len(payload))
	if v4 := from.IP.To4(); v4 != nil {
		b = append(b, 0x01)
		b = append(b, v4...)
	} else {
		b = append(b, 0x04)
		b = append(b, from.IP.To16()...)
	}
	b = append(b, byte(from.Port>>8), byte(from.Port))
	return append(b, payload...)
}
