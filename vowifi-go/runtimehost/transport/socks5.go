package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 wire constants (RFC 1928, RFC 1929).
const (
	socks5Version = 0x05

	// Socks5AuthNone is the "no authentication required" method.
	Socks5AuthNone byte = 0x00
	// Socks5AuthUserPassword is the RFC 1929 username/password method.
	Socks5AuthUserPassword byte = 0x02

	socks5AuthNoAcceptable byte = 0xFF
	socks5UserPassVersion  byte = 0x01

	socks5CmdConnect      byte = 0x01
	socks5CmdUDPAssociate byte = 0x03

	socks5AtypIPv4   byte = 0x01
	socks5AtypDomain byte = 0x03
	socks5AtypIPv6   byte = 0x04
)

// DefaultSocks5Timeout bounds the TCP connect to the proxy and, separately,
// every request/reply exchange on the control connection.
const DefaultSocks5Timeout = 10 * time.Second

// Socks5Stage names the step of the exchange that failed.
type Socks5Stage string

const (
	Socks5StageConnect   Socks5Stage = "tcp_connect"
	Socks5StageHandshake Socks5Stage = "handshake"
	Socks5StageRequest   Socks5Stage = "request"
)

// Socks5Reason classifies a failure so callers can explain it to an operator
// without matching on message text.
type Socks5Reason string

const (
	// Socks5ReasonIO: the connection failed, timed out or was closed by the peer.
	Socks5ReasonIO Socks5Reason = "io"
	// Socks5ReasonNotSocks5: the peer answered with another protocol version.
	Socks5ReasonNotSocks5 Socks5Reason = "not_socks5"
	// Socks5ReasonNoAcceptableMethod: the proxy refused every offered method.
	Socks5ReasonNoAcceptableMethod Socks5Reason = "no_acceptable_method"
	// Socks5ReasonCredentialsRequired: the proxy wants credentials, none are configured.
	Socks5ReasonCredentialsRequired Socks5Reason = "credentials_required"
	// Socks5ReasonUnsupportedMethod: the proxy selected a method that was not offered.
	Socks5ReasonUnsupportedMethod Socks5Reason = "unsupported_method"
	// Socks5ReasonAuthRejected: the proxy rejected the username/password.
	Socks5ReasonAuthRejected Socks5Reason = "auth_rejected"
	// Socks5ReasonInvalidCredentials: the credentials cannot be encoded (RFC 1929 limits).
	Socks5ReasonInvalidCredentials Socks5Reason = "invalid_credentials"
	// Socks5ReasonRequestRejected: the proxy answered the request with a failure code.
	Socks5ReasonRequestRejected Socks5Reason = "request_rejected"
	// Socks5ReasonMalformedReply: the reply cannot be used (bad address, port 0, ...).
	Socks5ReasonMalformedReply Socks5Reason = "malformed_reply"
	// Socks5ReasonInvalidTarget: the requested destination cannot be encoded.
	Socks5ReasonInvalidTarget Socks5Reason = "invalid_target"
)

// Socks5Error describes a failed SOCKS5 exchange.
type Socks5Error struct {
	Stage  Socks5Stage
	Reason Socks5Reason
	// Op is the step in progress, e.g. "UDP ASSOCIATE" or "read method selection".
	Op string
	// Code is the byte the proxy answered with, when it answered: the reply
	// code, the authentication status, the selected method or the version.
	Code byte
	Err  error
}

func (e *Socks5Error) Error() string {
	prefix := "socks5 " + string(e.Stage)
	if e.Op != "" {
		prefix += ": " + e.Op
	}
	switch e.Reason {
	case Socks5ReasonNotSocks5:
		return fmt.Sprintf("%s: unexpected protocol version 0x%02x, not a SOCKS5 server", prefix, e.Code)
	case Socks5ReasonNoAcceptableMethod:
		return prefix + ": proxy accepted none of the offered authentication methods (0xff)"
	case Socks5ReasonCredentialsRequired:
		return prefix + ": proxy requires username/password but none is configured"
	case Socks5ReasonUnsupportedMethod:
		return fmt.Sprintf("%s: proxy selected authentication method 0x%02x that was not offered", prefix, e.Code)
	case Socks5ReasonAuthRejected:
		return fmt.Sprintf("%s: username/password rejected (status 0x%02x)", prefix, e.Code)
	case Socks5ReasonRequestRejected:
		return fmt.Sprintf("%s rejected: %s (0x%02x)", prefix, socks5ReplyText(e.Code), e.Code)
	}
	if e.Err != nil {
		return prefix + ": " + e.Err.Error()
	}
	return prefix + ": " + string(e.Reason)
}

func (e *Socks5Error) Unwrap() error { return e.Err }

// PeerClosed reports whether the proxy closed the connection at this step
// instead of answering.
func (e *Socks5Error) PeerClosed() bool {
	return e != nil && e.Reason == Socks5ReasonIO &&
		(errors.Is(e.Err, io.EOF) || errors.Is(e.Err, io.ErrUnexpectedEOF))
}

func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unassigned reply code"
	}
}

// Socks5Addr is an address as carried in a SOCKS5 reply or datagram header:
// an IP or a domain name, plus a port.
type Socks5Addr struct {
	IP     net.IP
	Domain string
	Port   int
}

func (a Socks5Addr) String() string {
	host := a.Domain
	if host == "" && a.IP != nil {
		host = a.IP.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(a.Port))
}

// UDPAddr returns the address as a UDP endpoint. The IP is nil when the
// address carries a domain name.
func (a Socks5Addr) UDPAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: a.IP, Port: a.Port}
}

func appendSocks5Addr(b []byte, a Socks5Addr) ([]byte, error) {
	if a.Port < 0 || a.Port > 65535 {
		return nil, fmt.Errorf("port %d out of range", a.Port)
	}
	switch {
	case a.Domain != "":
		if len(a.Domain) > 255 {
			return nil, fmt.Errorf("domain name longer than 255 bytes")
		}
		b = append(b, socks5AtypDomain, byte(len(a.Domain)))
		b = append(b, a.Domain...)
	case a.IP.To4() != nil:
		b = append(b, socks5AtypIPv4)
		b = append(b, a.IP.To4()...)
	case len(a.IP) == net.IPv6len:
		b = append(b, socks5AtypIPv6)
		b = append(b, a.IP...)
	default:
		return nil, errors.New("address has neither an IP nor a domain name")
	}
	return append(b, byte(a.Port>>8), byte(a.Port)), nil
}

func readSocks5Addr(r io.Reader, atyp byte) (Socks5Addr, error) {
	var addr Socks5Addr
	var hostLen int
	switch atyp {
	case socks5AtypIPv4:
		hostLen = net.IPv4len
	case socks5AtypIPv6:
		hostLen = net.IPv6len
	case socks5AtypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return addr, err
		}
		hostLen = int(l[0])
	default:
		return addr, fmt.Errorf("unknown address type 0x%02x", atyp)
	}
	buf := make([]byte, hostLen+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return addr, err
	}
	if atyp == socks5AtypDomain {
		addr.Domain = string(buf[:hostLen])
	} else {
		addr.IP = net.IP(buf[:hostLen])
	}
	addr.Port = int(binary.BigEndian.Uint16(buf[hostLen:]))
	return addr, nil
}

// Socks5Options configures a control connection.
type Socks5Options struct {
	Username string
	Password string
	// Timeout bounds the TCP connect and every exchange on the control
	// connection. Zero means DefaultSocks5Timeout.
	Timeout time.Duration
	// Dial replaces the TCP dialer. Optional.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (o Socks5Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return DefaultSocks5Timeout
}

func (o Socks5Options) hasCredentials() bool {
	return o.Username != "" || o.Password != ""
}

// Socks5Conn is a SOCKS5 control connection that completed method negotiation.
type Socks5Conn struct {
	conn               net.Conn
	method             byte
	credentialsIgnored bool
	timeout            time.Duration
}

// DialSocks5 connects to proxyAddr and negotiates authentication.
//
// With credentials configured only username/password is offered first, so a
// proxy that supports it always authenticates the session. A proxy that
// refuses every offered method (it has no username/password support) is
// retried once on a fresh connection without authentication; CredentialsIgnored
// then reports that the configured credentials were not used.
func DialSocks5(ctx context.Context, proxyAddr string, opts Socks5Options) (*Socks5Conn, error) {
	offers := [][]byte{{Socks5AuthNone}}
	if opts.hasCredentials() {
		if len(opts.Username) > 255 || len(opts.Password) > 255 {
			return nil, &Socks5Error{
				Stage:  Socks5StageHandshake,
				Reason: Socks5ReasonInvalidCredentials,
				Err:    errors.New("username or password longer than 255 bytes"),
			}
		}
		offers = [][]byte{{Socks5AuthUserPassword}, {Socks5AuthNone}}
	}

	var refused error
	for _, offer := range offers {
		c, err := dialSocks5Once(ctx, proxyAddr, opts, offer)
		if err == nil {
			c.credentialsIgnored = opts.hasCredentials() && c.method == Socks5AuthNone
			return c, nil
		}
		var se *Socks5Error
		if refused == nil && errors.As(err, &se) && se.Reason == Socks5ReasonNoAcceptableMethod {
			refused = err
			continue
		}
		if refused != nil {
			// The fallback did not help; the original refusal is the useful error.
			return nil, refused
		}
		return nil, err
	}
	return nil, refused
}

func dialSocks5Once(ctx context.Context, proxyAddr string, opts Socks5Options, methods []byte) (*Socks5Conn, error) {
	timeout := opts.timeout()
	dial := opts.Dial
	if dial == nil {
		d := &net.Dialer{
			Timeout: timeout,
			// The control connection carries no traffic after the handshake but
			// must stay up for as long as the UDP association is used: probe it
			// so a dead proxy or an expired NAT mapping is noticed promptly.
			KeepAliveConfig: net.KeepAliveConfig{
				Enable:   true,
				Idle:     15 * time.Second,
				Interval: 5 * time.Second,
				Count:    3,
			},
		}
		dial = d.DialContext
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	conn, err := dial(dialCtx, "tcp", proxyAddr)
	cancel()
	if err != nil {
		return nil, &Socks5Error{Stage: Socks5StageConnect, Reason: Socks5ReasonIO, Err: err}
	}

	c := &Socks5Conn{conn: conn, timeout: timeout}
	err = c.exchange(ctx, Socks5StageHandshake, func() error {
		method, err := socks5Negotiate(conn, methods, opts.Username, opts.Password)
		c.method = method
		return err
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

// exchange runs one request/reply step with the connection deadline bounded
// by the timeout and by ctx, and unblocks the I/O as soon as ctx is cancelled.
func (c *Socks5Conn) exchange(ctx context.Context, stage Socks5Stage, step func() error) error {
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.conn.SetDeadline(deadline); err != nil {
		return &Socks5Error{Stage: stage, Reason: Socks5ReasonIO, Op: "set deadline", Err: err}
	}
	stop := context.AfterFunc(ctx, func() { _ = c.conn.SetDeadline(time.Unix(1, 0)) })
	err := step()
	if !stop() {
		// ctx was cancelled while the step ran. The callback may have poisoned
		// the deadline already, so the connection is unusable whatever the
		// step returned.
		return &Socks5Error{Stage: stage, Reason: Socks5ReasonIO, Op: "cancelled", Err: context.Cause(ctx)}
	}
	if err != nil {
		return err
	}
	if err := c.conn.SetDeadline(time.Time{}); err != nil {
		return &Socks5Error{Stage: stage, Reason: Socks5ReasonIO, Op: "clear deadline", Err: err}
	}
	return nil
}

func socks5Negotiate(rw io.ReadWriter, methods []byte, username, password string) (byte, error) {
	fail := func(reason Socks5Reason, op string, code byte, err error) (byte, error) {
		return 0, &Socks5Error{Stage: Socks5StageHandshake, Reason: reason, Op: op, Code: code, Err: err}
	}

	greeting := append([]byte{socks5Version, byte(len(methods))}, methods...)
	if _, err := rw.Write(greeting); err != nil {
		return fail(Socks5ReasonIO, "send method offer", 0, err)
	}
	var selection [2]byte
	if _, err := io.ReadFull(rw, selection[:]); err != nil {
		return fail(Socks5ReasonIO, "read method selection", 0, err)
	}
	if selection[0] != socks5Version {
		return fail(Socks5ReasonNotSocks5, "method selection", selection[0], nil)
	}

	method := selection[1]
	if method == socks5AuthNoAcceptable {
		return fail(Socks5ReasonNoAcceptableMethod, "method selection", method, nil)
	}
	offered := false
	for _, m := range methods {
		if m == method {
			offered = true
			break
		}
	}
	if !offered {
		if method == Socks5AuthUserPassword {
			return fail(Socks5ReasonCredentialsRequired, "method selection", method, nil)
		}
		return fail(Socks5ReasonUnsupportedMethod, "method selection", method, nil)
	}
	if method != Socks5AuthUserPassword {
		return method, nil
	}

	auth := make([]byte, 0, 3+len(username)+len(password))
	auth = append(auth, socks5UserPassVersion, byte(len(username)))
	auth = append(auth, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if _, err := rw.Write(auth); err != nil {
		return fail(Socks5ReasonIO, "send credentials", 0, err)
	}
	var status [2]byte
	if _, err := io.ReadFull(rw, status[:]); err != nil {
		return fail(Socks5ReasonIO, "read authentication status", 0, err)
	}
	if status[1] != 0x00 {
		return fail(Socks5ReasonAuthRejected, "authentication", status[1], nil)
	}
	return method, nil
}

// AuthMethod returns the authentication method the proxy selected.
func (c *Socks5Conn) AuthMethod() byte { return c.method }

// CredentialsIgnored reports that credentials are configured but the proxy
// does not support username/password, so the session is unauthenticated.
func (c *Socks5Conn) CredentialsIgnored() bool { return c.credentialsIgnored }

// Conn returns the underlying connection. After a successful Connect it is
// the tunnel to the target.
func (c *Socks5Conn) Conn() net.Conn { return c.conn }

// Close closes the control connection, which also ends a UDP association
// made on it (RFC 1928 section 7).
func (c *Socks5Conn) Close() error { return c.conn.Close() }

func (c *Socks5Conn) request(ctx context.Context, cmd byte, op string, dst Socks5Addr) (Socks5Addr, error) {
	req, err := appendSocks5Addr([]byte{socks5Version, cmd, 0x00}, dst)
	if err != nil {
		return Socks5Addr{}, &Socks5Error{Stage: Socks5StageRequest, Reason: Socks5ReasonInvalidTarget, Op: op, Err: err}
	}
	var bound Socks5Addr
	err = c.exchange(ctx, Socks5StageRequest, func() error {
		if _, err := c.conn.Write(req); err != nil {
			return &Socks5Error{Stage: Socks5StageRequest, Reason: Socks5ReasonIO, Op: op, Err: err}
		}
		var head [4]byte
		if _, err := io.ReadFull(c.conn, head[:]); err != nil {
			return &Socks5Error{Stage: Socks5StageRequest, Reason: Socks5ReasonIO, Op: op, Err: err}
		}
		if head[0] != socks5Version {
			return &Socks5Error{Stage: Socks5StageRequest, Reason: Socks5ReasonNotSocks5, Op: op, Code: head[0]}
		}
		if head[1] != 0x00 {
			return &Socks5Error{Stage: Socks5StageRequest, Reason: Socks5ReasonRequestRejected, Op: op, Code: head[1]}
		}
		// Read the bound address exactly: a short read would leave reply bytes
		// in the stream and a long one would swallow tunnelled data.
		addr, err := readSocks5Addr(c.conn, head[3])
		if err != nil {
			reason := Socks5ReasonMalformedReply
			var netErr net.Error
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &netErr) {
				reason = Socks5ReasonIO
			}
			return &Socks5Error{Stage: Socks5StageRequest, Reason: reason, Op: op, Err: err}
		}
		bound = addr
		return nil
	})
	return bound, err
}

// Connect asks the proxy to open a TCP connection to addr ("host:port"). On
// success the control connection becomes the tunnel; take it with Conn.
func (c *Socks5Conn) Connect(ctx context.Context, addr string) error {
	const op = "CONNECT"
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return &Socks5Error{Stage: Socks5StageRequest, Reason: Socks5ReasonInvalidTarget, Op: op, Err: err}
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		return &Socks5Error{Stage: Socks5StageRequest, Reason: Socks5ReasonInvalidTarget, Op: op, Err: err}
	}
	dst := Socks5Addr{Port: port}
	if ip := net.ParseIP(host); ip != nil {
		dst.IP = ip
	} else if host != "" {
		dst.Domain = host
	} else {
		return &Socks5Error{Stage: Socks5StageRequest, Reason: Socks5ReasonInvalidTarget, Op: op, Err: errors.New("empty host")}
	}
	_, err = c.request(ctx, socks5CmdConnect, op, dst)
	return err
}

// Socks5RelayAdjustment says how the relay address differs from what the
// proxy advertised.
type Socks5RelayAdjustment string

const (
	// Socks5RelayAsAdvertised: the advertised address is used unchanged.
	Socks5RelayAsAdvertised Socks5RelayAdjustment = ""
	// Socks5RelayUnspecified: the proxy advertised 0.0.0.0 or ::, meaning
	// "the address you reached me on"; the proxy's own address is used.
	Socks5RelayUnspecified Socks5RelayAdjustment = "unspecified"
	// Socks5RelayLoopback: a remote proxy advertised a loopback address, which
	// can only be its own; the proxy's address is used.
	Socks5RelayLoopback Socks5RelayAdjustment = "loopback"
	// Socks5RelayDomain: the proxy advertised a domain name that was resolved.
	Socks5RelayDomain Socks5RelayAdjustment = "domain"
	// Socks5RelayDomainUnresolved: the advertised domain name did not resolve;
	// the proxy's address is used.
	Socks5RelayDomainUnresolved Socks5RelayAdjustment = "domain_unresolved"
	// Socks5RelayPrivate: a proxy reached on a public address advertised a
	// private one. It is used as advertised, but datagrams only arrive if
	// that network is routable from here.
	Socks5RelayPrivate Socks5RelayAdjustment = "private"
)

// Socks5Relay is the UDP relay endpoint of an association.
type Socks5Relay struct {
	// Addr is where encapsulated datagrams are sent.
	Addr *net.UDPAddr
	// Advertised is the address from the UDP ASSOCIATE reply.
	Advertised Socks5Addr
	// Adjustment explains any difference between the two.
	Adjustment Socks5RelayAdjustment
}

// UDPAssociate asks the proxy for a UDP relay. The association lasts until
// the control connection is closed.
func (c *Socks5Conn) UDPAssociate(ctx context.Context) (Socks5Relay, error) {
	const op = "UDP ASSOCIATE"
	proxyIP, zone := remoteIP(c.conn)

	// The client address is declared as unknown: behind NAT the proxy never
	// sees the local address, and proxies restrict the relay to the control
	// connection's source address either way.
	client := Socks5Addr{IP: net.IPv4zero.To4()}
	if proxyIP != nil && proxyIP.To4() == nil {
		client.IP = net.IPv6unspecified
	}
	bound, err := c.request(ctx, socks5CmdUDPAssociate, op, client)
	if err != nil {
		return Socks5Relay{}, err
	}
	return normalizeSocks5Relay(bound, proxyIP, zone, func(host string) net.IP {
		return resolveRelayDomain(ctx, host, proxyIP, c.timeout)
	})
}

// normalizeSocks5Relay turns the address a proxy advertised for its relay
// into one datagrams can be sent to. proxyIP and zone describe the address
// the control connection reached the proxy on.
func normalizeSocks5Relay(bound Socks5Addr, proxyIP net.IP, zone string, resolve func(host string) net.IP) (Socks5Relay, error) {
	const op = "UDP ASSOCIATE"
	relay := Socks5Relay{Advertised: bound}
	malformed := func(err error) (Socks5Relay, error) {
		return Socks5Relay{Advertised: bound}, &Socks5Error{Stage: Socks5StageRequest, Reason: Socks5ReasonMalformedReply, Op: op, Err: err}
	}
	if bound.Port == 0 {
		return malformed(errors.New("proxy advertised relay port 0"))
	}
	if bound.Domain == "" && len(bound.IP) == 0 {
		return malformed(errors.New("proxy advertised an empty relay host"))
	}

	ip := bound.IP
	switch {
	case bound.Domain != "":
		resolved := resolve(bound.Domain)
		switch {
		case resolved != nil:
			ip, zone = resolved, ""
			relay.Adjustment = Socks5RelayDomain
		case proxyIP != nil:
			ip = proxyIP
			relay.Adjustment = Socks5RelayDomainUnresolved
		default:
			return malformed(fmt.Errorf("relay host %q does not resolve", bound.Domain))
		}
	case ip.IsUnspecified():
		if proxyIP == nil {
			return malformed(errors.New("proxy advertised an unspecified relay address"))
		}
		ip = proxyIP
		relay.Adjustment = Socks5RelayUnspecified
	case ip.IsLoopback() && proxyIP != nil && !proxyIP.IsLoopback():
		ip = proxyIP
		relay.Adjustment = Socks5RelayLoopback
	default:
		zone = ""
		if ip.IsPrivate() && proxyIP != nil && !proxyIP.IsPrivate() && !proxyIP.IsLoopback() && !proxyIP.IsLinkLocalUnicast() {
			relay.Adjustment = Socks5RelayPrivate
		}
	}
	relay.Addr = &net.UDPAddr{IP: ip, Port: bound.Port, Zone: zone}
	return relay, nil
}

func remoteIP(conn net.Conn) (net.IP, string) {
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok && tcp != nil && tcp.IP != nil {
		return tcp.IP, tcp.Zone
	}
	return nil, ""
}

func resolveRelayDomain(ctx context.Context, host string, proxyIP net.IP, timeout time.Duration) net.IP {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	// Prefer the family the proxy was reached on: that path is known to work.
	wantV4 := proxyIP == nil || proxyIP.To4() != nil
	for _, a := range addrs {
		if (a.IP.To4() != nil) == wantV4 {
			return a.IP
		}
	}
	return addrs[0].IP
}

// ErrSocks5Fragment is returned for a datagram that is part of a fragmented
// sequence. Reassembly is optional in RFC 1928 and not implemented, so such
// datagrams must be dropped.
var ErrSocks5Fragment = errors.New("socks5: fragmented datagram")

// EncodeSocks5UDPDatagram wraps payload in the RFC 1928 section 7 header
// addressed to dst.
func EncodeSocks5UDPDatagram(dst *net.UDPAddr, payload []byte) ([]byte, error) {
	if dst == nil || dst.IP == nil {
		return nil, errors.New("socks5: datagram destination is required")
	}
	b := make([]byte, 3, 3+1+net.IPv6len+2+len(payload))
	b, err := appendSocks5Addr(b, Socks5Addr{IP: dst.IP, Port: dst.Port})
	if err != nil {
		return nil, fmt.Errorf("socks5: datagram destination: %w", err)
	}
	return append(b, payload...), nil
}

// DecodeSocks5UDPDatagram splits a datagram received from a relay into the
// address it came from and its payload. The payload aliases datagram.
func DecodeSocks5UDPDatagram(datagram []byte) (Socks5Addr, []byte, error) {
	var src Socks5Addr
	if len(datagram) < 4 {
		return src, nil, io.ErrUnexpectedEOF
	}
	if datagram[2] != 0x00 {
		return src, nil, ErrSocks5Fragment
	}
	rest := datagram[4:]
	var hostLen int
	switch datagram[3] {
	case socks5AtypIPv4:
		hostLen = net.IPv4len
	case socks5AtypIPv6:
		hostLen = net.IPv6len
	case socks5AtypDomain:
		if len(rest) < 1 {
			return src, nil, io.ErrUnexpectedEOF
		}
		hostLen = int(rest[0])
		rest = rest[1:]
	default:
		return src, nil, fmt.Errorf("socks5: unknown address type 0x%02x", datagram[3])
	}
	if len(rest) < hostLen+2 {
		return src, nil, io.ErrUnexpectedEOF
	}
	if datagram[3] == socks5AtypDomain {
		src.Domain = string(rest[:hostLen])
	} else {
		src.IP = append(net.IP(nil), rest[:hostLen]...)
	}
	src.Port = int(binary.BigEndian.Uint16(rest[hostLen:]))
	return src, rest[hostLen+2:], nil
}
