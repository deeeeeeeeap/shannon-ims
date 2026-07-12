// Package transport provides datagram transport with proxy support,
// modeled after SimAdmin's transport.rs design.
package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// ProxyKind defines the proxy type (reference: SimAdmin transport.rs ProxyKind)
type ProxyKind int

const (
	ProxyDirect             ProxyKind = iota // Direct connection
	ProxySocks5UDPAssociate                  // SOCKS5 UDP ASSOCIATE
)

func (k ProxyKind) String() string {
	switch k {
	case ProxyDirect:
		return "direct"
	case ProxySocks5UDPAssociate:
		return "socks5_udp_associate"
	default:
		return "unknown"
	}
}

// RoutePolicy defines the network routing policy
type RoutePolicy struct {
	Kind     ProxyKind
	Addr     string // SOCKS5 proxy address host:port
	Username string
	Password string
}

// DefaultRoutePolicy returns direct connection policy
func DefaultRoutePolicy() RoutePolicy {
	return RoutePolicy{Kind: ProxyDirect}
}

// ResolvedEndpoint holds a resolved ePDG endpoint
type ResolvedEndpoint struct {
	Host        string
	Port        int
	Addresses   []net.IP
	RoutePolicy RoutePolicy
}

// DatagramTransport is the datagram transport interface (reference: SimAdmin IkeDatagramTransport)
type DatagramTransport interface {
	SendTo(payload []byte, addr *net.UDPAddr) (int, error)
	RecvFrom(buffer []byte) (int, *net.UDPAddr, error)
	Close() error
	LocalAddr() net.Addr
}

type relayAddrProvider interface {
	RelayAddr() *net.UDPAddr
}

// socks5UDPTransport implements DatagramTransport via SOCKS5 UDP ASSOCIATE
type socks5UDPTransport struct {
	mu        sync.Mutex
	proxyAddr string
	username  string
	password  string
	udpConn   *net.UDPConn
	relayAddr *net.UDPAddr
	tcpConn   net.Conn
	closed    bool
}

// NewSocks5UDPTransport creates a SOCKS5 UDP ASSOCIATE transport
func NewSocks5UDPTransport(proxyAddr, username, password string) (DatagramTransport, error) {
	return &socks5UDPTransport{
		proxyAddr: proxyAddr,
		username:  username,
		password:  password,
	}, nil
}

func (s *socks5UDPTransport) establish() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.udpConn != nil && !s.closed {
		return nil
	}

	// Connect SOCKS5 TCP control channel
	dialer := net.Dialer{Timeout: 10 * time.Second}
	tcpConn, err := dialer.Dial("tcp", s.proxyAddr)
	if err != nil {
		return fmt.Errorf("socks5 tcp connect to %s: %w", s.proxyAddr, err)
	}
	s.tcpConn = tcpConn

	// SOCKS5 handshake
	if err := s.socks5Handshake(tcpConn); err != nil {
		tcpConn.Close()
		s.tcpConn = nil
		return err
	}

	// SOCKS5 UDP ASSOCIATE request
	relayAddr, err := s.socks5UDPAssociate(tcpConn)
	if err != nil {
		tcpConn.Close()
		s.tcpConn = nil
		return err
	}
	s.relayAddr = relayAddr

	// Create local UDP socket
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		tcpConn.Close()
		s.tcpConn = nil
		return fmt.Errorf("socks5 udp listen: %w", err)
	}
	s.udpConn = udpConn

	// Background goroutine to detect TCP connection close
	go func() {
		buf := make([]byte, 1)
		tcpConn.Read(buf)
		s.Close()
	}()

	return nil
}

func (s *socks5UDPTransport) socks5Handshake(conn net.Conn) error {
	if s.username != "" || s.password != "" {
		// Username/password auth
		_, err := conn.Write([]byte{0x05, 0x01, 0x02})
		if err != nil {
			return fmt.Errorf("socks5 auth method write: %w", err)
		}
		resp := make([]byte, 2)
		if _, err := conn.Read(resp); err != nil {
			return fmt.Errorf("socks5 auth method read: %w", err)
		}
		if resp[0] != 0x05 || resp[1] != 0x02 {
			return fmt.Errorf("socks5 auth method rejected: %02x %02x", resp[0], resp[1])
		}
		// Send username/password
		auth := []byte{0x01}
		auth = append(auth, byte(len(s.username)))
		auth = append(auth, []byte(s.username)...)
		auth = append(auth, byte(len(s.password)))
		auth = append(auth, []byte(s.password)...)
		if _, err := conn.Write(auth); err != nil {
			return fmt.Errorf("socks5 auth creds write: %w", err)
		}
		authResp := make([]byte, 2)
		if _, err := conn.Read(authResp); err != nil {
			return fmt.Errorf("socks5 auth creds read: %w", err)
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("socks5 auth failed: status %02x", authResp[1])
		}
	} else {
		_, err := conn.Write([]byte{0x05, 0x01, 0x00})
		if err != nil {
			return fmt.Errorf("socks5 no-auth write: %w", err)
		}
		resp := make([]byte, 2)
		if _, err := conn.Read(resp); err != nil {
			return fmt.Errorf("socks5 no-auth read: %w", err)
		}
		if resp[0] != 0x05 || resp[1] != 0x00 {
			return fmt.Errorf("socks5 no-auth rejected: %02x %02x", resp[0], resp[1])
		}
	}
	return nil
}

func (s *socks5UDPTransport) socks5UDPAssociate(conn net.Conn) (*net.UDPAddr, error) {
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("socks5 udp associate write: %w", err)
	}

	resp := make([]byte, 262)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("socks5 udp associate read: %w", err)
	}
	if n < 10 || resp[0] != 0x05 || resp[1] != 0x00 {
		return nil, fmt.Errorf("socks5 udp associate rejected: status %02x", resp[1])
	}

	atype := resp[3]
	var relayIP net.IP
	var relayPort int
	switch atype {
	case 0x01: // IPv4
		relayIP = net.IPv4(resp[4], resp[5], resp[6], resp[7])
		relayPort = int(resp[8])<<8 | int(resp[9])
	case 0x04: // IPv6
		relayIP = make(net.IP, 16)
		copy(relayIP, resp[4:20])
		relayPort = int(resp[20])<<8 | int(resp[21])
	default:
		return nil, fmt.Errorf("socks5 udp associate unknown atype: %02x", atype)
	}

	return &net.UDPAddr{IP: relayIP, Port: relayPort}, nil
}

func (s *socks5UDPTransport) SendTo(payload []byte, addr *net.UDPAddr) (int, error) {
	if err := s.establish(); err != nil {
		return 0, err
	}

	header := []byte{0x00, 0x00, 0x00}
	if ip4 := addr.IP.To4(); ip4 != nil {
		header = append(header, 0x01)
		header = append(header, ip4...)
	} else {
		header = append(header, 0x04)
		header = append(header, addr.IP.To16()...)
	}
	header = append(header, byte(addr.Port>>8), byte(addr.Port&0xFF))

	packet := append(header, payload...)
	return s.udpConn.WriteToUDP(packet, s.relayAddr)
}

func (s *socks5UDPTransport) RecvFrom(buffer []byte) (int, *net.UDPAddr, error) {
	if err := s.establish(); err != nil {
		return 0, nil, err
	}

	n, _, err := s.udpConn.ReadFromUDP(buffer)
	if err != nil {
		return 0, nil, err
	}
	if n < 10 {
		return 0, nil, fmt.Errorf("socks5 udp packet too short: %d bytes", n)
	}

	data := buffer[:n]
	atype := data[3]
	var srcIP net.IP
	var srcPort int
	var headerLen int
	switch atype {
	case 0x01: // IPv4
		srcIP = net.IPv4(data[4], data[5], data[6], data[7])
		srcPort = int(data[8])<<8 | int(data[9])
		headerLen = 10
	case 0x04: // IPv6
		srcIP = make(net.IP, 16)
		copy(srcIP, data[4:20])
		srcPort = int(data[20])<<8 | int(data[21])
		headerLen = 22
	default:
		return 0, nil, fmt.Errorf("socks5 udp unknown atype: %02x", atype)
	}

	payloadLen := n - headerLen
	copy(buffer[:payloadLen], data[headerLen:n])

	return payloadLen, &net.UDPAddr{IP: srcIP, Port: srcPort}, nil
}

func (s *socks5UDPTransport) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	if s.tcpConn != nil {
		s.tcpConn.Close()
	}
	return nil
}

func (s *socks5UDPTransport) LocalAddr() net.Addr {
	if s.udpConn != nil {
		return s.udpConn.LocalAddr()
	}
	return nil
}

func (s *socks5UDPTransport) RelayAddr() *net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.relayAddr == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), s.relayAddr.IP...),
		Port: s.relayAddr.Port,
		Zone: s.relayAddr.Zone,
	}
}

// directUDPTransport implements DatagramTransport with direct UDP
type directUDPTransport struct {
	conn *net.UDPConn
}

// NewDirectUDPTransport creates a direct UDP transport
func NewDirectUDPTransport() (DatagramTransport, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("direct udp listen: %w", err)
	}
	return &directUDPTransport{conn: conn}, nil
}

func (d *directUDPTransport) SendTo(payload []byte, addr *net.UDPAddr) (int, error) {
	return d.conn.WriteToUDP(payload, addr)
}

func (d *directUDPTransport) RecvFrom(buffer []byte) (int, *net.UDPAddr, error) {
	return d.conn.ReadFromUDP(buffer)
}

func (d *directUDPTransport) Close() error {
	return d.conn.Close()
}

func (d *directUDPTransport) LocalAddr() net.Addr {
	return d.conn.LocalAddr()
}

// NewTransportFromRoutePolicy creates a transport based on the route policy
func NewTransportFromRoutePolicy(policy RoutePolicy) (DatagramTransport, error) {
	switch policy.Kind {
	case ProxyDirect:
		return NewDirectUDPTransport()
	case ProxySocks5UDPAssociate:
		return NewSocks5UDPTransport(policy.Addr, policy.Username, policy.Password)
	default:
		return NewDirectUDPTransport()
	}
}

// ResolveEpdgDNS resolves the ePDG address via DNS (reference: SimAdmin epdg.rs)
func ResolveEpdgDNS(ctx context.Context, host string, port int) (ResolvedEndpoint, error) {
	endpoint := ResolvedEndpoint{
		Host:        host,
		Port:        port,
		RoutePolicy: DefaultRoutePolicy(),
	}

	resolver := net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return endpoint, fmt.Errorf("dns resolve %s: %w", host, err)
	}
	for _, ip := range ips {
		endpoint.Addresses = append(endpoint.Addresses, ip.IP)
	}
	if len(endpoint.Addresses) == 0 {
		return endpoint, fmt.Errorf("dns resolve %s: empty address set", host)
	}
	return endpoint, nil
}

// =====================================================
// SOCKS5 TCP CONNECT — for ePDG probes and IMS signaling
// =====================================================

// Socks5TCPDialer returns a dial function that routes TCP through the SOCKS5 proxy.
func Socks5TCPDialer(proxyAddr, username, password string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Connect to SOCKS5 proxy
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy connect %s: %w", proxyAddr, err)
		}

		// SOCKS5 handshake with auth
		if username != "" || password != "" {
			if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5 auth method write: %w", err)
			}
			resp := make([]byte, 2)
			if _, err := conn.Read(resp); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5 auth method read: %w", err)
			}
			if resp[0] != 0x05 || resp[1] != 0x02 {
				conn.Close()
				return nil, fmt.Errorf("socks5 auth method rejected")
			}
			auth := []byte{0x01}
			auth = append(auth, byte(len(username)))
			auth = append(auth, []byte(username)...)
			auth = append(auth, byte(len(password)))
			auth = append(auth, []byte(password)...)
			if _, err := conn.Write(auth); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5 auth write: %w", err)
			}
			authResp := make([]byte, 2)
			if _, err := conn.Read(authResp); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5 auth read: %w", err)
			}
			if authResp[1] != 0x00 {
				conn.Close()
				return nil, fmt.Errorf("socks5 auth failed")
			}
		} else {
			if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5 no-auth write: %w", err)
			}
			resp := make([]byte, 2)
			if _, err := conn.Read(resp); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5 no-auth read: %w", err)
			}
			if resp[0] != 0x05 || resp[1] != 0x00 {
				conn.Close()
				return nil, fmt.Errorf("socks5 no-auth rejected")
			}
		}

		// Parse target address
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 bad target addr %s: %w", addr, err)
		}
		port, err := net.LookupPort("tcp", portStr)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 bad target port %s: %w", portStr, err)
		}

		// Build SOCKS5 CONNECT request
		req := []byte{0x05, 0x01, 0x00}
		if ip := net.ParseIP(host); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				req = append(req, 0x01) // IPv4
				req = append(req, ip4...)
			} else {
				req = append(req, 0x04) // IPv6
				req = append(req, ip.To16()...)
			}
		} else {
			req = append(req, 0x03) // Domain name
			req = append(req, byte(len(host)))
			req = append(req, []byte(host)...)
		}
		req = append(req, byte(port>>8), byte(port&0xFF))

		if _, err := conn.Write(req); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 connect write: %w", err)
		}

		connectResp := make([]byte, 262)
		n, err := conn.Read(connectResp)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 connect read: %w", err)
		}
		if n < 2 || connectResp[0] != 0x05 || connectResp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5 connect rejected: status=0x%02x", connectResp[1])
		}

		return conn, nil
	}
}
