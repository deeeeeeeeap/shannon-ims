// Package transport provides datagram transport with proxy support,
// modeled after SimAdmin's transport.rs design.
package transport

import (
	"context"
	"fmt"
	"net"
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

// Socks5TCPDialer returns a dial function that opens TCP connections through
// the SOCKS5 proxy with CONNECT. Cancelling ctx aborts the proxy handshake.
func Socks5TCPDialer(proxyAddr, username, password string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil, fmt.Errorf("socks5 connect: unsupported network %q", network)
		}
		proxy, err := DialSocks5(ctx, proxyAddr, Socks5Options{Username: username, Password: password})
		if err != nil {
			return nil, err
		}
		if err := proxy.Connect(ctx, addr); err != nil {
			_ = proxy.Close()
			return nil, err
		}
		return proxy.Conn(), nil
	}
}
