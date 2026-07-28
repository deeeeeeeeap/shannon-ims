package imscore

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

type scriptedRegisterIMSNetwork struct {
	mu         sync.Mutex
	transports []string
	dial       func(string) (net.Conn, error)
}

func (n *scriptedRegisterIMSNetwork) DialContext(_ context.Context, _ string, _ net.Addr, transport string, _ DialOptions) (net.Conn, error) {
	n.mu.Lock()
	n.transports = append(n.transports, transport)
	n.mu.Unlock()
	return n.dial(transport)
}

func (*scriptedRegisterIMSNetwork) HasLocalIP([]byte) bool { return false }
func (*scriptedRegisterIMSNetwork) ListenPacket(context.Context, string, net.Addr) (net.PacketConn, error) {
	return nil, nil
}
func (*scriptedRegisterIMSNetwork) ListenTCP(context.Context, *net.TCPAddr) (net.Listener, error) {
	return nil, nil
}
func (*scriptedRegisterIMSNetwork) LocalIP() []byte { return nil }
func (*scriptedRegisterIMSNetwork) ResolveIP(context.Context, string, bool) ([]byte, error) {
	return nil, nil
}

func (n *scriptedRegisterIMSNetwork) dialedTransports() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.transports...)
}

type immediateRegisterTimeoutConn struct{}

func (*immediateRegisterTimeoutConn) Read([]byte) (int, error)         { return 0, registerTimeoutError{} }
func (*immediateRegisterTimeoutConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*immediateRegisterTimeoutConn) Close() error                     { return nil }
func (*immediateRegisterTimeoutConn) LocalAddr() net.Addr              { return registerTestAddr("local") }
func (*immediateRegisterTimeoutConn) RemoteAddr() net.Addr             { return registerTestAddr("remote") }
func (*immediateRegisterTimeoutConn) SetDeadline(time.Time) error      { return nil }
func (*immediateRegisterTimeoutConn) SetReadDeadline(time.Time) error  { return nil }
func (*immediateRegisterTimeoutConn) SetWriteDeadline(time.Time) error { return nil }

type registerTimeoutError struct{}

func (registerTimeoutError) Error() string   { return "synthetic register timeout" }
func (registerTimeoutError) Timeout() bool   { return true }
func (registerTimeoutError) Temporary() bool { return true }

type registerTestAddr string

func (a registerTestAddr) Network() string { return "synthetic" }
func (a registerTestAddr) String() string  { return string(a) }

type syntheticAuthTimeoutAKA struct {
	calls atomic.Int32
}

func (p *syntheticAuthTimeoutAKA) CalculateAKA([]byte, []byte) (sim.AKAResult, error) {
	p.calls.Add(1)
	return sim.AKAResult{}, fmt.Errorf("synthetic authentication timeout")
}

func TestGenericRegisterFallsBackFromUDPTimeoutToTCP(t *testing.T) {
	serverErr := make(chan error, 1)
	network := &scriptedRegisterIMSNetwork{}
	network.dial = func(transport string) (net.Conn, error) {
		if transport == "udp" {
			return &immediateRegisterTimeoutConn{}, nil
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			req, err := readRegisterSessionTestRequest(bufio.NewReader(server))
			if err == nil {
				err = writeRegisterSessionTestResponse(server, req, sip.StatusUnauthorized, "Unauthorized", false)
			}
			serverErr <- err
		}()
		return client, nil
	}

	cfg := registerSessionTestConfig()
	cfg.CarrierBehavior = policy.Default3GPPBehavior()
	cfg.LocalIP = net.ParseIP("192.0.2.2")
	cfg.PCSCFAddr = "192.0.2.3:5060"
	cfg.TransportPCSCFAddr = cfg.PCSCFAddr
	service := &Service{
		imsCfg:  IMSConfig{Transport: "auto"},
		cfg:     cfg,
		network: network,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := service.registerWithTransportCandidates(ctx); err == nil {
		t.Fatal("REGISTER unexpectedly succeeded without an authentication challenge")
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("synthetic TCP registrar error type %T", err)
	}
	if got, want := network.dialedTransports(), []string{"udp", "tcp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dialed transports = %v, want %v", got, want)
	}
}

func TestGenericRegisterDoesNotFallbackAfterAuthenticationResponse(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reason string
	}{
		{name: "401", status: sip.StatusUnauthorized, reason: "Unauthorized"},
		{name: "407", status: sip.StatusProxyAuthRequired, reason: "Proxy Authentication Required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverErr := make(chan error, 1)
			network := &scriptedRegisterIMSNetwork{}
			network.dial = func(transport string) (net.Conn, error) {
				if transport != "udp" {
					return nil, fmt.Errorf("unexpected transport after authentication response")
				}
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					req, err := readRegisterSessionTestRequest(bufio.NewReader(server))
					if err == nil {
						err = writeRegisterSessionTestResponse(server, req, tt.status, tt.reason, false)
					}
					serverErr <- err
				}()
				return client, nil
			}

			cfg := registerSessionTestConfig()
			cfg.CarrierBehavior = policy.Default3GPPBehavior()
			cfg.LocalIP = net.ParseIP("192.0.2.2")
			cfg.PCSCFAddr = "192.0.2.3:5060"
			cfg.TransportPCSCFAddr = cfg.PCSCFAddr
			service := &Service{
				imsCfg:  IMSConfig{Transport: "auto"},
				cfg:     cfg,
				network: network,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := service.registerWithTransportCandidates(ctx); err == nil {
				t.Fatal("REGISTER unexpectedly succeeded without a complete authentication challenge")
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("synthetic UDP registrar error type %T", err)
			}
			if got, want := network.dialedTransports(), []string{"udp"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("dialed transports = %v, want %v", got, want)
			}
		})
	}
}

func TestGenericRegisterAuthenticationFailureDoesNotAdvanceCandidate(t *testing.T) {
	for _, status := range []int{sip.StatusUnauthorized, sip.StatusProxyAuthRequired} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			serverErr := make(chan error, 1)
			var dialCount int
			network := &scriptedRegisterIMSNetwork{}
			network.dial = func(string) (net.Conn, error) {
				dialCount++
				if dialCount > 1 {
					return nil, fmt.Errorf("unexpected registrar candidate fallback")
				}
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					req, err := readRegisterSessionTestRequest(bufio.NewReader(server))
					if err != nil {
						serverErr <- err
						return
					}
					response := sip.NewResponseFromRequest(req, status, "Authentication Required", nil)
					headerName := "WWW-Authenticate"
					if status == sip.StatusProxyAuthRequired {
						headerName = "Proxy-Authenticate"
					}
					nonce := base64.StdEncoding.EncodeToString(make([]byte, 32))
					response.AppendHeader(sip.NewHeader(headerName, fmt.Sprintf(`Digest realm="ims.example.invalid", nonce="%s", algorithm=AKAv1-MD5`, nonce)))
					_, err = io.WriteString(server, response.String())
					if err != nil && !errors.Is(err, io.ErrClosedPipe) {
						serverErr <- err
						return
					}
					serverErr <- nil
				}()
				return client, nil
			}

			cfg := registerSessionTestConfig()
			cfg.CarrierBehavior = policy.Default3GPPBehavior()
			aka := &syntheticAuthTimeoutAKA{}
			cfg.AKA = aka
			service := &Service{cfg: cfg, network: network}
			candidates := []registerAttemptCandidate{
				{Registrar: "192.0.2.3:5060", Gateway: "192.0.2.3:5060"},
				{Registrar: "192.0.2.4:5060", Gateway: "192.0.2.4:5060"},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := service.attemptRegisterMode(ctx, "udp", candidates); err == nil {
				t.Fatal("REGISTER unexpectedly succeeded after authentication failure")
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			if got := len(network.dialedTransports()); got != 1 {
				t.Fatalf("registrar dial count = %d, want 1", got)
			}
			if got := aka.calls.Load(); got != 1 {
				t.Fatalf("authentication entry count = %d, want 1", got)
			}
		})
	}
}
