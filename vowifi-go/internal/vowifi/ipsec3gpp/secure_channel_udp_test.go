package ipsec3gpp

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestSecureChannelUDPTransportsSIPOverESPForIPv4AndIPv6(t *testing.T) {
	tests := []struct {
		name   string
		client net.IP
		server net.IP
	}{
		{name: "IPv4", client: net.ParseIP("10.0.0.2"), server: net.ParseIP("10.0.0.3")},
		{name: "IPv6", client: net.ParseIP("2001:db8::2"), server: net.ParseIP("2001:db8::3")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientPolicy := secureChannelUDPTestPolicy(t, tt.client, tt.server)
			serverPolicy := reverseSecureChannelUDPTestPolicy(clientPolicy)
			clientTransport, err := NewTransport(clientPolicy)
			if err != nil {
				t.Fatalf("NewTransport(client): %v", err)
			}
			serverTransport, err := NewTransport(serverPolicy)
			if err != nil {
				t.Fatalf("NewTransport(server): %v", err)
			}

			clientRaw, serverRaw := net.Pipe()
			client := WrapSecureChannelUDP(clientRaw, clientTransport, clientPolicy)
			server := WrapSecureChannelUDP(serverRaw, serverTransport, serverPolicy)
			defer client.Close()
			defer server.Close()

			want := []byte("REGISTER sip:ims.example.invalid SIP/2.0\r\nContent-Length: 0\r\n\r\n")
			writeErr := make(chan error, 1)
			go func() {
				_, err := client.Write(want)
				writeErr <- err
			}()

			if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			buf := make([]byte, 4096)
			n, err := server.Read(buf)
			if err != nil {
				t.Fatalf("server Read: %v", err)
			}
			if !bytes.Equal(buf[:n], want) {
				t.Fatalf("SIP payload changed: got %q want %q", buf[:n], want)
			}
			if err := <-writeErr; err != nil {
				t.Fatalf("client Write: %v", err)
			}
		})
	}
}

func TestSecureChannelUDPWriteServerFlowUsesFlowSPorts(t *testing.T) {
	clientPolicy := secureChannelUDPTestPolicy(t, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3"))
	serverPolicy := reverseSecureChannelUDPTestPolicy(clientPolicy)
	clientTransport, err := NewTransport(clientPolicy)
	if err != nil {
		t.Fatalf("NewTransport(client): %v", err)
	}
	serverTransport, err := NewTransport(serverPolicy)
	if err != nil {
		t.Fatalf("NewTransport(server): %v", err)
	}
	raw := &secureChannelCaptureConn{writes: make(chan []byte, 1)}
	client := WrapSecureChannelUDP(raw, clientTransport, clientPolicy)

	want := []byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")
	if _, err := client.WriteServerFlow(want); err != nil {
		t.Fatalf("WriteServerFlow: %v", err)
	}
	encrypted := <-raw.writes
	plain, err := serverTransport.TransformInbound(encrypted)
	if err != nil {
		t.Fatalf("TransformInbound: %v", err)
	}
	parsed, err := parseIPPacket(plain)
	if err != nil {
		t.Fatalf("parseIPPacket: %v", err)
	}
	if parsed.nextHeader != ipProtoUDP {
		t.Fatalf("next header = %d, want UDP", parsed.nextHeader)
	}
	if parsed.srcPort != clientPolicy.FlowS.LocalPort || parsed.dstPort != clientPolicy.FlowS.RemotePort {
		t.Fatalf("UDP ports = %d->%d, want FlowS %d->%d", parsed.srcPort, parsed.dstPort, clientPolicy.FlowS.LocalPort, clientPolicy.FlowS.RemotePort)
	}
	payload, err := parseUDPPayload(parsed.transportPayload)
	if err != nil {
		t.Fatalf("parseUDPPayload: %v", err)
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("SIP response changed")
	}
}

type secureChannelCaptureConn struct {
	writes chan []byte
}

func (*secureChannelCaptureConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *secureChannelCaptureConn) Write(p []byte) (int, error) {
	c.writes <- append([]byte(nil), p...)
	return len(p), nil
}
func (*secureChannelCaptureConn) Close() error                     { return nil }
func (*secureChannelCaptureConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (*secureChannelCaptureConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (*secureChannelCaptureConn) SetDeadline(time.Time) error      { return nil }
func (*secureChannelCaptureConn) SetReadDeadline(time.Time) error  { return nil }
func (*secureChannelCaptureConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*secureChannelCaptureConn)(nil)

func secureChannelUDPTestPolicy(t *testing.T, localIP, remoteIP net.IP) Policy {
	t.Helper()
	policy, err := NewPolicy(PolicyInput{
		LocalIP:  localIP,
		RemoteIP: remoteIP,
		CK:       bytes.Repeat([]byte{0x11}, 16),
		IK:       bytes.Repeat([]byte{0x22}, 16),
		Mech: SecurityMechanism{
			Alg:   "hmac-sha-1-96",
			EAlg:  "aes-cbc",
			Prot:  "esp",
			Mode:  "trans",
			SPIc:  100,
			SPIs:  101,
			PortC: 5090,
			PortS: 5091,
		},
		UEPortC: 5062,
		UEPortS: 5063,
		UESPIc:  200,
		UESPIs:  201,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return policy
}

func reverseSecureChannelUDPTestPolicy(client Policy) Policy {
	reverseFlow := func(flow Flow) Flow {
		return Flow{
			OutboundSPI: flow.InboundSPI,
			InboundSPI:  flow.OutboundSPI,
			LocalPort:   flow.RemotePort,
			RemotePort:  flow.LocalPort,
			AuthAlg:     flow.AuthAlg,
			EncAlg:      flow.EncAlg,
			CK:          append([]byte(nil), flow.CK...),
			IK:          append([]byte(nil), flow.IK...),
		}
	}
	return Policy{
		LocalIP:     append([]byte(nil), client.RemoteIP...),
		RemoteIP:    append([]byte(nil), client.LocalIP...),
		LocalPortC:  client.RemotePortC,
		LocalPortS:  client.RemotePortS,
		RemotePortC: client.LocalPortC,
		RemotePortS: client.LocalPortS,
		FlowC:       reverseFlow(client.FlowC),
		FlowS:       reverseFlow(client.FlowS),
	}
}
