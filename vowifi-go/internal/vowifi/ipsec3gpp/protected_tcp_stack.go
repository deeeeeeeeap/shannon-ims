package ipsec3gpp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ProtectedTCPStack is a private userspace TCP stack whose only link is the
// ESP-protected endpoint.
//
// It exists so that IPsec never has to synthesise a TCP header. A real stack
// owns the handshake, sequence numbers, checksums, retransmission, windowing,
// congestion control and — the reason this whole path exists — segmentation. The
// ESP transform only ever protects segments the stack produced.
//
// Ownership is deliberately explicit. The stack, the link endpoint and the ESP
// carrier are created and destroyed together by Close, so a registration attempt
// cannot leave a detached runtime behind holding a dead SA.
type ProtectedTCPStack struct {
	stack    *stack.Stack
	endpoint *ProtectedLinkEndpoint
	carrier  net.Conn
	policy   Policy

	// clientEP is the client flow's TCP endpoint, retained solely to read its
	// retransmission counter after the exchange.
	//
	// gvisor exposes retransmits only through the endpoint's own Stats(), and the
	// link endpoint below cannot derive them: a retransmitted segment looks
	// identical to a first transmission on the wire. Without this, a stalled send
	// and a send that was never attempted report the same numbers.
	clientMu sync.Mutex
	clientEP tcpip.Endpoint

	closeOnce sync.Once
}

// protectedTCPStackNICID is the single NIC of this private stack.
const protectedTCPStackNICID = 1

// NewProtectedTCPStack builds the stack around an ESP carrier.
//
// carrier must be a packet-mode raw IP connection carrying ESP (protocol 50) to
// the negotiated P-CSCF. innerMTU is the tunnel's raw IP MTU: it becomes the link
// MTU, and the safe MSS is derived from it and the negotiated transform.
func NewProtectedTCPStack(carrier net.Conn, transport *Transport, policy Policy, innerMTU int) (*ProtectedTCPStack, error) {
	endpoint, err := NewProtectedLinkEndpoint(carrier, transport, policy, innerMTU)
	if err != nil {
		return nil, err
	}

	netProto := endpoint.NetworkProtocol()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{gtcp.NewProtocol},
	})
	if err := s.CreateNIC(protectedTCPStackNICID, endpoint); err != nil {
		s.Close()
		return nil, fmt.Errorf("ipsec3gpp: protected stack create NIC: %v", err)
	}

	prefixLen := 128
	if len(policy.LocalIP) == 4 {
		prefixLen = 32
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol: netProto,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(policy.LocalIP),
			PrefixLen: prefixLen,
		},
	}
	if err := s.AddProtocolAddress(protectedTCPStackNICID, protocolAddr, stack.AddressProperties{}); err != nil {
		s.Close()
		return nil, fmt.Errorf("ipsec3gpp: protected stack add local address: %v", err)
	}
	destination := header.IPv6EmptySubnet
	if len(policy.LocalIP) == 4 {
		destination = header.IPv4EmptySubnet
	}
	s.SetRouteTable([]tcpip.Route{{Destination: destination, NIC: protectedTCPStackNICID}})

	return &ProtectedTCPStack{
		stack:    s,
		endpoint: endpoint,
		carrier:  carrier,
		policy:   policy,
	}, nil
}

// ClientFlowBindPort is the local port the UE-originating protected connection
// must bind.
//
// TS 33.203 clause 7.1 permits only the pairs (port_uc, port_ps) and
// (port_us, port_pc), and the installed SA selectors cover exactly those. An
// ephemeral local port would therefore match no SA at all: the segment could
// neither be protected on egress nor attributed to an SA by the peer. This is
// exported so the binding rule has one definition that both the dialer and its
// tests read, instead of each restating FlowC.LocalPort.
func ClientFlowBindPort(policy Policy) int {
	return policy.FlowC.LocalPort
}

// SafeMSS is the derived MSS this stack advertises and clamps peers to.
func (p *ProtectedTCPStack) SafeMSS() int {
	if p == nil {
		return 0
	}
	return p.endpoint.SafeMSS()
}

// Snapshot exposes the link endpoint counters.
func (p *ProtectedTCPStack) Snapshot() ProtectedLinkSnapshot {
	if p == nil {
		return ProtectedLinkSnapshot{}
	}
	return p.endpoint.Snapshot()
}

// DialClientFlow opens the UE-originating protected connection: from the UE
// protected client port to the P-CSCF protected server port.
//
// TS 33.203 clause 7.1 allows exactly two port pairs, so the local port is bound
// explicitly rather than left to an ephemeral choice. The user MSS is set BEFORE
// Connect, because gonet.DialTCPWithBind offers no seam for it and the option is
// only read while the endpoint is unconnected.
func (p *ProtectedTCPStack) DialClientFlow(ctx context.Context) (net.Conn, error) {
	if p == nil || p.stack == nil {
		return nil, errors.New("ipsec3gpp: protected TCP stack is not ready")
	}
	localPort := ClientFlowBindPort(p.policy)
	remotePort := p.policy.FlowC.RemotePort
	if localPort <= 0 || remotePort <= 0 {
		return nil, errors.New("ipsec3gpp: protected client flow ports are unavailable")
	}
	safeMSS := p.endpoint.SafeMSS()
	if safeMSS <= 0 {
		return nil, errors.New("ipsec3gpp: derived safe MSS is unavailable")
	}

	var wq waiter.Queue
	ep, tcpErr := p.stack.NewEndpoint(gtcp.ProtocolNumber, p.endpoint.NetworkProtocol(), &wq)
	if tcpErr != nil {
		return nil, fmt.Errorf("ipsec3gpp: protected client endpoint: %v", tcpErr)
	}

	// Pre-connect only. This bounds what the PEER may send us; our own segments
	// are bounded by clamping the peer's advertised MSS on ingress.
	if err := ep.SetSockOptInt(tcpip.MaxSegOption, safeMSS); err != nil {
		ep.Close()
		return nil, fmt.Errorf("ipsec3gpp: set protected MSS: %v", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	localAddr := tcpip.FullAddress{
		NIC:  protectedTCPStackNICID,
		Addr: tcpip.AddrFromSlice(p.policy.LocalIP),
		Port: uint16(localPort),
	}
	if err := ep.Bind(localAddr); err != nil {
		ep.Close()
		return nil, fmt.Errorf("ipsec3gpp: bind protected client port: %v", err)
	}
	remoteAddr := tcpip.FullAddress{
		NIC:  protectedTCPStackNICID,
		Addr: tcpip.AddrFromSlice(p.policy.RemoteIP),
		Port: uint16(remotePort),
	}

	connErr := ep.Connect(remoteAddr)
	if _, started := connErr.(*tcpip.ErrConnectStarted); started {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		case <-notifyCh:
		}
		connErr = ep.LastError()
	}
	if connErr != nil {
		ep.Close()
		return nil, fmt.Errorf("ipsec3gpp: protected client connect: %v", connErr)
	}
	// Retain the endpoint so its own send statistics can be read afterwards.
	// Retransmissions are the one measurement the link endpoint cannot supply:
	// gvisor's sender decides when to resend, and from the link's point of view a
	// resent segment is indistinguishable from a new one without inspecting
	// sequence numbers - which this code deliberately does not retain.
	p.clientMu.Lock()
	p.clientEP = ep
	p.clientMu.Unlock()
	return gonet.NewTCPConn(&wq, ep), nil
}

// ClientFlowRetransmissions is how many segments gvisor's sender retransmitted on
// the protected client flow.
//
// It reads the endpoint's own counter. No sequence or acknowledgement number is
// read or retained.
func (p *ProtectedTCPStack) ClientFlowRetransmissions() int {
	if p == nil {
		return 0
	}
	p.clientMu.Lock()
	ep := p.clientEP
	p.clientMu.Unlock()
	if ep == nil {
		return 0
	}
	stats, ok := ep.Stats().(*gtcp.Stats)
	if !ok || stats == nil {
		return 0
	}
	return int(stats.SendErrors.Retransmits.Value())
}

// ListenServerFlow opens the terminating half: the UE's protected server port,
// which the P-CSCF connects to for every network-originated request.
//
// TS 33.203 clause 7.1 Ports item 1 requires the P-CSCF to set up its own TCP
// connection from port_pc to port_us before sending a request, and TS 24.229
// clause 3.1 NOTE 3 leaves it no other flow. Without this listener a UE
// registers successfully and then silently receives nothing.
//
// The listener exists ONLY inside this gvisor stack. It binds no host socket, so
// nothing appears in the operating system's port table.
//
// It deliberately shares the same stack, link endpoint, ESP carrier and inbound
// pump as DialClientFlow. Two stacks would mean two carriers over one
// (src,dst,proto) triple, and swuNetstack.dispatchRawIPPacket delivers a COPY to
// every matching raw connection - so each ESP packet would be processed twice,
// by two independent replay windows.
func (p *ProtectedTCPStack) ListenServerFlow() (net.Listener, error) {
	if p == nil || p.stack == nil {
		return nil, errors.New("ipsec3gpp: protected TCP stack is not ready")
	}
	// FlowS is the server flow: its local port is the stable port_us.
	serverPort := p.policy.FlowS.LocalPort
	if serverPort <= 0 {
		return nil, errors.New("ipsec3gpp: protected server flow port is unavailable")
	}
	safeMSS := p.endpoint.SafeMSS()
	if safeMSS <= 0 {
		return nil, errors.New("ipsec3gpp: derived safe MSS is unavailable")
	}

	// The endpoint is built by hand rather than via gonet.ListenTCP because the
	// safe MSS has to be set BEFORE Listen: MaxSegOption is only read while the
	// endpoint is unconnected, and it is what the SYN-ACK advertises. Left at the
	// default the listener would advertise the route MSS (link MTU minus headers),
	// which is larger than the ESP budget allows - so the P-CSCF would send
	// segments whose protected packets fragment on the way in.
	var wq waiter.Queue
	ep, tcpErr := p.stack.NewEndpoint(gtcp.ProtocolNumber, p.endpoint.NetworkProtocol(), &wq)
	if tcpErr != nil {
		return nil, fmt.Errorf("ipsec3gpp: protected server endpoint: %v", tcpErr)
	}
	if err := ep.SetSockOptInt(tcpip.MaxSegOption, safeMSS); err != nil {
		ep.Close()
		return nil, fmt.Errorf("ipsec3gpp: set protected server MSS: %v", err)
	}
	addr := tcpip.FullAddress{
		NIC:  protectedTCPStackNICID,
		Addr: tcpip.AddrFromSlice(p.policy.LocalIP),
		Port: uint16(serverPort),
	}
	if err := ep.Bind(addr); err != nil {
		ep.Close()
		return nil, fmt.Errorf("ipsec3gpp: bind protected server port: %v", err)
	}
	// Backlog of one: TS 33.203 clause 7.1 NOTE 6 lets the P-CSCF reuse a single
	// connection from port_pc to port_us, so a deeper queue would only hold
	// connections this UE has no separate use for.
	if err := ep.Listen(1); err != nil {
		ep.Close()
		return nil, fmt.Errorf("ipsec3gpp: listen on protected server port: %v", err)
	}
	return gonet.NewTCPListener(p.stack, &wq, ep), nil
}

// ProtectedServerPort is the stable port_us this stack listens on.
func (p *ProtectedTCPStack) ProtectedServerPort() int {
	if p == nil {
		return 0
	}
	return p.policy.FlowS.LocalPort
}

// Close tears down the stack, the link endpoint and the ESP carrier together.
//
// A registration attempt that fails must not leave any of the three alive: a
// surviving stack would keep injecting into a replaced SA.
func (p *ProtectedTCPStack) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		if p.endpoint != nil {
			p.endpoint.Close()
		}
		if p.stack != nil {
			p.stack.Close()
		}
		if p.carrier != nil {
			_ = p.carrier.Close()
		}
		if p.endpoint != nil {
			p.endpoint.Wait()
		}
		if p.stack != nil {
			p.stack.Wait()
		}
	})
	return nil
}
