package socks5sim

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// UDPPeer is a UDP endpoint on 127.0.0.1 that stands in for the remote end of
// a tunnel, such as an ePDG. It answers every datagram, by default with the
// same bytes, and records where its datagrams came from, which is how a test
// observes the source address change after a proxy re-association.
type UDPPeer struct {
	conn *net.UDPConn
	done chan struct{}

	mu      sync.Mutex
	respond func([]byte) []byte
	silent  bool
	sources []string
	seen    map[string]struct{}
	last    *net.UDPAddr

	received atomic.Uint64
}

// StartUDPPeer runs a peer on a free port of 127.0.0.1.
func StartUDPPeer() (*UDPPeer, error) {
	conn, err := listenLoopbackUDP()
	if err != nil {
		return nil, fmt.Errorf("socks5sim: peer listen: %w", err)
	}
	p := &UDPPeer{conn: conn, done: make(chan struct{}), seen: make(map[string]struct{})}
	go p.serve()
	return p, nil
}

// Addr returns the peer's address.
func (p *UDPPeer) Addr() *net.UDPAddr {
	return p.conn.LocalAddr().(*net.UDPAddr)
}

// SetResponder replaces the echo. A nil result sends no answer.
func (p *UDPPeer) SetResponder(fn func(payload []byte) []byte) {
	p.mu.Lock()
	p.respond = fn
	p.mu.Unlock()
}

// SetSilent makes the peer receive without answering.
func (p *UDPPeer) SetSilent(silent bool) {
	p.mu.Lock()
	p.silent = silent
	p.mu.Unlock()
}

// Received returns the number of datagrams received.
func (p *UDPPeer) Received() uint64 { return p.received.Load() }

// Sources returns the distinct source addresses seen, in order of first use.
func (p *UDPPeer) Sources() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.sources...)
}

// Send sends an unsolicited datagram to the most recent source.
func (p *UDPPeer) Send(payload []byte) error {
	p.mu.Lock()
	last := p.last
	p.mu.Unlock()
	if last == nil {
		return errors.New("socks5sim: peer has not received anything yet")
	}
	_, err := p.conn.WriteToUDP(payload, last)
	return err
}

// Close stops the peer.
func (p *UDPPeer) Close() {
	_ = p.conn.Close()
	<-p.done
}

func (p *UDPPeer) serve() {
	defer close(p.done)
	buf := make([]byte, 65535)
	for {
		n, from, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.received.Add(1)

		p.mu.Lock()
		key := from.String()
		if _, ok := p.seen[key]; !ok {
			p.seen[key] = struct{}{}
			p.sources = append(p.sources, key)
		}
		p.last = from
		respond, silent := p.respond, p.silent
		p.mu.Unlock()

		if silent {
			continue
		}
		reply := append([]byte(nil), buf[:n]...)
		if respond != nil {
			if reply = respond(reply); reply == nil {
				continue
			}
		}
		_, _ = p.conn.WriteToUDP(reply, from)
	}
}
