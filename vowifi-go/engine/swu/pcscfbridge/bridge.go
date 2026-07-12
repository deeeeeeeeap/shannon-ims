// Package pcscfbridge is the Go side of P-CSCF discovery: a small Unix
// socket server that a companion strongSwan charon plugin (not part of this
// Go module — see plugin/ in this package's directory) pushes the P-CSCF
// server address to, once charon receives it in the IKE_AUTH configuration
// payload.
//
// This exists because strongSwan's own stock p-cscf plugin
// (libcharon/plugins/p_cscf) only logs the address it receives — it has no
// vici surface at all, same class of gap as the EAP-AKA card backends that
// motivated akabridge. Unlike akabridge, this is a push, not a
// request/response: charon tells us something it learned, once, when it
// learns it — there's nothing for the plugin to ask us for.
package pcscfbridge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

const (
	protoVersion = 1

	familyIPv4 = 4
	familyIPv6 = 6

	maxConnNameLen = 255
)

// Bridge receives pushed P-CSCF addresses keyed by vici connection name
// (charon's ike_sa->get_name(), which is exactly the connNameFor(deviceID)
// string engine/swu already uses) and lets callers wait for one to arrive.
type Bridge struct {
	mu      sync.Mutex
	waiters map[string]chan net.IP // connName -> channel a Dial() is waiting on
}

func New() *Bridge {
	return &Bridge{waiters: make(map[string]chan net.IP)}
}

// WaitFor returns a channel that receives the P-CSCF address for connName
// once the plugin pushes it, at most once. Call Forget(connName) once done
// waiting (success, failure, or Session.Close) to release the channel;
// WaitFor itself does not time out.
func (b *Bridge) WaitFor(connName string) <-chan net.IP {
	ch := make(chan net.IP, 1)
	b.mu.Lock()
	b.waiters[connName] = ch
	b.mu.Unlock()
	return ch
}

// Forget releases the waiter for connName, if any. Safe to call even if
// nothing is waiting (e.g. the address already arrived).
func (b *Bridge) Forget(connName string) {
	b.mu.Lock()
	delete(b.waiters, connName)
	b.mu.Unlock()
}

func (b *Bridge) deliver(connName string, ip net.IP) {
	b.mu.Lock()
	ch, ok := b.waiters[connName]
	b.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- ip:
	default:
		// Already delivered (or nobody reading fast enough); a P-CSCF
		// address doesn't change mid-session, so dropping a duplicate is
		// correct, not lossy.
	}
}

// ListenAndServe binds socketPath (removing any stale socket first) and
// serves pushed addresses until ctx is done. socketPath should be
// /run/charon.vohive-pcscf in production, matching the /run/charon.*
// AppArmor allowance the same way akabridge's socket does.
func (b *Bridge) ListenAndServe(ctx context.Context, socketPath string) error {
	_ = os.Remove(socketPath)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("pcscfbridge: listen %s: %w", socketPath, err)
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("pcscfbridge: accept: %w", err)
		}
		go b.handle(conn)
	}
}

func (b *Bridge) handle(conn net.Conn) {
	defer conn.Close()

	connName, ip, err := readPush(conn)
	if err != nil {
		return // malformed push: nothing to do but drop it
	}
	b.deliver(connName, ip)
}

func readPush(r io.Reader) (connName string, ip net.IP, err error) {
	br := bufio.NewReaderSize(r, 1+1+maxConnNameLen+1+16)

	header := make([]byte, 2)
	if _, err = io.ReadFull(br, header); err != nil {
		return "", nil, err
	}
	if header[0] != protoVersion {
		return "", nil, fmt.Errorf("pcscfbridge: unsupported push version %d", header[0])
	}
	nameLen := int(header[1])

	name := make([]byte, nameLen)
	if _, err = io.ReadFull(br, name); err != nil {
		return "", nil, err
	}

	family := make([]byte, 1)
	if _, err = io.ReadFull(br, family); err != nil {
		return "", nil, err
	}

	addrLen := 4
	if family[0] == familyIPv6 {
		addrLen = 16
	} else if family[0] != familyIPv4 {
		return "", nil, fmt.Errorf("pcscfbridge: unknown address family %d", family[0])
	}

	addr := make([]byte, addrLen)
	if _, err = io.ReadFull(br, addr); err != nil {
		return "", nil, err
	}

	return string(name), net.IP(addr), nil
}
