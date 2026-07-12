// Package akabridge is the Go side of the live EAP-AKA bridge: a small Unix
// socket server that a companion strongSwan charon plugin (not part of this
// Go module — see plugin/ in this package's directory) calls into whenever
// charon's eap-aka needs a RAND/AUTN pair turned into RES/CK/IK, mid
// IKE_AUTH exchange.
//
// This exists because strongSwan's own EAP-AKA card backends only support a
// PC/SC smartcard reader or static test vectors — neither fits a SIM that
// lives behind a QMI modem. The bridge forwards each request to whatever
// sim.AKAProvider vohive already uses for the exact same computation over
// APDU/QMI (identity.PrepareStart / vohive's own AKA app preference
// resolution already decided which one).
//
// # Wire format
//
// One request per connection (dial, write, read, close) — simplest thing
// that works given the tiny, fixed-size payloads and charon's likely one
// EAP-AKA computation at a time per IKE_SA:
//
//	request  (C -> Go):  version(1) id_len(1) id(id_len) rand(16) autn(16)
//	response (Go -> C):  status(1) [ res_len(1) res(res_len) ck(16) ik(16) | auts(14) ]
//
// status: 0 = success (res/ck/ik follow), 1 = sync failure (auts follows),
// 2 = failed, 3 = not found (no provider registered for this identity).
package akabridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/1239t/vowifi-go/engine/sim"
)

const (
	protoVersion = 1

	statusSuccess     = 0
	statusSyncFailure = 1
	statusFailed      = 2
	statusNotFound    = 3

	randLen = 16
	autnLen = 16
	autsLen = 14
	ckLen   = 16
	ikLen   = 16
	// resMaxLen mirrors AKA_RES_MAX in strongSwan's simaka_manager.h: RES is
	// variable length (32-128 bits) but we only support whole bytes, same as
	// the card interface we're bridging.
	resMaxLen = 16

	maxIdentityLen = 255 // id_len is a single byte
)

// Bridge maps identity strings (the same NAI/IMPI string used as the EAP
// identity / IKE IDi) to the AKAProvider that should answer for them, and
// serves the plugin's requests against that map.
type Bridge struct {
	mu        sync.RWMutex
	providers map[string]sim.AKAProvider
}

func New() *Bridge {
	return &Bridge{providers: make(map[string]sim.AKAProvider)}
}

// Register makes the bridge answer requests for identity using p. Callers
// (engine/swu's Dial) register before initiating the IKE_SA and Unregister
// on teardown; a stale registration would let a *new* session for the same
// identity silently answer from an old, possibly-closed AKAProvider.
func (b *Bridge) Register(identity string, p sim.AKAProvider) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.providers[identity] = p
}

func (b *Bridge) Unregister(identity string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.providers, identity)
}

func (b *Bridge) provider(identity string) (sim.AKAProvider, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	p, ok := b.providers[identity]
	return p, ok
}

// ListenAndServe binds socketPath (removing any stale socket first) and
// serves requests until ctx is done. socketPath should be
// /run/charon.vohive-aka in production — see the package-level charon
// AppArmor note in engine/swu/charon: that path matches the profile's
// `/run/charon.*` allowance, everything else about this socket is
// unconstrained by AppArmor (a blanket `network,` grant, no unix-specific
// restriction), but there's no reason not to stay consistent.
func (b *Bridge) ListenAndServe(ctx context.Context, socketPath string) error {
	_ = os.Remove(socketPath)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("akabridge: listen %s: %w", socketPath, err)
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
			return fmt.Errorf("akabridge: accept: %w", err)
		}
		go b.handle(conn)
	}
}

func (b *Bridge) handle(conn net.Conn) {
	defer conn.Close()

	req, err := readRequest(conn)
	if err != nil {
		return // malformed/short request: nothing sane to reply with, just drop it
	}

	provider, ok := b.provider(req.identity)
	if !ok {
		writeStatusOnly(conn, statusNotFound)
		return
	}

	result, err := provider.CalculateAKA(req.rand, req.autn)
	switch {
	case err == nil:
		writeSuccess(conn, result)
	case errors.Is(err, sim.ErrSyncFailure):
		writeSyncFailure(conn, result)
	default:
		writeStatusOnly(conn, statusFailed)
	}
}

type request struct {
	identity string
	rand     []byte
	autn     []byte
}

func readRequest(r io.Reader) (request, error) {
	br := bufio.NewReaderSize(r, 1+1+maxIdentityLen+randLen+autnLen)

	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return request{}, err
	}
	if header[0] != protoVersion {
		return request{}, fmt.Errorf("akabridge: unsupported request version %d", header[0])
	}
	idLen := int(header[1])

	rest := make([]byte, idLen+randLen+autnLen)
	if _, err := io.ReadFull(br, rest); err != nil {
		return request{}, err
	}

	return request{
		identity: string(rest[:idLen]),
		rand:     rest[idLen : idLen+randLen],
		autn:     rest[idLen+randLen : idLen+randLen+autnLen],
	}, nil
}

func writeStatusOnly(w io.Writer, status byte) {
	_, _ = w.Write([]byte{status})
}

func writeSuccess(w io.Writer, result sim.AKAResult) {
	res := result.RES
	if len(res) > resMaxLen {
		res = res[:resMaxLen]
	}
	ck := fixedLen(result.CK, ckLen)
	ik := fixedLen(result.IK, ikLen)

	out := make([]byte, 0, 1+1+len(res)+ckLen+ikLen)
	out = append(out, statusSuccess, byte(len(res)))
	out = append(out, res...)
	out = append(out, ck...)
	out = append(out, ik...)
	_, _ = w.Write(out)
}

func writeSyncFailure(w io.Writer, result sim.AKAResult) {
	auts := fixedLen(result.AUTS, autsLen)
	out := make([]byte, 0, 1+autsLen)
	out = append(out, statusSyncFailure)
	out = append(out, auts...)
	_, _ = w.Write(out)
}

// fixedLen returns b padded with zeros or truncated to exactly n bytes, so a
// short/long value from a provider never desyncs the wire format.
func fixedLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}
