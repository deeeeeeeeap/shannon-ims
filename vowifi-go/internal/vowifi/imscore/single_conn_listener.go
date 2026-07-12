package imscore

import (
	"errors"
	"net"
	"sync"
)

// singleConnListener exposes at most one accepted connection, matching the
// author imscore port-s inbound pattern.
type singleConnListener struct {
	addr     net.Addr
	connCh   chan net.Conn
	closeCh  chan struct{}
	acceptMu sync.Mutex
	closed   bool
}

func newSingleConnListener(addr net.Addr) *singleConnListener {
	return &singleConnListener{
		addr:    addr,
		connCh:  make(chan net.Conn, 1),
		closeCh: make(chan struct{}),
	}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.acceptMu.Lock()
	if l.closed {
		l.acceptMu.Unlock()
		return nil, errors.New("imscore: port-s listener closed")
	}
	l.acceptMu.Unlock()
	select {
	case <-l.closeCh:
		return nil, errors.New("imscore: port-s listener closed")
	case conn := <-l.connCh:
		if conn == nil {
			return nil, errors.New("imscore: port-s listener closed")
		}
		return conn, nil
	}
}

func (l *singleConnListener) Close() error {
	l.acceptMu.Lock()
	defer l.acceptMu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.closeCh)
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.addr
}

func (l *singleConnListener) deliver(conn net.Conn) {
	select {
	case <-l.closeCh:
		_ = conn.Close()
	case l.connCh <- conn:
	}
}