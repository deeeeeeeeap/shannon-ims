package imscore

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeProtectedMessagingRuntime struct {
	client   net.Conn
	acceptCh chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

func newFakeProtectedMessagingRuntime(client net.Conn) *fakeProtectedMessagingRuntime {
	return &fakeProtectedMessagingRuntime{
		client:   client,
		acceptCh: make(chan net.Conn, 1),
		closed:   make(chan struct{}),
	}
}

func (r *fakeProtectedMessagingRuntime) ServerFlowReady() bool {
	select {
	case <-r.closed:
		return false
	default:
		return true
	}
}

func (r *fakeProtectedMessagingRuntime) AcceptServerFlow() (net.Conn, error) {
	select {
	case conn := <-r.acceptCh:
		return conn, nil
	case <-r.closed:
		return nil, net.ErrClosed
	}
}

func (r *fakeProtectedMessagingRuntime) Close() error {
	r.once.Do(func() {
		close(r.closed)
		if r.client != nil {
			_ = r.client.Close()
		}
	})
	return nil
}

func (r *fakeProtectedMessagingRuntime) Read(p []byte) (int, error) {
	return r.client.Read(p)
}
func (r *fakeProtectedMessagingRuntime) Write(p []byte) (int, error) {
	return r.client.Write(p)
}
func (r *fakeProtectedMessagingRuntime) LocalAddr() net.Addr  { return r.client.LocalAddr() }
func (r *fakeProtectedMessagingRuntime) RemoteAddr() net.Addr { return r.client.RemoteAddr() }
func (r *fakeProtectedMessagingRuntime) SetDeadline(deadline time.Time) error {
	return r.client.SetDeadline(deadline)
}
func (r *fakeProtectedMessagingRuntime) SetReadDeadline(deadline time.Time) error {
	return r.client.SetReadDeadline(deadline)
}
func (r *fakeProtectedMessagingRuntime) SetWriteDeadline(deadline time.Time) error {
	return r.client.SetWriteDeadline(deadline)
}

func TestProtectedTCPMessagingConnRepliesOnOriginatingServerFlow(t *testing.T) {
	client, clientPeer := net.Pipe()
	runtime := newFakeProtectedMessagingRuntime(client)
	defer clientPeer.Close()
	messagingConn, err := newProtectedTCPMessagingConn(runtime)
	if err != nil {
		t.Fatalf("newProtectedTCPMessagingConn: %v", err)
	}
	defer messagingConn.Close()

	server, serverPeer := net.Pipe()
	defer serverPeer.Close()
	runtime.acceptCh <- server

	request := []byte("MESSAGE sip:safe.invalid SIP/2.0\r\nCall-ID: synthetic\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n")
	writeDone := make(chan error, 1)
	go func() {
		if _, err := serverPeer.Write(request[:17]); err != nil {
			writeDone <- err
			return
		}
		_, err := serverPeer.Write(request[17:])
		writeDone <- err
	}()
	message, err := messagingConn.ReadSIPMessage()
	if err != nil {
		t.Fatalf("ReadSIPMessage: %v", err)
	}
	if !bytes.Equal(message, request) {
		t.Fatal("server-flow SIP message was not reassembled exactly")
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write server-flow message: %v", err)
	}

	response := []byte("SIP/2.0 200 OK\r\nCall-ID: synthetic\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n")
	responseDone := make(chan error, 1)
	go func() {
		got := make([]byte, len(response))
		_, err := io.ReadFull(serverPeer, got)
		if err == nil && !bytes.Equal(got, response) {
			err = errors.New("server-flow response changed")
		}
		responseDone <- err
	}()
	if _, err := messagingConn.WriteServerFlow(response); err != nil {
		t.Fatalf("WriteServerFlow: %v", err)
	}
	if err := <-responseDone; err != nil {
		t.Fatalf("read server-flow response: %v", err)
	}

	if err := clientPeer.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var one [1]byte
	if _, err := clientPeer.Read(one[:]); err == nil {
		t.Fatal("server-flow response leaked onto the client flow")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("client-flow isolation read error = %v, want timeout", err)
	}

	if err := messagingConn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-runtime.closed:
	default:
		t.Fatal("Close did not cancel the blocking server-flow accept")
	}
}
