package imscore

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

type messagingWriteSignalConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *messagingWriteSignalConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestProtectedServerResponseDoesNotDefeatSendCancellation(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	runtime := newFakeProtectedMessagingRuntime(local)
	conn, err := newProtectedTCPMessagingConn(runtime)
	if err != nil {
		t.Fatal(err)
	}
	client, err := voiceclient.AttachSecureStreamMessaging(context.Background(), voiceclient.Config{
		LocalIP: net.ParseIP("192.0.2.10"), LocalPort: 5062,
		PCSCFAddr: "192.0.2.20:5060", PrivateID: "fixture@example.invalid", PublicURI: "sip:fixture@example.invalid",
		HomeDomain: "example.invalid", SMSC: "sip:smsc@example.invalid",
	}, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())
	server, serverPeer := net.Pipe()
	defer serverPeer.Close()
	started := make(chan struct{})
	runtime.acceptCh <- &messagingWriteSignalConn{Conn: server, started: started}
	request := []byte("MESSAGE sip:fixture@example.invalid SIP/2.0\r\nVia: SIP/2.0/TCP 192.0.2.20;branch=z9hG4bK-fixture\r\nFrom: <sip:gateway@example.invalid>;tag=fixture\r\nTo: <sip:fixture@example.invalid>\r\nCall-ID: fixture\r\nCSeq: 1 MESSAGE\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n")
	if _, err := serverPeer.Write(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("response did not reach server flow")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.SendSMS(ctx, "fixture", "fixture", []messaging.SMSPart{{Body: []byte{0, 1}}})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("send error=%v, want deadline", err)
		}
	case <-time.After(250 * time.Millisecond):
		_ = serverPeer.Close()
		<-done
		t.Fatal("send deadline expired but blocked behind server-flow response write")
	}
}

func TestProtectedClientWriteCanCancelWhileQueued(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	started := make(chan struct{})
	runtime := newFakeProtectedMessagingRuntime(&messagingWriteSignalConn{Conn: local, started: started})
	conn, err := newProtectedTCPMessagingConn(runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	first := make(chan error, 1)
	go func() { _, err := conn.WriteContext(context.Background(), []byte("first")); first <- err }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	second := make(chan error, 1)
	go func() { _, err := conn.WriteContext(ctx, []byte("canceled")); second <- err }()
	select {
	case err := <-second:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued write error=%v", err)
		}
	case <-time.After(time.Second):
		_ = conn.Close()
		t.Fatal("queued write ignored cancellation")
	}
	buffer := make([]byte, len("first"))
	if _, err := io.ReadFull(peer, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "first" {
		t.Fatal("queued cancellation changed first frame")
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestProtectedServerFlowContextUsesActualFlowDeadline(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	runtime := newFakeProtectedMessagingRuntime(local)
	conn, err := newProtectedTCPMessagingConn(runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server, serverPeer := net.Pipe()
	defer serverPeer.Close()
	runtime.acceptCh <- server
	request := []byte("MESSAGE sip:fixture@example.invalid SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	if _, err := serverPeer.Write(request); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ReadSIPMessage(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := conn.WriteServerFlowContext(ctx, []byte("reply")); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("server write error=%v", err)
		}
	case <-time.After(time.Second):
		_ = conn.Close()
		t.Fatal("server flow deadline did not interrupt its write")
	}
	// No bytes were written; a later response may use the same flow. The old
	// cancellation callback must have finished before its deadline was cleared.
	if _, err := serverPeer.Write(request); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ReadSIPMessage(); err != nil {
		t.Fatal(err)
	}
	go func() { _, err := conn.WriteServerFlowContext(context.Background(), []byte("reply")); done <- err }()
	buffer := make([]byte, len("reply"))
	if _, err := io.ReadFull(serverPeer, buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
