package imscore

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// protectedTCPMessagingConn presents the two ipsec-3gpp TCP flows as one SIP
// messaging transport. Outbound requests always use the authenticated client
// flow. Inbound messages may arrive on either flow; their response is written
// back to the exact connection that carried the request.
type protectedTCPMessagingConn struct {
	runtime protectedTCPMessagingRuntime
	client  net.Conn

	frames chan protectedTCPMessagingFrame
	done   chan struct{}

	mu         sync.Mutex
	server     net.Conn
	reply      net.Conn
	closed     bool
	closeOnce  sync.Once
	failOnce   sync.Once
	wireWrite  sync.Mutex
	readerWait sync.WaitGroup
}

type protectedTCPMessagingRuntime interface {
	ServerFlowReady() bool
	AcceptServerFlow() (net.Conn, error)
	Close()
}

type protectedTCPMessagingFrame struct {
	payload []byte
	reply   net.Conn
	err     error
}

func newProtectedTCPMessagingConn(runtime protectedTCPMessagingRuntime, client net.Conn) (*protectedTCPMessagingConn, error) {
	if runtime == nil || !runtime.ServerFlowReady() {
		return nil, errors.New("imscore: protected TCP messaging runtime is not ready")
	}
	if client == nil {
		return nil, errors.New("imscore: protected TCP messaging client flow is unavailable")
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	c := &protectedTCPMessagingConn{
		runtime: runtime,
		client:  client,
		frames:  make(chan protectedTCPMessagingFrame, 16),
		done:    make(chan struct{}),
	}
	c.readerWait.Add(2)
	go c.runClientReader()
	go c.runServerAcceptor()
	return c, nil
}

func (c *protectedTCPMessagingConn) runClientReader() {
	defer c.readerWait.Done()
	if err := c.readFrames(c.client); err != nil && !c.isClosing() {
		c.fail(err)
	}
}

func (c *protectedTCPMessagingConn) runServerAcceptor() {
	defer c.readerWait.Done()
	for {
		server, err := c.runtime.AcceptServerFlow()
		if err != nil {
			if !c.isClosing() {
				c.fail(err)
			}
			return
		}
		_ = server.SetDeadline(time.Time{})
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = server.Close()
			return
		}
		c.server = server
		c.mu.Unlock()

		readErr := c.readFrames(server)
		c.mu.Lock()
		if c.server == server {
			c.server = nil
		}
		c.mu.Unlock()
		_ = server.Close()
		if c.isClosing() {
			return
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, net.ErrClosed) {
			c.fail(readErr)
			return
		}
	}
}

func (c *protectedTCPMessagingConn) readFrames(conn net.Conn) error {
	framer := newSIPStreamFramer(defaultSIPFramerLimits())
	buf := make([]byte, streamReadChunkLen)
	for {
		n, readErr := conn.Read(buf)
		if n > 0 {
			frames, err := framer.Push(buf[:n])
			if err != nil {
				return err
			}
			for _, frame := range frames {
				event := protectedTCPMessagingFrame{
					payload: append([]byte(nil), frame...),
					reply:   conn,
				}
				select {
				case c.frames <- event:
				case <-c.done:
					return net.ErrClosed
				}
			}
		}
		if readErr != nil {
			if err := framer.CloseInput(); err != nil {
				return err
			}
			return readErr
		}
	}
}

func (c *protectedTCPMessagingConn) fail(err error) {
	if err == nil {
		return
	}
	c.failOnce.Do(func() {
		select {
		case c.frames <- protectedTCPMessagingFrame{err: err}:
		case <-c.done:
		}
	})
}

func (c *protectedTCPMessagingConn) ReadSIPMessage() ([]byte, error) {
	if c == nil {
		return nil, net.ErrClosed
	}
	select {
	case <-c.done:
		return nil, net.ErrClosed
	case frame := <-c.frames:
		if frame.err != nil {
			return nil, frame.err
		}
		c.mu.Lock()
		c.reply = frame.reply
		c.mu.Unlock()
		return frame.payload, nil
	}
}

func (c *protectedTCPMessagingConn) Read(p []byte) (int, error) {
	message, err := c.ReadSIPMessage()
	if err != nil {
		return 0, err
	}
	if len(message) > len(p) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, message), nil
}

func (c *protectedTCPMessagingConn) Write(p []byte) (int, error) {
	if c == nil || c.client == nil || c.isClosing() {
		return 0, net.ErrClosed
	}
	c.wireWrite.Lock()
	defer c.wireWrite.Unlock()
	return writeFullSIPStream(c.client, p)
}

func (c *protectedTCPMessagingConn) WriteServerFlow(p []byte) (int, error) {
	if c == nil || c.isClosing() {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	reply := c.reply
	c.reply = nil
	c.mu.Unlock()
	if reply == nil {
		return 0, errors.New("imscore: protected TCP response has no source flow")
	}
	c.wireWrite.Lock()
	defer c.wireWrite.Unlock()
	return writeFullSIPStream(reply, p)
}

func writeFullSIPStream(conn net.Conn, payload []byte) (int, error) {
	written := 0
	for written < len(payload) {
		n, err := conn.Write(payload[written:])
		if n > 0 {
			written += n
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

func (c *protectedTCPMessagingConn) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		server := c.server
		c.server = nil
		close(c.done)
		c.mu.Unlock()
		if c.client != nil {
			_ = c.client.Close()
		}
		if server != nil {
			_ = server.Close()
		}
		// Closing the runtime also closes the listener, which joins an Accept that
		// has not yet produced the terminating server flow.
		c.runtime.Close()
		c.readerWait.Wait()
	})
	return nil
}

func (c *protectedTCPMessagingConn) isClosing() bool {
	if c == nil {
		return true
	}
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *protectedTCPMessagingConn) LocalAddr() net.Addr {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.LocalAddr()
}

func (c *protectedTCPMessagingConn) RemoteAddr() net.Addr {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.RemoteAddr()
}

func (c *protectedTCPMessagingConn) SetDeadline(deadline time.Time) error {
	if c == nil || c.client == nil {
		return net.ErrClosed
	}
	return c.client.SetDeadline(deadline)
}

func (c *protectedTCPMessagingConn) SetReadDeadline(deadline time.Time) error {
	if c == nil || c.client == nil {
		return net.ErrClosed
	}
	return c.client.SetReadDeadline(deadline)
}

func (c *protectedTCPMessagingConn) SetWriteDeadline(deadline time.Time) error {
	if c == nil || c.client == nil {
		return net.ErrClosed
	}
	return c.client.SetWriteDeadline(deadline)
}
