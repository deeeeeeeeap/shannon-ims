package imscore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

const (
	registerTransportReadTimeout  = 12 * time.Second
	registerTransportCandidateGap = 150 * time.Millisecond
)

type stableSIPConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr

	mu     sync.Mutex
	closed bool
}

func wrapStableSIPConn(conn net.Conn) net.Conn {
	if conn == nil {
		return nil
	}
	return &stableSIPConn{
		Conn:   &sipFramingConn{Conn: conn},
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
	}
}

func (c *stableSIPConn) LocalAddr() net.Addr {
	if c == nil || c.local == nil {
		return nil
	}
	return c.local
}

func (c *stableSIPConn) RemoteAddr() net.Addr {
	if c == nil || c.remote == nil {
		return nil
	}
	return c.remote
}

func (c *stableSIPConn) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
}

type sipFramingConn struct {
	net.Conn

	mu       sync.Mutex
	lastByte byte
	hasLast  bool
}

func (c *sipFramingConn) Read(p []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.hasLast && len(p) > 0 {
		p[0] = c.lastByte
		c.hasLast = false
		n, err := c.Conn.Read(p[1:])
		if err != nil {
			return n + 1, err
		}
		return n + 1, nil
	}

	return c.Conn.Read(p)
}

func (c *sipFramingConn) shouldCoalesceShortCRLF(buf []byte) bool {
	return len(bytesTrim(buf, "\x00\r\n")) == 0 && len(buf) <= 4
}

func (c *sipFramingConn) rememberLastByte(b byte) {
	c.lastByte = b
	c.hasLast = true
}

func bytesTrim(buf []byte, cutset string) []byte {
	start, end := 0, len(buf)
	for start < end && strings.ContainsRune(cutset, rune(buf[start])) {
		start++
	}
	for end > start && strings.ContainsRune(cutset, rune(buf[end-1])) {
		end--
	}
	return buf[start:end]
}

type connRegisterTransport struct {
	conn      net.Conn
	rawConn   net.Conn
	traceID   string
	deviceID  string
	transport string
	parser    *sip.ParserStream

	mu       sync.Mutex
	released bool
	closed   bool
}

func newConnRegisterTransport(conn net.Conn, traceID, deviceID, transport string) *connRegisterTransport {
	stable := wrapStableSIPConn(conn)
	return &connRegisterTransport{
		conn:      stable,
		rawConn:   conn,
		traceID:   strings.TrimSpace(traceID),
		deviceID:  strings.TrimSpace(deviceID),
		transport: canonicalRegisterTransport(transport),
		parser:    sip.NewParser().NewSIPStream(),
	}
}

func registerTransportDeadline() time.Duration {
	if v := strings.TrimSpace(os.Getenv("VOHIVE_REGISTER_TRANSPORT_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return registerTransportReadTimeout
}

func (t *connRegisterTransport) Send(ctx context.Context, req *sip.Request) error {
	if req == nil {
		return fmt.Errorf("imscore: register transport unavailable")
	}
	return t.SendPayload(ctx, []byte(req.String()))
}

func (t *connRegisterTransport) SendPayload(ctx context.Context, payload []byte) error {
	if t == nil || len(payload) == 0 {
		return fmt.Errorf("imscore: register transport unavailable")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.released {
		return fmt.Errorf("imscore: register transport closed")
	}
	if err := t.conn.SetWriteDeadline(time.Now().Add(registerTransportDeadline())); err != nil {
		return err
	}
	if _, err := t.conn.Write(payload); err != nil {
		return err
	}
	if strings.TrimSpace(os.Getenv("VOHIVE_SIP_TRACE")) != "" {
		loggerSIPWrite(t.traceID, t.deviceID, t.transport, connLocalAddrString(t.conn), connRemoteAddrString(t.conn), payload)
	}
	return nil
}

func (t *connRegisterTransport) ReadResponse(ctx context.Context) (*sip.Response, error) {
	if t == nil {
		return nil, fmt.Errorf("imscore: register transport unavailable")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.released {
		return nil, fmt.Errorf("imscore: register transport closed")
	}

	deadline := registerTransportDeadline()
	if err := t.conn.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		return nil, err
	}

	buf := make([]byte, 32*1024)
	var response *sip.Response
	for response == nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		n, err := t.conn.Read(buf)
		if n > 0 {
			data := buf[:n]
			if len(bytesTrim(data, "\x00\r\n")) == 0 {
				continue
			}
			if strings.TrimSpace(os.Getenv("VOHIVE_SIP_TRACE")) != "" {
				loggerSIPRead(t.traceID, t.deviceID, t.transport, connLocalAddrString(t.conn), connRemoteAddrString(t.conn), data)
			}
			parseErr := t.parser.ParseSIPStream(data, func(msg sip.Message) {
				if res, ok := msg.(*sip.Response); ok && response == nil {
					response = res
				}
			})
			if parseErr != nil {
				return nil, parseErr
			}
			if response != nil {
				return response, nil
			}
		}
		if err != nil {
			if isTimeoutError(err) && response == nil {
				return nil, fmt.Errorf("register response timeout: %w", err)
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil, fmt.Errorf("register connection closed before response")
			}
			return nil, err
		}
	}
	return response, nil
}

func (t *connRegisterTransport) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.parser != nil {
		t.parser.Close()
		t.parser = nil
	}
	var err error
	if t.conn != nil {
		err = t.conn.Close()
		t.conn = nil
	}
	if t.rawConn != nil {
		if closeErr := t.rawConn.Close(); err == nil {
			err = closeErr
		}
		t.rawConn = nil
	}
	return err
}

func (t *connRegisterTransport) ReleaseConn() net.Conn {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.released = true
	if t.parser != nil {
		t.parser.Close()
		t.parser = nil
	}
	conn := t.rawConn
	t.conn = nil
	t.rawConn = nil
	return conn
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

func connLocalAddrString(conn net.Conn) string {
	if conn == nil || conn.LocalAddr() == nil {
		return ""
	}
	return conn.LocalAddr().String()
}

func connRemoteAddrString(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}

func loggerSIPWrite(traceID, deviceID, transport, local, remote string, payload []byte) {
	sipTraceLogger{traceID: traceID, deviceID: deviceID}.SIPTraceWrite(transport, local, remote, payload)
}

func loggerSIPRead(traceID, deviceID, transport, local, remote string, payload []byte) {
	sipTraceLogger{traceID: traceID, deviceID: deviceID}.SIPTraceRead(transport, local, remote, payload)
}
