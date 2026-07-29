package imscore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

// Phase E: the SIP transport for a protected TCP connection.
//
// It differs from connRegisterTransport in exactly one way that matters: reads
// go through sipStreamFramer, which decides message boundaries from
// Content-Length under hard size limits, instead of handing whatever one Read
// returned straight to a parser.
//
// On a packet channel one read is one message, so the older adapter could get
// away with feeding read-sized chunks to a streaming parser. On TCP that is not
// true in either direction: a message can arrive in several segments, and
// several messages can arrive in one segment. The framer owns that distinction
// and refuses anything unbounded.
//
// Every framer instance belongs to exactly one connection. Sharing one across
// connections would let a partial message on one flow prepend itself to the
// first message of another.
//
// Nothing here logs SIP text, a header value, an identity, an address or key
// material. Errors carry counts and closed enums only - streamFramerError is
// built that way on purpose.

// streamRegisterTransport sends and receives SIP over one protected TCP
// connection.
type streamRegisterTransport struct {
	conn   net.Conn
	framer *sipStreamFramer

	// pending holds frames the framer completed but the caller has not consumed
	// yet. One Read can complete several pipelined messages, and dropping the
	// extras would lose a response that already arrived.
	pending [][]byte

	// framesProduced counts every complete SIP message the framer yielded, not
	// just the ones consumed. It answers a question a stalled exchange cannot
	// otherwise settle: whether nothing arrived at all, or whether bytes arrived
	// and could not be framed into a message.
	framesProduced int

	// bytesWritten is how many payload bytes were handed to the connection. It is
	// recorded here rather than recomputed from the request, so the reported number
	// is what the write path actually accepted.
	bytesWritten int

	mu     sync.Mutex
	closed bool
}

// newStreamRegisterTransport wraps one connection with its own framer.
//
// It deliberately takes no traceID or deviceID. newConnRegisterTransport uses
// those to drive a SIP trace hook that writes whole raw messages to the log;
// this path must never do that, so it does not accept the means to.
func newStreamRegisterTransport(conn net.Conn) (*streamRegisterTransport, error) {
	if conn == nil {
		return nil, errors.New("imscore: stream transport requires a connection")
	}
	return &streamRegisterTransport{
		conn:   conn,
		framer: newSIPStreamFramer(defaultSIPFramerLimits()),
	}, nil
}

// SendPayload writes one already-serialized SIP message.
//
// TCP is a byte stream, so a short write is a truncated message rather than a
// dropped datagram. net.Conn.Write already loops until the whole buffer is
// written or it errors, so the only thing to add is refusing an empty payload.
func (t *streamRegisterTransport) SendPayload(ctx context.Context, payload []byte) error {
	if t == nil {
		return errors.New("imscore: stream transport unavailable")
	}
	if len(payload) == 0 {
		return errors.New("imscore: refusing to send an empty SIP message")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("imscore: stream transport closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.conn.SetWriteDeadline(time.Now().Add(registerTransportDeadline())); err != nil {
		return err
	}
	n, err := t.conn.Write(payload)
	// Count what actually left, even on an error or a short write: those bytes are
	// on the wire, and a measurement that ignored them would under-report progress
	// on exactly the failure this instrumentation exists to explain.
	if n > 0 {
		t.bytesWritten += n
	}
	if err != nil {
		return err
	}
	if n != len(payload) {
		// Defensive: a partial write would put a truncated request on the wire.
		return fmt.Errorf("imscore: short SIP write (%d of %d bytes)", n, len(payload))
	}
	return nil
}

// Send serializes and writes one request.
func (t *streamRegisterTransport) Send(ctx context.Context, req *sip.Request) error {
	if req == nil {
		return errors.New("imscore: stream transport unavailable")
	}
	return t.SendPayload(ctx, []byte(req.String()))
}

// ReadResponse returns the next complete SIP response.
//
// It loops because a Read can return a partial message, several messages, or
// only the tail of one. The framer decides when a complete frame exists; this
// function never guesses from read sizes.
func (t *streamRegisterTransport) ReadResponse(ctx context.Context) (*sip.Response, error) {
	if t == nil {
		return nil, errors.New("imscore: stream transport unavailable")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errors.New("imscore: stream transport closed")
	}

	deadline := time.Now().Add(registerTransportDeadline())
	if err := t.conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	// A frame may already have been completed by an earlier read.
	if frame, ok := t.takePendingLocked(); ok {
		return parseStreamSIPResponse(frame)
	}
	if err := t.framer.Failed(); err != nil {
		return nil, err
	}

	buf := make([]byte, streamReadChunkLen)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, readErr := t.conn.Read(buf)
		if n > 0 {
			frames, err := t.framer.Push(buf[:n])
			if err != nil {
				return nil, err
			}
			t.pending = append(t.pending, frames...)
			t.framesProduced += len(frames)
			if frame, ok := t.takePendingLocked(); ok {
				return parseStreamSIPResponse(frame)
			}
		}
		if readErr != nil {
			// EOF while the framer still holds bytes is a truncated message, not a
			// clean close. CloseInput reports which one it was.
			if closeErr := t.framer.CloseInput(); closeErr != nil {
				return nil, closeErr
			}
			return nil, readErr
		}
	}
}

// Measurement reports what THIS transport observed: how many payload bytes were
// handed to the connection and how many complete SIP messages the framer
// produced.
//
// It reports only what this layer can see. The segment counts, the largest inner
// ESP packet and the acknowledged byte progress live one layer down, in the
// protected link endpoint, and are merged in by mergeProtectedTCPRuntimeStats.
// Splitting it this way is deliberate: neither layer invents a number it cannot
// observe, which is exactly the defect this replaces.
func (t *streamRegisterTransport) Measurement() protectedTCPMeasurement {
	if t == nil {
		return protectedTCPMeasurement{Closure: protectedTCPClosureUnknown}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return protectedTCPMeasurement{
		BytesWritten:   t.bytesWritten,
		ResponseFrames: t.framesProduced,
		Closure:        protectedTCPClosureUnknown,
	}
}

// takePendingLocked pops the oldest completed frame. The caller holds t.mu.
func (t *streamRegisterTransport) takePendingLocked() ([]byte, bool) {
	if len(t.pending) == 0 {
		return nil, false
	}
	frame := t.pending[0]
	t.pending = t.pending[1:]
	return frame, true
}

// FramesProduced is how many COMPLETE SIP messages the framer has produced on
// this connection.
//
// It is a count of whole messages, not of reads or of bytes, which is what
// distinguishes "the peer sent nothing" from "the peer sent something that never
// completed a message". A partial message in the buffer is deliberately not
// counted: it is not a frame yet.
func (t *streamRegisterTransport) FramesProduced() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.framesProduced
}

// AtMessageBoundary reports whether registration consumed every framed byte on
// this borrowed connection. It transfers no connection ownership; the enclosing
// ProtectedChannel remains the sole owner throughout REGISTER and messaging.
func (t *streamRegisterTransport) AtMessageBoundary() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.closed && len(t.pending) == 0 && t.framer.Buffered() == 0
}

// streamReadChunkLen is one Read's buffer. It is unrelated to message size: the
// framer reassembles across reads.
const streamReadChunkLen = 4096

// parseStreamSIPResponse parses one COMPLETE frame.
//
// The framer guarantees the frame is exactly one message, so a stream parser
// must yield exactly one response from it. Anything else means the frame and the
// parser disagree, which is treated as an error rather than silently taking the
// first message.
func parseStreamSIPResponse(frame []byte) (*sip.Response, error) {
	parser := sip.NewParser().NewSIPStream()
	defer parser.Close()

	var found *sip.Response
	count := 0
	parseErr := parser.ParseSIPStream(frame, func(msg sip.Message) {
		count++
		if res, ok := msg.(*sip.Response); ok && found == nil {
			found = res
		}
	})
	if parseErr != nil {
		return nil, parseErr
	}
	if count != 1 {
		return nil, fmt.Errorf("imscore: framed SIP message yielded %d messages", count)
	}
	if found == nil {
		return nil, errors.New("imscore: framed SIP message is not a response")
	}
	return found, nil
}

// Close closes the connection and drops any buffered bytes.
func (t *streamRegisterTransport) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	t.framer.Reset()
	return t.conn.Close()
}
