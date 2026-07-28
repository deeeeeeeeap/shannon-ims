package imscore

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Phase E: framing SIP on a protected TCP connection.
//
// UDP framing is "one datagram is one message". TCP has no such boundary, so
// RFC 3261 clause 7.5 makes the framing rules explicit:
//
//	"In the case of message-oriented transports (such as UDP), if the message
//	 has a Content-Length header field value that is greater than the size of
//	 the body ... the message MUST be discarded. ... In the case of a
//	 stream-oriented transport such as TCP, the Content-Length header field
//	 indicates the size of the body. The Content-Length header field MUST be
//	 used with stream oriented transports."
//
// So on TCP a message ends where Content-Length says, and a missing
// Content-Length is not a framing hint - it is a defect that makes the stream
// unparseable from that point on. Guessing (for example treating the first blank
// line as the end) would resynchronise on attacker-chosen boundaries.
//
// Every limit here exists because the peer controls the byte stream: an
// unbounded header section or body would let one connection consume memory until
// the process dies.
//
// The framer is owned per connection. Two connections must never share a buffer:
// the client flow and the server flow are different peers writing concurrently,
// and one stream's partial message must not appear in the other's.
//
// Nothing in this file logs or asserts SIP text, a header value, an identity, an
// address or a credential. Assertions are lengths, counts, booleans and closed
// enum classifications.

// ---------------------------------------------------------------------------
// helpers: build byte streams without asserting their content
// ---------------------------------------------------------------------------

// framerMessage builds a syntactically valid SIP response with a body of the
// requested size. The text is fixed and carries no identity.
func framerMessage(bodyLen int) []byte {
	body := strings.Repeat("x", bodyLen)
	return []byte("SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/TCP 192.0.2.1;branch=z9hG4bK0000\r\n" +
		"Call-ID: 00000000-0000-4000-8000-000000000000\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Content-Length: " + itoaE(bodyLen) + "\r\n" +
		"\r\n" + body)
}

func itoaE(v int) string {
	if v == 0 {
		return "0"
	}
	out := ""
	for v > 0 {
		out = string(rune('0'+v%10)) + out
		v /= 10
	}
	return out
}

// ---------------------------------------------------------------------------
// E.1: a whole message, then partial delivery
// ---------------------------------------------------------------------------

func TestSIPFramerReadsOneCompleteMessage(t *testing.T) {
	f := newSIPStreamFramer(defaultSIPFramerLimits())
	msg := framerMessage(16)

	frames, err := f.Push(msg)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	if len(frames[0]) != len(msg) {
		t.Fatalf("frame length = %d, want %d", len(frames[0]), len(msg))
	}
	if f.Buffered() != 0 {
		t.Fatalf("buffered = %d, want 0 after a clean frame", f.Buffered())
	}
	t.Logf("MEASURED frames=1 frame_len=%d buffered_after=0", len(frames[0]))
}

// A message split at every possible offset must still produce exactly one frame,
// and never a partial one. This is the property a datagram framer silently gets
// wrong.
func TestSIPFramerHandlesEveryPartialSplit(t *testing.T) {
	msg := framerMessage(24)
	for split := 1; split < len(msg); split++ {
		f := newSIPStreamFramer(defaultSIPFramerLimits())
		first, err := f.Push(msg[:split])
		if err != nil {
			t.Fatalf("split %d first Push: %v", split, err)
		}
		if len(first) != 0 {
			t.Fatalf("split %d produced %d frames from a partial message", split, len(first))
		}
		second, err := f.Push(msg[split:])
		if err != nil {
			t.Fatalf("split %d second Push: %v", split, err)
		}
		if len(second) != 1 {
			t.Fatalf("split %d produced %d frames, want 1", split, len(second))
		}
		if len(second[0]) != len(msg) {
			t.Fatalf("split %d reassembled %d bytes, want %d", split, len(second[0]), len(msg))
		}
		if f.Buffered() != 0 {
			t.Fatalf("split %d left %d bytes buffered", split, f.Buffered())
		}
	}
	t.Logf("MEASURED splits_tested=%d all_reassembled=true", len(msg)-1)
}

// Byte-at-a-time delivery is the worst case for a stream framer and the most
// realistic one for a small MSS.
func TestSIPFramerHandlesByteAtATimeDelivery(t *testing.T) {
	f := newSIPStreamFramer(defaultSIPFramerLimits())
	msg := framerMessage(8)

	total := 0
	for i := 0; i < len(msg); i++ {
		frames, err := f.Push(msg[i : i+1])
		if err != nil {
			t.Fatalf("byte %d: %v", i, err)
		}
		total += len(frames)
	}
	if total != 1 {
		t.Fatalf("frames = %d, want 1", total)
	}
	t.Logf("MEASURED pushes=%d frames=1", len(msg))
}

// ---------------------------------------------------------------------------
// E.2: pipelining
// ---------------------------------------------------------------------------

// Several messages in one read must all be returned, in order, with nothing left
// over. A framer that returns only the first would stall the exchange until the
// next read happens to arrive.
func TestSIPFramerReturnsPipelinedMessagesInOrder(t *testing.T) {
	f := newSIPStreamFramer(defaultSIPFramerLimits())
	var stream bytes.Buffer
	lengths := []int{0, 4, 32, 1}
	for _, n := range lengths {
		stream.Write(framerMessage(n))
	}

	frames, err := f.Push(stream.Bytes())
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(frames) != len(lengths) {
		t.Fatalf("frames = %d, want %d", len(frames), len(lengths))
	}
	for i, n := range lengths {
		want := len(framerMessage(n))
		if len(frames[i]) != want {
			t.Fatalf("frame %d length = %d, want %d", i, len(frames[i]), want)
		}
	}
	if f.Buffered() != 0 {
		t.Fatalf("buffered = %d, want 0", f.Buffered())
	}
	t.Logf("MEASURED pipelined_in=%d frames_out=%d order_preserved=true", len(lengths), len(frames))
}

// A pipelined stream cut mid-way must yield the complete messages and hold the
// remainder, without losing or duplicating a byte.
func TestSIPFramerHoldsPartialTailOfPipelinedStream(t *testing.T) {
	f := newSIPStreamFramer(defaultSIPFramerLimits())
	first := framerMessage(4)
	second := framerMessage(64)
	stream := append(append([]byte(nil), first...), second[:20]...)

	frames, err := f.Push(stream)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	if f.Buffered() != 20 {
		t.Fatalf("buffered = %d, want 20", f.Buffered())
	}
	rest, err := f.Push(second[20:])
	if err != nil {
		t.Fatalf("second Push: %v", err)
	}
	if len(rest) != 1 || len(rest[0]) != len(second) {
		t.Fatalf("tail did not reassemble: frames=%d", len(rest))
	}
	t.Logf("MEASURED complete_first=1 buffered_tail=20 tail_completed=true")
}

// ---------------------------------------------------------------------------
// E.3: Content-Length is mandatory and authoritative on TCP
// ---------------------------------------------------------------------------

// RFC 3261 clause 7.5: "The Content-Length header field MUST be used with stream
// oriented transports." Absent, the stream cannot be framed, so it must fail
// rather than guess a boundary.
func TestSIPFramerRejectsMissingContentLengthOnStream(t *testing.T) {
	f := newSIPStreamFramer(defaultSIPFramerLimits())
	msg := []byte("SIP/2.0 200 OK\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"\r\n")

	_, err := f.Push(msg)
	if err == nil {
		t.Fatal("a stream message without Content-Length was accepted")
	}
	var framing *sipFramingError
	if !errors.As(err, &framing) {
		t.Fatalf("error is not classified: %v", err)
	}
	if framing.Reason() != sipFramingReasonMissingContentLength {
		t.Fatalf("reason = %q, want %q", framing.Reason(), sipFramingReasonMissingContentLength)
	}
	// The error must not quote the stream.
	if strings.Contains(err.Error(), "SIP/2.0") || strings.Contains(err.Error(), "CSeq") {
		t.Fatal("the framing error quotes the message")
	}
	t.Logf("MEASURED missing_content_length_rejected=true reason=%s quoted=false", framing.Reason())
}

// Conflicting, negative, non-numeric or duplicated values are all defects, not
// hints. Each must fail closed with its own classification.
func TestSIPFramerRejectsMalformedContentLength(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		reason string
	}{
		{name: "negative", header: "Content-Length: -1\r\n", reason: sipFramingReasonBadContentLength},
		{name: "non_numeric", header: "Content-Length: abc\r\n", reason: sipFramingReasonBadContentLength},
		{name: "empty", header: "Content-Length: \r\n", reason: sipFramingReasonBadContentLength},
		{name: "plus_signed", header: "Content-Length: +8\r\n", reason: sipFramingReasonBadContentLength},
		{name: "hex", header: "Content-Length: 0x10\r\n", reason: sipFramingReasonBadContentLength},
		{name: "conflicting_duplicate", header: "Content-Length: 4\r\nContent-Length: 8\r\n", reason: sipFramingReasonConflictingContentLength},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSIPStreamFramer(defaultSIPFramerLimits())
			msg := []byte("SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\n" + tc.header + "\r\nxxxxxxxx")
			_, err := f.Push(msg)
			if err == nil {
				t.Fatal("a malformed Content-Length was accepted")
			}
			var framing *sipFramingError
			if !errors.As(err, &framing) {
				t.Fatalf("error is not classified: %v", err)
			}
			if framing.Reason() != tc.reason {
				t.Fatalf("reason = %q, want %q", framing.Reason(), tc.reason)
			}
			if strings.Contains(err.Error(), "Content-Length:") {
				t.Fatal("the error quotes the offending header")
			}
		})
	}
	t.Logf("MEASURED malformed_cases=6 all_failed_closed=true quoted=false")
}

// An identical duplicate is not a conflict: RFC 3261 clause 7.3.1 allows a
// header to appear more than once when the values agree. Accepting it avoids
// rejecting a legitimate proxy rewrite.
func TestSIPFramerAcceptsIdenticalDuplicateContentLength(t *testing.T) {
	f := newSIPStreamFramer(defaultSIPFramerLimits())
	msg := []byte("SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\n" +
		"Content-Length: 4\r\nContent-Length: 4\r\n\r\nabcd")

	frames, err := f.Push(msg)
	if err != nil {
		t.Fatalf("an identical duplicate was rejected: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	t.Logf("MEASURED identical_duplicate_accepted=true frames=1")
}

// The compact form "l:" is the same header (RFC 3261 clause 20), so it must be
// honoured or a compact-form peer would look like a missing Content-Length.
func TestSIPFramerHonoursCompactContentLengthForm(t *testing.T) {
	f := newSIPStreamFramer(defaultSIPFramerLimits())
	msg := []byte("SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\nl: 3\r\n\r\nabc")

	frames, err := f.Push(msg)
	if err != nil {
		t.Fatalf("compact form rejected: %v", err)
	}
	if len(frames) != 1 || len(frames[0]) != len(msg) {
		t.Fatalf("compact form framed incorrectly: frames=%d", len(frames))
	}
	t.Logf("MEASURED compact_form_accepted=true frames=1")
}

// ---------------------------------------------------------------------------
// E.4: bounds
// ---------------------------------------------------------------------------

// The peer controls the stream, so every accumulation must be bounded. A header
// section that never terminates must fail before the buffer grows without limit.
func TestSIPFramerBoundsHeaderSection(t *testing.T) {
	limits := defaultSIPFramerLimits()
	f := newSIPStreamFramer(limits)

	// Never send the terminating blank line.
	chunk := []byte(strings.Repeat("X-Pad: 0123456789abcdef\r\n", 64))
	var err error
	pushed := 0
	for i := 0; i < 4096 && err == nil; i++ {
		_, err = f.Push(chunk)
		pushed += len(chunk)
	}
	if err == nil {
		t.Fatalf("an unterminated header section was accepted after %d bytes", pushed)
	}
	var framing *sipFramingError
	if !errors.As(err, &framing) {
		t.Fatalf("error is not classified: %v", err)
	}
	if framing.Reason() != sipFramingReasonHeaderTooLarge {
		t.Fatalf("reason = %q, want %q", framing.Reason(), sipFramingReasonHeaderTooLarge)
	}
	if pushed > limits.MaxHeaderBytes+len(chunk) {
		t.Fatalf("accepted %d header bytes, limit is %d", pushed, limits.MaxHeaderBytes)
	}
	t.Logf("MEASURED header_limit=%d rejected_at<=%d reason=%s",
		limits.MaxHeaderBytes, pushed, framing.Reason())
}

// A declared body larger than the limit must be refused at the moment it is
// declared, not after it has been buffered.
func TestSIPFramerBoundsDeclaredBody(t *testing.T) {
	limits := defaultSIPFramerLimits()
	f := newSIPStreamFramer(limits)

	oversize := limits.MaxBodyBytes + 1
	header := []byte("SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\nContent-Length: " +
		itoaE(oversize) + "\r\n\r\n")

	_, err := f.Push(header)
	if err == nil {
		t.Fatal("an oversize declared body was accepted")
	}
	var framing *sipFramingError
	if !errors.As(err, &framing) {
		t.Fatalf("error is not classified: %v", err)
	}
	if framing.Reason() != sipFramingReasonBodyTooLarge {
		t.Fatalf("reason = %q, want %q", framing.Reason(), sipFramingReasonBodyTooLarge)
	}
	// Nothing of the body was buffered: the refusal happened on the declaration.
	if f.Buffered() > len(header) {
		t.Fatalf("buffered %d bytes while refusing", f.Buffered())
	}
	t.Logf("MEASURED body_limit=%d declared=%d refused_before_buffering=true",
		limits.MaxBodyBytes, oversize)
}

// The total buffer must be bounded too, so a stream of maximum-size headers plus
// a maximum-size body cannot exceed a known ceiling.
func TestSIPFramerBoundsTotalBuffer(t *testing.T) {
	limits := defaultSIPFramerLimits()
	f := newSIPStreamFramer(limits)

	// A valid header declaring the largest allowed body, then a slow body.
	body := limits.MaxBodyBytes
	header := []byte("SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\nContent-Length: " +
		itoaE(body) + "\r\n\r\n")
	if _, err := f.Push(header); err != nil {
		t.Fatalf("valid header rejected: %v", err)
	}
	chunk := bytes.Repeat([]byte("y"), 4096)
	sent := 0
	for sent < body {
		n := body - sent
		if n > len(chunk) {
			n = len(chunk)
		}
		frames, err := f.Push(chunk[:n])
		if err != nil {
			t.Fatalf("body push: %v", err)
		}
		sent += n
		if f.Buffered() > limits.MaxHeaderBytes+limits.MaxBodyBytes {
			t.Fatalf("buffer grew to %d, ceiling is %d",
				f.Buffered(), limits.MaxHeaderBytes+limits.MaxBodyBytes)
		}
		if sent == body && len(frames) != 1 {
			t.Fatalf("final push produced %d frames, want 1", len(frames))
		}
	}
	if f.Buffered() != 0 {
		t.Fatalf("buffered = %d after the frame completed", f.Buffered())
	}
	t.Logf("MEASURED body_bytes=%d ceiling=%d final_buffered=0",
		body, limits.MaxHeaderBytes+limits.MaxBodyBytes)
}

// ---------------------------------------------------------------------------
// E.5: malformed start line, EOF and cancel
// ---------------------------------------------------------------------------

// A stream that does not begin with a SIP start line cannot be resynchronised.
func TestSIPFramerRejectsMalformedStartLine(t *testing.T) {
	for _, tc := range []struct{ name, data string }{
		{name: "binary_garbage", data: "\x00\x01\x02\x03\r\n\r\n"},
		{name: "http_response", data: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
		{name: "empty_start_line", data: "\r\nContent-Length: 0\r\n\r\n"},
		{name: "lowercase_sip", data: "sip/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSIPStreamFramer(defaultSIPFramerLimits())
			_, err := f.Push([]byte(tc.data))
			if err == nil {
				t.Fatal("a malformed start line was accepted")
			}
			var framing *sipFramingError
			if !errors.As(err, &framing) {
				t.Fatalf("error is not classified: %v", err)
			}
			if framing.Reason() != sipFramingReasonBadStartLine {
				t.Fatalf("reason = %q, want %q", framing.Reason(), sipFramingReasonBadStartLine)
			}
			if strings.Contains(err.Error(), tc.data) {
				t.Fatal("the error quotes the stream")
			}
		})
	}
	t.Logf("MEASURED malformed_start_lines=4 all_rejected=true quoted=false")
}

// A framer that is closed with bytes still buffered must report the truncation
// rather than emitting a partial message as if it were complete.
func TestSIPFramerReportsTruncationOnEOF(t *testing.T) {
	f := newSIPStreamFramer(defaultSIPFramerLimits())
	msg := framerMessage(32)

	if _, err := f.Push(msg[:len(msg)-4]); err != nil {
		t.Fatalf("partial Push: %v", err)
	}
	if f.Buffered() == 0 {
		t.Fatal("nothing buffered before EOF")
	}
	err := f.CloseInput()
	if err == nil {
		t.Fatal("EOF with a partial message did not report truncation")
	}
	var framing *sipFramingError
	if !errors.As(err, &framing) {
		t.Fatalf("error is not classified: %v", err)
	}
	if framing.Reason() != sipFramingReasonTruncated {
		t.Fatalf("reason = %q, want %q", framing.Reason(), sipFramingReasonTruncated)
	}

	// A clean EOF on an empty buffer is not an error.
	clean := newSIPStreamFramer(defaultSIPFramerLimits())
	if _, err := clean.Push(msg); err != nil {
		t.Fatalf("complete Push: %v", err)
	}
	if err := clean.CloseInput(); err != nil {
		t.Fatalf("clean EOF reported an error: %v", err)
	}
	t.Logf("MEASURED truncated_eof_reported=true clean_eof_ok=true")
}

// Once a framing error has been reported the framer must stay failed. Resuming
// after a defect would mean parsing from an attacker-chosen offset.
func TestSIPFramerStaysFailedAfterError(t *testing.T) {
	f := newSIPStreamFramer(defaultSIPFramerLimits())
	if _, err := f.Push([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")); err == nil {
		t.Fatal("malformed stream accepted")
	}
	// A subsequent valid message must NOT be parsed.
	frames, err := f.Push(framerMessage(4))
	if err == nil {
		t.Fatal("the framer resumed after a framing error")
	}
	if len(frames) != 0 {
		t.Fatalf("the framer emitted %d frames after failing", len(frames))
	}
	// The buffer must be dropped, not retained for a retry.
	if f.Buffered() != 0 {
		t.Fatalf("buffered = %d after failure, want 0", f.Buffered())
	}
	t.Logf("MEASURED stays_failed=true frames_after_error=0 buffer_dropped=true")
}

// Reset must clear a failed framer so a NEW connection can reuse the value. The
// point is that recovery is tied to a new connection, not to a resync inside a
// broken one.
func TestSIPFramerResetClearsFailureForNewConnection(t *testing.T) {
	f := newSIPStreamFramer(defaultSIPFramerLimits())
	if _, err := f.Push([]byte("garbage\r\n\r\n")); err == nil {
		t.Fatal("malformed stream accepted")
	}
	f.Reset()
	frames, err := f.Push(framerMessage(8))
	if err != nil {
		t.Fatalf("after Reset: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	t.Logf("MEASURED reset_recovers=true frames=1")
}

// ---------------------------------------------------------------------------
// E.6: per-connection ownership
// ---------------------------------------------------------------------------

// Two framers must not share state. The client flow and the server flow are
// different peers, and a shared buffer would splice one stream into the other.
func TestSIPFramersAreIndependentPerConnection(t *testing.T) {
	client := newSIPStreamFramer(defaultSIPFramerLimits())
	server := newSIPStreamFramer(defaultSIPFramerLimits())

	clientMsg := framerMessage(12)
	serverMsg := framerMessage(48)

	// Interleave partial writes from both peers.
	if _, err := client.Push(clientMsg[:10]); err != nil {
		t.Fatalf("client partial: %v", err)
	}
	if _, err := server.Push(serverMsg[:30]); err != nil {
		t.Fatalf("server partial: %v", err)
	}
	if client.Buffered() != 10 || server.Buffered() != 30 {
		t.Fatalf("buffers crossed: client=%d server=%d", client.Buffered(), server.Buffered())
	}

	clientFrames, err := client.Push(clientMsg[10:])
	if err != nil {
		t.Fatalf("client completion: %v", err)
	}
	if len(clientFrames) != 1 || len(clientFrames[0]) != len(clientMsg) {
		t.Fatal("client stream did not reassemble independently")
	}
	// The server framer must be untouched by the client completing.
	if server.Buffered() != 30 {
		t.Fatalf("server buffer changed to %d", server.Buffered())
	}
	serverFrames, err := server.Push(serverMsg[30:])
	if err != nil {
		t.Fatalf("server completion: %v", err)
	}
	if len(serverFrames) != 1 || len(serverFrames[0]) != len(serverMsg) {
		t.Fatal("server stream did not reassemble independently")
	}

	// Failing one must not fail the other.
	broken := newSIPStreamFramer(defaultSIPFramerLimits())
	if _, err := broken.Push([]byte("HTTP/1.1 200 OK\r\n\r\n")); err == nil {
		t.Fatal("malformed accepted")
	}
	if _, err := client.Push(framerMessage(4)); err != nil {
		t.Fatalf("an unrelated framer failed: %v", err)
	}
	t.Logf("MEASURED independent_buffers=true cross_contamination=false")
}

// The limits must be a value, not package state, so one connection cannot widen
// another's ceiling.
func TestSIPFramerLimitsAreDefensiveCopies(t *testing.T) {
	limits := defaultSIPFramerLimits()
	f := newSIPStreamFramer(limits)

	// Mutating the caller's copy afterwards must not change the framer.
	limits.MaxBodyBytes = 1 << 30
	limits.MaxHeaderBytes = 1 << 30

	oversize := defaultSIPFramerLimits().MaxBodyBytes + 1
	_, err := f.Push([]byte("SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\nContent-Length: " +
		itoaE(oversize) + "\r\n\r\n"))
	if err == nil {
		t.Fatal("the framer adopted the caller's mutated limits")
	}
	t.Logf("MEASURED limits_copied=true")
}

// Zero or negative limits must fall back to the defaults rather than disabling
// the bounds entirely.
func TestSIPFramerRejectsUnboundedLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits sipFramerLimits
	}{
		{name: "zero", limits: sipFramerLimits{}},
		{name: "negative", limits: sipFramerLimits{MaxHeaderBytes: -1, MaxBodyBytes: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSIPStreamFramer(tc.limits)
			oversize := defaultSIPFramerLimits().MaxBodyBytes + 1
			_, err := f.Push([]byte("SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\nContent-Length: " +
				itoaE(oversize) + "\r\n\r\n"))
			if err == nil {
				t.Fatal("an unbounded framer was created")
			}
		})
	}
	t.Logf("MEASURED unbounded_limits_rejected=true")
}
