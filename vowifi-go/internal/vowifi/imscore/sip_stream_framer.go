package imscore

import (
	"bytes"
	"fmt"
)

// Phase E: bounded SIP framing for a stream transport.
//
// On UDP a datagram IS a message. On TCP there is no boundary, so RFC 3261
// clause 7.5 makes Content-Length authoritative and mandatory:
//
//	"In the case of a stream-oriented transport such as TCP, the Content-Length
//	 header field indicates the size of the body. The Content-Length header
//	 field MUST be used with stream oriented transports."
//
// Two consequences drive this file. A message ends exactly where Content-Length
// says, and a missing or malformed Content-Length is a defect rather than a
// hint - guessing a boundary (say, the first blank line) would let a peer choose
// where the next "message" starts.
//
// Every accumulation is bounded because the peer controls the byte stream. An
// unterminated header section or an enormous declared body would otherwise grow
// the buffer until the process dies, and the protected connection is reachable
// by whatever the P-CSCF's own peer can reach.
//
// One framer belongs to one connection. The client flow and the server flow are
// different peers writing concurrently, so a shared buffer would splice one
// stream into the other.
//
// Nothing here logs, wraps or returns stream content. Errors carry a closed-enum
// reason and nothing else.

// sipFramerLimits bounds one connection's buffering.
type sipFramerLimits struct {
	// MaxHeaderBytes bounds the start line plus header section, including the
	// terminating blank line.
	MaxHeaderBytes int
	// MaxBodyBytes bounds the declared Content-Length.
	MaxBodyBytes int
}

// defaultSIPFramerLimits are sized for IMS REGISTER traffic with headroom, not
// for arbitrary SIP: a protected REGISTER on this path is around 1.4 KiB, and
// the largest thing expected inbound is a reg-event NOTIFY body.
func defaultSIPFramerLimits() sipFramerLimits {
	return sipFramerLimits{
		MaxHeaderBytes: 16 * 1024,
		MaxBodyBytes:   64 * 1024,
	}
}

// normalized replaces missing or nonsensical bounds with the defaults. A zero
// limit must never mean "unbounded".
func (l sipFramerLimits) normalized() sipFramerLimits {
	defaults := defaultSIPFramerLimits()
	if l.MaxHeaderBytes <= 0 {
		l.MaxHeaderBytes = defaults.MaxHeaderBytes
	}
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = defaults.MaxBodyBytes
	}
	return l
}

// Framing failure reasons. Closed enum, safe to log.
const (
	sipFramingReasonBadStartLine             = "bad_start_line"
	sipFramingReasonMissingContentLength     = "missing_content_length"
	sipFramingReasonBadContentLength         = "bad_content_length"
	sipFramingReasonConflictingContentLength = "conflicting_content_length"
	sipFramingReasonHeaderTooLarge           = "header_too_large"
	sipFramingReasonBodyTooLarge             = "body_too_large"
	sipFramingReasonTruncated                = "truncated"
)

// sipFramingError is a classified framing failure. It deliberately carries no
// offset, no length and no stream bytes: this error is logged, and the stream is
// SIP.
type sipFramingError struct {
	reason string
}

func (e *sipFramingError) Error() string {
	return fmt.Sprintf("imscore: SIP stream framing failed (reason=%s)", e.reason)
}

// Reason exposes the classification for diagnostics.
func (e *sipFramingError) Reason() string {
	if e == nil {
		return ""
	}
	return e.reason
}

// sipStreamFramer turns a byte stream into whole SIP messages.
//
// It is not safe for concurrent use: one connection's reader owns it.
type sipStreamFramer struct {
	limits sipFramerLimits

	buf []byte
	// headerDone reports that the current message's header section has been
	// parsed and headerLen/bodyLen are authoritative.
	headerDone bool
	headerLen  int
	bodyLen    int

	// failed latches the first framing error. A stream that has lost sync cannot
	// be resynchronised: the next parse would start at an offset the peer chose.
	failed error
}

func newSIPStreamFramer(limits sipFramerLimits) *sipStreamFramer {
	// Stored by value, so a caller mutating its own struct afterwards cannot
	// widen this framer's ceiling.
	return &sipStreamFramer{limits: limits.normalized()}
}

var sipHeaderTerminator = []byte("\r\n\r\n")

// Push feeds bytes and returns every complete message they completed, in order.
//
// It returns the framer's latched error once framing has failed, and never
// returns a partial message.
func (f *sipStreamFramer) Push(data []byte) ([][]byte, error) {
	if f == nil {
		return nil, &sipFramingError{reason: sipFramingReasonTruncated}
	}
	if f.failed != nil {
		return nil, f.failed
	}
	if len(data) > 0 {
		f.buf = append(f.buf, data...)
	}

	var frames [][]byte
	for {
		if !f.headerDone {
			// RFC 3261 clause 7.5 requires a stream parser to ignore CRLF that
			// appears before a start line, which is also how keep-alive pings are
			// framed. Skipping them here means a ping cannot be mistaken for a
			// malformed message.
			f.skipLeadingCRLF()

			idx := bytes.Index(f.buf, sipHeaderTerminator)
			if idx < 0 {
				if len(f.buf) > f.limits.MaxHeaderBytes {
					return frames, f.fail(sipFramingReasonHeaderTooLarge)
				}
				return frames, nil
			}
			headerEnd := idx + len(sipHeaderTerminator)
			if headerEnd > f.limits.MaxHeaderBytes {
				return frames, f.fail(sipFramingReasonHeaderTooLarge)
			}

			header := f.buf[:idx]
			if !validSIPStartLine(header) {
				return frames, f.fail(sipFramingReasonBadStartLine)
			}
			bodyLen, reason := declaredContentLength(header)
			if reason != "" {
				return frames, f.fail(reason)
			}
			// Refuse on the declaration, before a single body byte is buffered.
			if bodyLen > f.limits.MaxBodyBytes {
				return frames, f.fail(sipFramingReasonBodyTooLarge)
			}
			f.headerDone = true
			f.headerLen = headerEnd
			f.bodyLen = bodyLen
		}

		total := f.headerLen + f.bodyLen
		if len(f.buf) < total {
			// Bounded by construction: headerLen <= MaxHeaderBytes and bodyLen <=
			// MaxBodyBytes were both checked above.
			return frames, nil
		}

		frame := make([]byte, total)
		copy(frame, f.buf[:total])
		frames = append(frames, frame)

		// Copy the remainder down rather than reslicing, so a long-lived
		// connection does not retain every byte it has ever received.
		f.buf = append(f.buf[:0], f.buf[total:]...)
		f.headerDone = false
		f.headerLen = 0
		f.bodyLen = 0
	}
}

// CloseInput reports end of stream. A partially buffered message is a
// truncation, not a message.
func (f *sipStreamFramer) CloseInput() error {
	if f == nil {
		return nil
	}
	if f.failed != nil {
		return f.failed
	}
	if len(f.buf) > 0 {
		return f.fail(sipFramingReasonTruncated)
	}
	return nil
}

// Buffered is how many bytes are held for an incomplete message.
func (f *sipStreamFramer) Buffered() int {
	if f == nil {
		return 0
	}
	return len(f.buf)
}

// Failed reports the latched framing error, if any.
func (f *sipStreamFramer) Failed() error {
	if f == nil {
		return nil
	}
	return f.failed
}

// Reset clears the framer for a NEW connection.
//
// Recovery is deliberately tied to a new connection: it is not a resync inside a
// stream that has already lost its boundaries.
func (f *sipStreamFramer) Reset() {
	if f == nil {
		return
	}
	f.buf = nil
	f.headerDone = false
	f.headerLen = 0
	f.bodyLen = 0
	f.failed = nil
}

// fail latches the error and drops the buffer. The buffer is dropped because
// keeping it would invite a caller to retry from a position the peer chose.
func (f *sipStreamFramer) fail(reason string) error {
	f.failed = &sipFramingError{reason: reason}
	f.buf = nil
	f.headerDone = false
	f.headerLen = 0
	f.bodyLen = 0
	return f.failed
}

func (f *sipStreamFramer) skipLeadingCRLF() {
	for len(f.buf) >= 2 && f.buf[0] == '\r' && f.buf[1] == '\n' {
		f.buf = f.buf[2:]
	}
}

// validSIPStartLine accepts a status line or a request line, per RFC 3261
// clause 7.1. The check is case-sensitive because "SIP/2.0" is a literal.
func validSIPStartLine(header []byte) bool {
	line := header
	if idx := bytes.Index(header, []byte("\r\n")); idx >= 0 {
		line = header[:idx]
	}
	if len(line) == 0 {
		return false
	}
	// Status-Line: "SIP/2.0 <status> <reason>"
	if bytes.HasPrefix(line, []byte("SIP/2.0 ")) {
		return true
	}
	// Request-Line: "<METHOD> <Request-URI> SIP/2.0"
	if bytes.HasSuffix(line, []byte(" SIP/2.0")) {
		return bytes.Count(line, []byte(" ")) >= 2
	}
	return false
}

// maxParsedContentLength caps digit accumulation so a long run of digits cannot
// overflow. Anything at or above it is reported as-is and then rejected by the
// caller's body bound.
const maxParsedContentLength = 1 << 40

// declaredContentLength returns the body length declared by the header section.
//
// It returns a non-empty reason when the value is absent, malformed, or present
// more than once with differing values. RFC 3261 clause 7.3.1 permits a repeated
// header when the values agree, so an identical duplicate is accepted.
func declaredContentLength(header []byte) (int, string) {
	values := contentLengthValues(header)
	if len(values) == 0 {
		return 0, sipFramingReasonMissingContentLength
	}
	for _, v := range values[1:] {
		if v != values[0] {
			return 0, sipFramingReasonConflictingContentLength
		}
	}
	n, ok := parseStrictDigits(values[0])
	if !ok {
		return 0, sipFramingReasonBadContentLength
	}
	return n, ""
}

// contentLengthValues collects every Content-Length value in the header section,
// honouring the compact form "l" (RFC 3261 clause 20) and line folding
// (clause 7.3.1).
func contentLengthValues(header []byte) []string {
	lines := unfoldHeaderLines(header)
	// Skip the start line.
	if len(lines) > 0 {
		lines = lines[1:]
	}
	var values []string
	for _, line := range lines {
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := string(bytes.TrimSpace(line[:colon]))
		if !equalFoldASCII(name, "content-length") && !equalFoldASCII(name, "l") {
			continue
		}
		values = append(values, string(bytes.TrimSpace(line[colon+1:])))
	}
	return values
}

// unfoldHeaderLines splits a header section into logical lines, joining
// continuation lines onto the header they belong to.
func unfoldHeaderLines(header []byte) [][]byte {
	raw := bytes.Split(header, []byte("\r\n"))
	out := make([][]byte, 0, len(raw))
	for _, line := range raw {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && len(out) > 0 {
			joined := append(append([]byte(nil), out[len(out)-1]...), ' ')
			joined = append(joined, bytes.TrimSpace(line)...)
			out[len(out)-1] = joined
			continue
		}
		out = append(out, line)
	}
	return out
}

// parseStrictDigits accepts a non-empty run of ASCII digits and nothing else.
//
// strconv.Atoi is deliberately not used: it accepts a leading "+" or "-", and a
// signed Content-Length is a defect rather than a value to normalise.
func parseStrictDigits(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		if n < maxParsedContentLength {
			n = n*10 + int(c-'0')
		}
	}
	return n, true
}

// equalFoldASCII compares header names case-insensitively without allocating.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
