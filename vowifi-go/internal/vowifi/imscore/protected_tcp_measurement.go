package imscore

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"

	"github.com/1239t/swu-go/pkg/logger"
	"go.uber.org/zap"
)

// Phase G step 2: what the protected TCP path actually observed.
//
// This type exists because the previous diagnostic on this path reported a
// PREDICTION dressed as a measurement. logProtectedTransportDecision called
// registerProtectedInnerPacketLen, which models one ESP-encapsulated UDP
// datagram:
//
//	inner = 40(IPv6) + 8(ESP) + 16(IV) + roundUp16(8 + sipLen + 2) + 12(ICV)
//
// On the TCP path that model is simply wrong: the MSS clamp splits the request
// into segments and each segment is separately encapsulated. The live run
// reported inner_packet_len=1452 / fragmented=true for a packet that was never
// built, which meant the log could neither prove nor disprove fragmentation.
//
// So the prediction is removed rather than supplemented. A number that looks
// authoritative but is not measured is worse than no number, because a reader
// cannot tell the difference.
//
// Deliberately absent: raw sequence and acknowledgement numbers. Byte PROGRESS
// distinguishes "nothing was accepted" from "everything was accepted", which is
// what a stalled send needs, and carries no connection-identifying wire state.
type protectedTCPMeasurement struct {
	// SerializedMessageLen is the complete SIP request length before the stream
	// write. It stays distinct from BytesWritten so a short write remains visible.
	SerializedMessageLen int

	// DataSegments is how many TCP segments carrying payload the stack emitted.
	DataSegments int
	// MaxInnerPacketLen is the largest ESP inner packet observed for this flow.
	// This is the number that answers "did anything exceed the SWu MTU".
	MaxInnerPacketLen int
	// Fragmented reports whether IP fragmentation was actually required.
	Fragmented bool

	// BytesWritten is how many payload bytes were handed to the connection.
	BytesWritten int
	// BytesAcknowledged is how many of those the peer's TCP acknowledged.
	BytesAcknowledged int
	// FullyAcknowledged is BytesAcknowledged >= BytesWritten with a non-zero
	// write. It is recorded separately so a reader does not have to compare two
	// clamped integers.
	FullyAcknowledged bool
	// Retransmissions is how many segments the stack sent more than once.
	Retransmissions int

	// EffectiveMSS is the send MSS in force after the clamp.
	EffectiveMSS int

	// ResponseFrames is how many complete SIP messages the framer produced.
	ResponseFrames int

	// Closure is the closed-enum reason the exchange ended.
	Closure string
}

// mergeProtectedTCPTransportMeasurement copies only counters observed by the SIP
// stream transport. In particular, BytesWritten is the count returned by
// net.Conn.Write, not the intended serialized request length.
func mergeProtectedTCPTransportMeasurement(m *protectedTCPMeasurement, transport *streamRegisterTransport) {
	if m == nil || transport == nil {
		return
	}
	observed := transport.Measurement()
	m.BytesWritten = observed.BytesWritten
	m.ResponseFrames = observed.ResponseFrames
}

// The closure enum. Every value describes a decision this code made or an
// observable transport event; none carries a peer-chosen string.
const (
	protectedTCPClosureResponseComplete = "response_complete"
	protectedTCPClosureReadTimeout      = "read_timeout"
	protectedTCPClosurePeerClosed       = "peer_closed"
	protectedTCPClosureTruncated        = "truncated_mid_message"
	protectedTCPClosureFramingRejected  = "framing_rejected"
	protectedTCPClosureWriteFailed      = "write_failed"
	protectedTCPClosureHandshakeFailed  = "handshake_failed"
	protectedTCPClosureCancelled        = "cancelled"
	protectedTCPClosureUnknown          = "unknown"
)

func canonicalProtectedTCPClosure(value string) string {
	switch strings.TrimSpace(value) {
	case protectedTCPClosureResponseComplete,
		protectedTCPClosureReadTimeout,
		protectedTCPClosurePeerClosed,
		protectedTCPClosureTruncated,
		protectedTCPClosureFramingRejected,
		protectedTCPClosureWriteFailed,
		protectedTCPClosureHandshakeFailed,
		protectedTCPClosureCancelled:
		return strings.TrimSpace(value)
	default:
		return protectedTCPClosureUnknown
	}
}

// mergeProtectedTCPRuntimeStats fills in what only the runtime can observe: the
// segment counts, the largest inner packet, whether anything fragmented, and how
// many payload bytes the peer's TCP acknowledged.
//
// It is called from a deferred block on every exit, so a stalled send reports the
// same fields as a successful one. A nil runtime leaves the measurement untouched
// rather than zeroing it, because a zero reads as "measured zero".
func mergeProtectedTCPRuntimeStats(m *protectedTCPMeasurement, rt *protectedTCPRuntime) {
	if m == nil || rt == nil {
		return
	}
	snapshot := rt.Snapshot()
	m.DataSegments = boundRegisterESPCounterU64(snapshot.DataSegments)
	m.MaxInnerPacketLen = boundRegisterESPCounterU64(snapshot.MaxInnerPacketLen)
	m.BytesAcknowledged = boundRegisterESPCounterU64(snapshot.AckedBytes)
	m.Retransmissions = rt.ClientFlowRetransmissions()

	// Fragmentation is DERIVED from the largest packet actually written, not from
	// a model. The endpoint refuses to write anything over the inner MTU, so a
	// value above it would mean the fail-closed guard was bypassed - which is why
	// this is computed rather than assumed false.
	m.Fragmented = m.MaxInnerPacketLen > registerProtectedInnerMTU

	m.FullyAcknowledged = m.BytesWritten > 0 && m.BytesAcknowledged >= m.BytesWritten
	if m.EffectiveMSS <= 0 {
		m.EffectiveMSS = rt.SafeMSS()
	}
}

// classifyProtectedTCPReadFailure maps a read error to the closed closure enum.
//
// The mapping is deliberately coarse. A finer classification would have to look at
// the error text, and peer-influenced text is exactly what must not reach a log
// line. Four buckets are enough to separate the cases that call for different
// action: nothing arrived, the peer hung up, a partial message was cut off, and
// the bytes were not valid SIP.
func classifyProtectedTCPReadFailure(err error) string {
	if err == nil {
		return protectedTCPClosureUnknown
	}
	switch {
	case errors.Is(err, context.Canceled):
		return protectedTCPClosureCancelled
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return protectedTCPClosureReadTimeout
	}
	// A framing rejection is typed, so it is distinguishable without text matching.
	var framing *sipFramingError
	if errors.As(err, &framing) {
		if framing.reason == sipFramingReasonTruncated {
			return protectedTCPClosureTruncated
		}
		return protectedTCPClosureFramingRejected
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return protectedTCPClosurePeerClosed
	}
	return protectedTCPClosureUnknown
}

// logProtectedTCPMeasurement emits one line describing what the protected TCP
// exchange did.
//
// It intentionally does NOT reuse logRegisterDiagnostic: that emitter always
// writes inner_packet_len, raw_ip_packet_count and exceeds_udp_mtu_limit, and
// those three UDP-model keys are exactly what must not appear on this path. Their
// absence is load-bearing, so a zero value would not do - a zero still reads as
// "measured zero".
//
// Every integer is clamped by the same bound as the ESP counters, and the closure
// collapses to a closed enum. No SIP text, identity, address, port value, SPI,
// key, sequence or acknowledgement number is written.
func logProtectedTCPMeasurement(m protectedTCPMeasurement) {
	logger.Info("IMS REGISTER diagnostic",
		[]zap.Field{
			logger.String("stage", canonicalRegisterDiagnosticStage("protected_send")),
			logger.String("result", canonicalRegisterDiagnosticResult("sending")),
			logger.String("transport", canonicalRegisterTransportDiagnostic(protectedTransportTCP)),
			logger.Bool("protected", true),
			logger.Bool("ipsec_installed", true),
			logger.Int("sip_message_len", boundRegisterESPCounter(m.SerializedMessageLen)),
			logger.Int("tcp_data_segments", boundRegisterESPCounter(m.DataSegments)),
			logger.Int("tcp_max_inner_packet_len", boundRegisterESPCounter(m.MaxInnerPacketLen)),
			logger.Bool("tcp_fragmented", m.Fragmented),
			logger.Int("tcp_bytes_written", boundRegisterESPCounter(m.BytesWritten)),
			logger.Int("tcp_bytes_acked", boundRegisterESPCounter(m.BytesAcknowledged)),
			logger.Bool("tcp_fully_acked", m.FullyAcknowledged),
			logger.Int("tcp_retransmissions", boundRegisterESPCounter(m.Retransmissions)),
			logger.Int("tcp_effective_mss", boundRegisterESPCounter(m.EffectiveMSS)),
			logger.Int("tcp_response_frames", boundRegisterESPCounter(m.ResponseFrames)),
			logger.String("tcp_closure", canonicalProtectedTCPClosure(m.Closure)),
		}...)
}
