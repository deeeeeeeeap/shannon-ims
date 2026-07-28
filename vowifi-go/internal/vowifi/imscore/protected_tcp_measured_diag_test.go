package imscore

import (
	"net"
	"testing"
	"time"

	swulogger "github.com/1239t/swu-go/pkg/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type shortWriteMeasurementConn struct {
	written int
}

func (c *shortWriteMeasurementConn) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (c *shortWriteMeasurementConn) Write(p []byte) (int, error) {
	c.written = len(p) / 3
	return c.written, nil
}
func (*shortWriteMeasurementConn) Close() error                     { return nil }
func (*shortWriteMeasurementConn) LocalAddr() net.Addr              { return registerTestAddr("local") }
func (*shortWriteMeasurementConn) RemoteAddr() net.Addr             { return registerTestAddr("remote") }
func (*shortWriteMeasurementConn) SetDeadline(time.Time) error      { return nil }
func (*shortWriteMeasurementConn) SetReadDeadline(time.Time) error  { return nil }
func (*shortWriteMeasurementConn) SetWriteDeadline(time.Time) error { return nil }

// Phase G step 2: the TCP path must report what it MEASURED, not what a UDP
// model predicted.
//
// The 2026-07-27 21:48 run emitted this for the TCP attempt:
//
//	transport=tcp  sip_message_len=1362  inner_packet_len=1452
//	raw_ip_packet_count=2  fragmented=true
//
// Every one of those derived numbers came from registerProtectedInnerPacketLen,
// which models a single ESP-encapsulated UDP datagram:
//
//	inner = 40(IPv6) + 8(ESP) + 16(IV) + roundUp16(8 + sipLen + 2) + 12(ICV)
//
// For sipLen=1362 that is exactly 1452, which is why the two log lines agreed.
// But the TCP path does not send one datagram: the MSS clamp splits the request
// into TCP segments, each of which is separately ESP-encapsulated. So
// inner_packet_len=1452 and fragmented=true described a packet that was never
// constructed, and the log could neither prove nor disprove fragmentation.
//
// A predicted number that looks authoritative is worse than no number, because
// it is indistinguishable from a measurement in a log. So the UDP prediction is
// REMOVED from this path rather than supplemented.
//
// What replaces it is only what the runtime observed. Notably absent: raw
// sequence and acknowledgement numbers. Byte PROGRESS (written, acknowledged) is
// enough to tell "nothing was accepted" from "everything was accepted", and
// carries no wire-identifying state.
//
// Assertions are counts, lengths, bools and closed enums. No SIP text, address,
// port value, SPI, key, seq or ack appears here.

// observeProtectedTCPDiag captures one diagnostic line.
func observeProtectedTCPDiag(t *testing.T, emit func()) map[string]zap.Field {
	t.Helper()
	core, observed := observer.New(zap.DebugLevel)
	swulogger.SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	emit()

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic entry count = %d, want 1", len(entries))
	}
	fields := map[string]zap.Field{}
	for _, field := range entries[0].Context {
		fields[field.Key] = field
	}
	return fields
}

// ---------------------------------------------------------------------------
// G2.1: the UDP prediction is gone from the TCP path
// ---------------------------------------------------------------------------

// The measured emitter must not carry the UDP-model fields at all. Their absence
// is the point: a reader must not be able to mistake a prediction for a
// measurement.
func TestProtectedTCPDiagnosticDropsUDPPredictionFields(t *testing.T) {
	measured := protectedTCPMeasurement{
		SerializedMessageLen: 1362,
		DataSegments:         2,
		MaxInnerPacketLen:    1276,
		Fragmented:           false,
		BytesWritten:         1362,
		BytesAcknowledged:    0,
		FullyAcknowledged:    false,
		Retransmissions:      4,
		EffectiveMSS:         1178,
		ResponseFrames:       0,
		Closure:              protectedTCPClosureReadTimeout,
	}
	fields := observeProtectedTCPDiag(t, func() {
		logProtectedTCPMeasurement(measured)
	})

	// The UDP-model keys must be absent, not merely zero: a zero would still read
	// as "measured 0".
	for _, key := range []string{"inner_packet_len", "raw_ip_packet_count", "exceeds_udp_mtu_limit"} {
		if _, present := fields[key]; present {
			t.Fatalf("the measured TCP diagnostic still carries the UDP-model key %q", key)
		}
	}
	if got := fields["transport"].String; got != "tcp" {
		t.Fatalf("transport = %q, want tcp", got)
	}
	t.Logf("MEASURED udp_prediction_keys=0 transport=tcp")
}

// ---------------------------------------------------------------------------
// G2.2: every measured field is present and whitelisted
// ---------------------------------------------------------------------------

func TestProtectedTCPDiagnosticReportsMeasuredFields(t *testing.T) {
	measured := protectedTCPMeasurement{
		SerializedMessageLen: 1362,
		DataSegments:         2,
		MaxInnerPacketLen:    1276,
		Fragmented:           false,
		BytesWritten:         1362,
		BytesAcknowledged:    1362,
		FullyAcknowledged:    true,
		Retransmissions:      0,
		EffectiveMSS:         1178,
		ResponseFrames:       1,
		Closure:              protectedTCPClosureResponseComplete,
	}
	fields := observeProtectedTCPDiag(t, func() {
		logProtectedTCPMeasurement(measured)
	})

	allowed := registerDiagnosticAllowedFieldKeys()
	for _, key := range []string{
		"tcp_data_segments",
		"tcp_max_inner_packet_len",
		"tcp_fragmented",
		"tcp_bytes_written",
		"tcp_bytes_acked",
		"tcp_fully_acked",
		"tcp_retransmissions",
		"tcp_effective_mss",
		"tcp_response_frames",
		"tcp_closure",
	} {
		if _, present := fields[key]; !present {
			t.Fatalf("the measured diagnostic is missing %q", key)
		}
		if _, ok := allowed[key]; !ok {
			t.Fatalf("field %q is emitted but not whitelisted", key)
		}
	}

	if got := fields["tcp_data_segments"].Integer; got != 2 {
		t.Fatalf("tcp_data_segments = %d, want 2", got)
	}
	if got := fields["tcp_max_inner_packet_len"].Integer; got != 1276 {
		t.Fatalf("tcp_max_inner_packet_len = %d, want 1276", got)
	}
	if got := fields["tcp_bytes_acked"].Integer; got != 1362 {
		t.Fatalf("tcp_bytes_acked = %d, want 1362", got)
	}
	if got := fields["tcp_fully_acked"].Integer; got != 1 {
		t.Fatalf("tcp_fully_acked = %d, want 1 (true)", got)
	}
	if got := fields["tcp_effective_mss"].Integer; got != 1178 {
		t.Fatalf("tcp_effective_mss = %d, want 1178", got)
	}
	if got := fields["tcp_closure"].String; got != protectedTCPClosureResponseComplete {
		t.Fatalf("tcp_closure = %q, want %q", got, protectedTCPClosureResponseComplete)
	}
	t.Logf("MEASURED measured_fields=10 all_whitelisted=true")
}

// ---------------------------------------------------------------------------
// G2.3: no raw sequence or acknowledgement state
// ---------------------------------------------------------------------------

// Byte progress is permitted; wire sequence numbers are not. A seq/ack pair
// identifies a specific connection's state and is exactly the kind of value this
// project keeps out of logs.
func TestProtectedTCPDiagnosticNeverLogsSequenceNumbers(t *testing.T) {
	allowed := registerDiagnosticAllowedFieldKeys()
	for _, forbidden := range []string{
		"tcp_seq", "tcp_ack", "tcp_seq_num", "tcp_ack_num",
		"seq", "ack", "tcp_snd_nxt", "tcp_snd_una", "tcp_rcv_nxt",
		"tcp_window", "tcp_local_port", "tcp_remote_port",
	} {
		if _, present := allowed[forbidden]; present {
			t.Fatalf("the diagnostic allowlist contains wire state %q", forbidden)
		}
	}

	// And the emitter itself must not produce any key that looks like sequence
	// state, even under a different name.
	fields := observeProtectedTCPDiag(t, func() {
		logProtectedTCPMeasurement(protectedTCPMeasurement{
			DataSegments: 1,
			EffectiveMSS: 1178,
			Closure:      protectedTCPClosureReadTimeout,
		})
	})
	for key := range fields {
		switch key {
		case "tcp_seq", "tcp_ack", "seq", "ack":
			t.Fatalf("the emitter produced wire state %q", key)
		}
	}
	t.Logf("MEASURED sequence_keys=0 byte_progress_only=true")
}

// ---------------------------------------------------------------------------
// G2.4: bounds and closed enums
// ---------------------------------------------------------------------------

// Every counter must be clamped like the ESP counters, and the closure reason
// must collapse to a closed enum.
func TestProtectedTCPMeasurementIsBoundedAndClosed(t *testing.T) {
	fields := observeProtectedTCPDiag(t, func() {
		logProtectedTCPMeasurement(protectedTCPMeasurement{
			DataSegments:      -5,
			MaxInnerPacketLen: registerESPCounterMax + 9000,
			BytesWritten:      -1,
			BytesAcknowledged: registerESPCounterMax + 1,
			Retransmissions:   -3,
			EffectiveMSS:      -7,
			ResponseFrames:    registerESPCounterMax + 4,
			Closure:           "something the peer chose",
		})
	})

	for _, key := range []string{
		"tcp_data_segments", "tcp_max_inner_packet_len", "tcp_bytes_written",
		"tcp_bytes_acked", "tcp_retransmissions", "tcp_effective_mss",
		"tcp_response_frames",
	} {
		got := fields[key].Integer
		if got < 0 || got > int64(registerESPCounterMax) {
			t.Fatalf("%s = %d, want clamped to 0..%d", key, got, registerESPCounterMax)
		}
	}
	if got := fields["tcp_closure"].String; got != protectedTCPClosureUnknown {
		t.Fatalf("tcp_closure = %q, want %q for an unmodelled reason", got, protectedTCPClosureUnknown)
	}
	t.Logf("MEASURED clamped=7 closure_collapsed_to=%s", protectedTCPClosureUnknown)
}

// The closure enum must cover the outcomes this path can actually produce, and
// each must survive canonicalisation unchanged.
func TestProtectedTCPClosureEnumIsStable(t *testing.T) {
	for _, closure := range []string{
		protectedTCPClosureResponseComplete,
		protectedTCPClosureReadTimeout,
		protectedTCPClosurePeerClosed,
		protectedTCPClosureTruncated,
		protectedTCPClosureFramingRejected,
		protectedTCPClosureWriteFailed,
		protectedTCPClosureHandshakeFailed,
		protectedTCPClosureCancelled,
		protectedTCPClosureUnknown,
	} {
		t.Run(closure, func(t *testing.T) {
			if got := canonicalProtectedTCPClosure(closure); got != closure {
				t.Fatalf("canonical(%q) = %q", closure, got)
			}
		})
	}
	// Anything else collapses.
	for _, bogus := range []string{"", "  ", "peer said no", "504"} {
		if got := canonicalProtectedTCPClosure(bogus); got != protectedTCPClosureUnknown {
			t.Fatalf("canonical(%q) = %q, want unknown", bogus, got)
		}
	}
	t.Logf("MEASURED closure_enum_size=9 unmodelled_collapse=true")
}

// ---------------------------------------------------------------------------
// G2.5: the measurement is derived from the transport, not hand-assembled
// ---------------------------------------------------------------------------

// The whole failure this replaces was a hand-assembled number that looked
// measured. So the measurement must come from the connection's own counters.
func TestProtectedTCPMeasurementComesFromTransportCounters(t *testing.T) {
	// A stream transport that has written a request and received nothing.
	carrier := newRuntimeCarrier()
	transport, err := newStreamRegisterTransport(carrier)
	if err != nil {
		t.Fatalf("newStreamRegisterTransport: %v", err)
	}

	measured := transport.Measurement()
	// Nothing sent yet: every counter is zero and the closure is unknown rather
	// than a guess.
	if measured.BytesWritten != 0 || measured.ResponseFrames != 0 {
		t.Fatal("a fresh transport reports non-zero progress")
	}
	if measured.FullyAcknowledged {
		t.Fatal("a fresh transport claims full acknowledgement")
	}

	// After a write the byte count must reflect what was handed to the connection.
	payload := []byte("REGISTER sip:example.invalid SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	if err := transport.SendPayload(t.Context(), payload); err != nil {
		t.Fatalf("SendPayload: %v", err)
	}
	measured = transport.Measurement()
	if measured.BytesWritten != len(payload) {
		t.Fatalf("BytesWritten = %d, want %d", measured.BytesWritten, len(payload))
	}
	t.Logf("MEASURED derived_from_transport=true bytes_written=%d", measured.BytesWritten)
}

func TestProtectedTCPExchangeUsesActualShortWriteMeasurement(t *testing.T) {
	conn := &shortWriteMeasurementConn{}
	transport, err := newStreamRegisterTransport(conn)
	if err != nil {
		t.Fatalf("newStreamRegisterTransport: %v", err)
	}
	payload := []byte("synthetic protected request bytes")
	if err := transport.SendPayload(t.Context(), payload); err == nil {
		t.Fatal("short write unexpectedly succeeded")
	}

	measurement := protectedTCPMeasurement{
		SerializedMessageLen: len(payload),
		BytesWritten:         len(payload),
	}
	mergeProtectedTCPTransportMeasurement(&measurement, transport)
	if measurement.BytesWritten != conn.written {
		t.Fatalf("BytesWritten = %d, want actual %d", measurement.BytesWritten, conn.written)
	}
	if measurement.BytesWritten == len(payload) {
		t.Fatal("measurement retained the intended payload length after a short write")
	}
	if measurement.SerializedMessageLen != len(payload) {
		t.Fatalf("SerializedMessageLen = %d, want %d", measurement.SerializedMessageLen, len(payload))
	}
}
