package smscodec

import "testing"

func TestClassifyRPDU(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		kind RPDUKind
	}{
		{name: "rp-data-ms", in: []byte{0x00, 0x01}, kind: RPDUKindData},
		{name: "rp-data-net", in: []byte{0x01, 0x01}, kind: RPDUKindData},
		{name: "rp-ack-ms", in: []byte{0x02, 0x01}, kind: RPDUKindAck},
		{name: "rp-ack-net", in: []byte{0x03, 0x01}, kind: RPDUKindAck},
		{name: "rp-error-ms", in: []byte{0x04, 0x0A, 0x01, 0x29, 0x00}, kind: RPDUKindError},
		{name: "rp-error-net", in: []byte{0x05, 0x0A, 0x01, 0x29, 0x00}, kind: RPDUKindError},
		{name: "unknown", in: []byte{0x7F, 0x01}, kind: RPDUKindUnknown},
		{name: "empty", in: []byte{}, kind: RPDUKindUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyRPDU(tc.in)
			if got.Kind != tc.kind {
				t.Fatalf("kind mismatch: got=%s want=%s", got.Kind, tc.kind)
			}
		})
	}
}

func TestParseRPErrorCause_VariableLengthIE(t *testing.T) {
	// cause IE length = 3: cause + 2 bytes diagnostics
	body := []byte{0x04, 0x22, 0x03, 0xA9, 0x12, 0x34, 0x00}
	cause, err := ParseRPErrorCause(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 0xA9 & 0x7F = 0x29
	if cause != 0x29 {
		t.Fatalf("cause mismatch: got=%d want=%d", cause, 0x29)
	}
}

func TestParseRPErrorCause_Invalid(t *testing.T) {
	if _, err := ParseRPErrorCause([]byte{0x04, 0x01, 0x00}); err == nil {
		t.Fatalf("expected error for empty cause IE")
	}
	if _, err := ParseRPErrorCause([]byte{0x02, 0x01, 0x01, 0x29}); err == nil {
		t.Fatalf("expected error for non RP-ERROR")
	}
}
