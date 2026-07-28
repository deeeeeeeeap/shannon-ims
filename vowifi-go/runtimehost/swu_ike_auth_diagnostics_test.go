//go:build linux

package runtimehost

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	swulogger "github.com/1239t/swu-go/pkg/logger"
	externalswu "github.com/1239t/swu-go/pkg/swu"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const rawIKEAuthErrorMarker = "synthetic-raw-error-marker"

type syntheticIKEAuthInitialError struct {
	result     string
	notifyType string
	protocolID uint8
	dataLen    int
}

func (syntheticIKEAuthInitialError) Error() string    { return rawIKEAuthErrorMarker }
func (syntheticIKEAuthInitialError) Stage() string    { return "ike_auth_initial" }
func (e syntheticIKEAuthInitialError) Result() string { return e.result }
func (e syntheticIKEAuthInitialError) NotifyType() string {
	return e.notifyType
}
func (e syntheticIKEAuthInitialError) ProtocolID() uint8 { return e.protocolID }
func (e syntheticIKEAuthInitialError) DataLen() int      { return e.dataLen }

type failingIKEAuthSWuSession struct {
	err   error
	inner chan []byte
}

func (s *failingIKEAuthSWuSession) Connect(context.Context) error { return s.err }
func (*failingIKEAuthSWuSession) Snapshot() externalswu.SessionSnapshot {
	return externalswu.SessionSnapshot{}
}
func (*failingIKEAuthSWuSession) UpdateAddresses(string, string) error { return nil }
func (*failingIKEAuthSWuSession) SendInnerPacket([]byte) error         { return nil }
func (s *failingIKEAuthSWuSession) InnerPackets() <-chan []byte        { return s.inner }
func (*failingIKEAuthSWuSession) Shutdown()                            {}
func (*failingIKEAuthSWuSession) WaitDone()                            {}

func TestStartSWuSessionLogsInitialIKEAuthFailureOnce(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	session := &failingIKEAuthSWuSession{
		err: syntheticIKEAuthInitialError{
			result:     "error_notify",
			notifyType: "authentication_failed",
			protocolID: 1,
			dataLen:    4,
		},
		inner: make(chan []byte),
	}
	req := StartRequest{
		Profile: Profile{MCC: "001", MNC: "01"},
		SIM:     inertSWuSIM{},
		outboundIPDetector: func(net.IP, int) (net.IP, error) {
			return net.ParseIP("198.51.100.20"), nil
		},
		swuSessionFactory: func(*externalswu.Config) swuSession { return session },
	}
	_, err := (&Instance{}).startSWuSession(context.Background(), req, "192.0.2.10", "500")
	if err == nil {
		t.Fatal("startSWuSession() unexpectedly succeeded")
	}

	entries := observed.FilterMessage("SWu IKE_AUTH initial failure").All()
	if len(entries) != 1 {
		t.Fatalf("IKE_AUTH failure log count = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	want := map[string]any{
		"stage":       "ike_auth_initial",
		"result":      "error_notify",
		"notify_type": "authentication_failed",
		"protocol_id": int64(1),
		"data_len":    int64(4),
	}
	if fmt.Sprint(fields) == "" {
		t.Fatal("IKE_AUTH failure log has no fields")
	}
	if len(fields) != len(want) {
		t.Fatalf("IKE_AUTH failure log field count = %d, want %d", len(fields), len(want))
	}
	for key, expected := range want {
		if fields[key] != expected {
			t.Fatalf("IKE_AUTH failure field %q = %v, want %v", key, fields[key], expected)
		}
	}
	for key, value := range fields {
		if _, ok := want[key]; !ok {
			t.Fatalf("IKE_AUTH failure log contains disallowed field %q", key)
		}
		if strings.Contains(fmt.Sprint(value), rawIKEAuthErrorMarker) {
			t.Fatal("IKE_AUTH failure log exposed raw error text")
		}
	}
}

func TestIKEAuthFailureLogUsesFiniteEnums(t *testing.T) {
	for _, result := range []string{"decrypt_failed", "integrity_failed", "missing_eap", "malformed", "canceled"} {
		t.Run(result, func(t *testing.T) {
			core, observed := observer.New(zap.DebugLevel)
			SetLogger(zap.New(core))
			t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

			logSWUIKEAuthInitialFailure(syntheticIKEAuthInitialError{result: result})
			entries := observed.FilterMessage("SWu IKE_AUTH initial failure").All()
			if len(entries) != 1 {
				t.Fatalf("IKE_AUTH failure log count = %d, want 1", len(entries))
			}
			fields := entries[0].ContextMap()
			if len(fields) != 2 || fields["stage"] != "ike_auth_initial" || fields["result"] != result {
				t.Fatalf("IKE_AUTH failure fields = %#v", fields)
			}
		})
	}

	core, observed := observer.New(zap.DebugLevel)
	SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })
	logSWUIKEAuthInitialFailure(syntheticIKEAuthInitialError{
		result:     "error_notify",
		notifyType: rawIKEAuthErrorMarker,
		protocolID: 255,
		dataLen:    -1,
	})
	entries := observed.FilterMessage("SWu IKE_AUTH initial failure").All()
	if len(entries) != 1 {
		t.Fatalf("IKE_AUTH failure log count = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["notify_type"] != "other_error_notify" || fields["protocol_id"] != int64(255) || fields["data_len"] != int64(0) {
		t.Fatalf("sanitized Notify fields = %#v", fields)
	}
	for _, value := range fields {
		if strings.Contains(fmt.Sprint(value), rawIKEAuthErrorMarker) {
			t.Fatal("IKE_AUTH failure log exposed an unrecognized enum or raw error text")
		}
	}
}

func TestNonDiagnosticSWuErrorDoesNotLogIKEAuthFailure(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	SetLogger(zap.New(core))
	t.Cleanup(func() { swulogger.SetLogger(zap.NewNop()) })

	logSWUIKEAuthInitialFailure(fmt.Errorf("ordinary synthetic failure"))
	if entries := observed.FilterMessage("SWu IKE_AUTH initial failure").All(); len(entries) != 0 {
		t.Fatalf("ordinary SWu error produced %d IKE_AUTH failure logs", len(entries))
	}
}
