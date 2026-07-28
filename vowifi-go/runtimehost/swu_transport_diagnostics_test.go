//go:build linux

package runtimehost

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"

	externalipsec "github.com/1239t/swu-go/pkg/ipsec"
	externalswu "github.com/1239t/swu-go/pkg/swu"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type diagnosticFakeTransport struct {
	ikeCh          chan []byte
	espCh          chan []byte
	netEvents      chan externalipsec.NetEvent
	stopOnce       sync.Once
	port           int
	keepaliveCalls int
}

func newDiagnosticFakeTransport() *diagnosticFakeTransport {
	return &diagnosticFakeTransport{
		ikeCh:     make(chan []byte, 1),
		espCh:     make(chan []byte, 1),
		netEvents: make(chan externalipsec.NetEvent, 1),
		port:      500,
	}
}

func (*diagnosticFakeTransport) Start() {}
func (t *diagnosticFakeTransport) Stop() {
	t.stopOnce.Do(func() {
		close(t.ikeCh)
		close(t.espCh)
		close(t.netEvents)
	})
}
func (*diagnosticFakeTransport) SendIKE([]byte) error { return nil }
func (*diagnosticFakeTransport) SendESP([]byte) error { return nil }
func (t *diagnosticFakeTransport) IKEPackets() <-chan []byte {
	return t.ikeCh
}
func (t *diagnosticFakeTransport) ESPPackets() <-chan []byte {
	return t.espCh
}
func (t *diagnosticFakeTransport) NetEventsChan() <-chan externalipsec.NetEvent {
	return t.netEvents
}
func (t *diagnosticFakeTransport) RemotePort() int { return t.port }
func (t *diagnosticFakeTransport) SetRemotePort(port int) {
	t.port = port
}
func (t *diagnosticFakeTransport) SendNATKeepalive() error {
	t.keepaliveCalls++
	return nil
}

func syntheticIKEPacket(spi uint64, messageID uint32, response bool) []byte {
	packet := make([]byte, 28)
	binary.BigEndian.PutUint64(packet[0:8], spi)
	packet[17] = 0x20
	packet[18] = 34
	packet[19] = 0x08
	if response {
		packet[19] |= 0x20
	}
	binary.BigEndian.PutUint32(packet[20:24], messageID)
	binary.BigEndian.PutUint32(packet[24:28], uint32(len(packet)))
	return packet
}

func syntheticInvalidKEPayloadResponse(spi uint64, messageID uint32, group uint16) []byte {
	packet := make([]byte, 38)
	binary.BigEndian.PutUint64(packet[0:8], spi)
	packet[16] = 41 // Notify
	packet[17] = 0x20
	packet[18] = 34 // IKE_SA_INIT
	packet[19] = 0x20
	binary.BigEndian.PutUint32(packet[20:24], messageID)
	binary.BigEndian.PutUint32(packet[24:28], uint32(len(packet)))
	binary.BigEndian.PutUint16(packet[30:32], 10)
	binary.BigEndian.PutUint16(packet[34:36], 17) // INVALID_KE_PAYLOAD
	binary.BigEndian.PutUint16(packet[36:38], group)
	return packet
}

func TestObservedSWuTransportLogsCorrelatedInvalidKEPayloadMetadata(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	inner := newDiagnosticFakeTransport()
	wrapped := newObservedSWUTransport(inner, epdgCandidate{Family: "ipv4", Index: 1, Total: 1}, zap.New(core))
	wrapped.Start()

	const spi = uint64(0xa1b2c3d4e5f60718)
	if err := wrapped.SendIKE(syntheticIKEPacket(spi, 0, false)); err != nil {
		t.Fatalf("SendIKE() error = %v", err)
	}
	response := syntheticInvalidKEPayloadResponse(spi, 0, 19)
	inner.ikeCh <- response
	<-wrapped.IKEPackets()
	wrapped.Stop()

	entries := observed.FilterMessage("SWu transport packet").All()
	if len(entries) != 2 {
		t.Fatalf("packet diagnostic entries = %d, want 2", len(entries))
	}
	fields := entries[1].ContextMap()
	if got := fields["notify_type"]; got != "invalid_ke_payload" {
		t.Fatalf("notify_type = %#v, want invalid_ke_payload", got)
	}
	if got := fields["suggested_dh_group"]; got != uint16(19) {
		t.Fatalf("suggested_dh_group = %#v, want 19", got)
	}
}

func TestParseIKESAInitNotifyMetadataRejectsNonZeroMessageID(t *testing.T) {
	packet := syntheticInvalidKEPayloadResponse(0xa1b2c3d4e5f60718, 1, 19)
	if notifyType, group, ok := parseIKESAInitNotifyMetadata(packet); ok {
		t.Fatalf("parsed non-zero IKE_SA_INIT message ID: notify=%q group=%d", notifyType, group)
	}
}

func TestParseIKESAInitNotifyMetadataRejectsInitiatorFlagOnResponse(t *testing.T) {
	packet := syntheticInvalidKEPayloadResponse(0xa1b2c3d4e5f60718, 0, 19)
	packet[19] |= 0x08
	if notifyType, group, ok := parseIKESAInitNotifyMetadata(packet); ok {
		t.Fatalf("parsed responder packet with initiator flag: notify=%q group=%d", notifyType, group)
	}
}

func TestParseIKESAInitNotifyMetadataRejectsMalformedPackets(t *testing.T) {
	valid := func() []byte {
		return syntheticInvalidKEPayloadResponse(0xa1b2c3d4e5f60718, 0, 19)
	}
	tests := map[string]func([]byte) []byte{
		"declared length mismatch": func(packet []byte) []byte {
			binary.BigEndian.PutUint32(packet[24:28], uint32(len(packet)+1))
			return packet
		},
		"truncated payload chain": func(packet []byte) []byte {
			packet[28] = 41
			return packet
		},
		"notify payload too short": func(packet []byte) []byte {
			binary.BigEndian.PutUint16(packet[30:32], 7)
			return packet
		},
		"notify spi overlaps group": func(packet []byte) []byte {
			packet[33] = 1
			return packet
		},
		"invalid ke group data too short": func(packet []byte) []byte {
			packet = packet[:37]
			binary.BigEndian.PutUint32(packet[24:28], uint32(len(packet)))
			binary.BigEndian.PutUint16(packet[30:32], 9)
			return packet
		},
		"zero suggested group": func(packet []byte) []byte {
			binary.BigEndian.PutUint16(packet[36:38], 0)
			return packet
		},
		"wrong version": func(packet []byte) []byte {
			packet[17] = 0x21
			return packet
		},
		"wrong exchange": func(packet []byte) []byte {
			packet[18] = 35
			return packet
		},
		"not a response": func(packet []byte) []byte {
			packet[19] = 0x08
			return packet
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			packet := mutate(valid())
			if notifyType, group, ok := parseIKESAInitNotifyMetadata(packet); ok {
				t.Fatalf("parsed malformed packet: notify=%q group=%d", notifyType, group)
			}
		})
	}
}

func TestObservedSWuTransportLogsOnlyBoundedMetadataAndCorrelation(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	inner := newDiagnosticFakeTransport()
	wrapped := newObservedSWUTransport(inner, epdgCandidate{Family: "ipv4", Index: 2, Total: 4}, zap.New(core))
	wrapped.Start()

	request := syntheticIKEPacket(0xa1b2c3d4e5f60718, 0, false)
	response := syntheticIKEPacket(0xa1b2c3d4e5f60718, 0, true)
	if err := wrapped.SendIKE(request); err != nil {
		t.Fatalf("SendIKE() error = %v", err)
	}
	inner.ikeCh <- response
	if got := <-wrapped.IKEPackets(); len(got) != len(response) {
		t.Fatalf("IKE response length = %d, want %d", len(got), len(response))
	}
	wrapped.Stop()

	entries := observed.FilterMessage("SWu transport packet").All()
	if len(entries) != 2 {
		t.Fatalf("diagnostic entry count = %d, want 2", len(entries))
	}
	allowed := map[string]bool{
		"address_family":            true,
		"candidate_index":           true,
		"candidate_total":           true,
		"direction":                 true,
		"udp_port":                  true,
		"packet_count":              true,
		"packet_len":                true,
		"first_response_correlated": true,
	}
	for _, entry := range entries {
		for key := range entry.ContextMap() {
			if !allowed[key] {
				t.Fatalf("diagnostic log contains disallowed field %q", key)
			}
		}
	}
	if got, ok := entries[1].ContextMap()["first_response_correlated"].(bool); !ok || !got {
		t.Fatalf("first response correlation = %#v, want true", entries[1].ContextMap()["first_response_correlated"])
	}
}

func TestBuildObservedSWuTransportFactoryWrapsDirectTransport(t *testing.T) {
	inner := newDiagnosticFakeTransport()
	baseCalls := 0
	factory := buildObservedSWuTransportFactory(
		nil,
		epdgCandidate{Family: "ipv6", Index: 1, Total: 2},
		zap.NewNop(),
		func(string, string) (externalswu.Transport, error) {
			baseCalls++
			return inner, nil
		},
	)

	transport, err := factory("[::]:0", "[2001:db8::10]:500")
	if err != nil {
		t.Fatalf("transport factory error = %v", err)
	}
	if baseCalls != 1 {
		t.Fatalf("base transport factory calls = %d, want 1", baseCalls)
	}
	var observedTransport *observedSWUTransport
	switch typed := transport.(type) {
	case *observedSWUTransport:
		observedTransport = typed
	case *observedSWUNATTransport:
		observedTransport = typed.observedSWUTransport
	default:
		t.Fatalf("transport type = %T, want observed SWu transport", transport)
	}
	if got := observedTransport.diagnostics.candidate; got.Family != "ipv6" || got.Index != 1 || got.Total != 2 {
		t.Fatalf("observed candidate = %+v", got)
	}
}

func TestBuildObservedSWuTransportFactoryCanonicalizesIPv6Remote(t *testing.T) {
	inner := newDiagnosticFakeTransport()
	capturedRemote := ""
	factory := buildObservedSWuTransportFactory(
		nil,
		epdgCandidate{IP: net.ParseIP("2001:db8::10"), Family: "ipv6", Index: 1, Total: 1},
		zap.NewNop(),
		func(_ string, remote string) (externalswu.Transport, error) {
			capturedRemote = remote
			return inner, nil
		},
	)

	if _, err := factory(":0", "2001:db8::10:500"); err != nil {
		t.Fatalf("transport factory error = %v", err)
	}
	if capturedRemote != "[2001:db8::10]:500" {
		t.Fatalf("base transport remote = %q, want bracketed IPv6 endpoint", capturedRemote)
	}
}

func TestObservedSWuTransportPreservesNATKeepaliveOnUDP4500(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	inner := newDiagnosticFakeTransport()
	wrapped := newObservedSWUTransport(inner, epdgCandidate{Family: "ipv4", Index: 1, Total: 1}, zap.New(core))
	setter, ok := wrapped.(interface{ SetRemotePort(int) })
	if !ok {
		t.Fatal("observed transport does not preserve SetRemotePort")
	}
	setter.SetRemotePort(4500)
	sender, ok := interface{}(wrapped).(interface{ SendNATKeepalive() error })
	if !ok {
		t.Fatal("observed transport does not preserve SendNATKeepalive")
	}
	if err := sender.SendNATKeepalive(); err != nil {
		t.Fatalf("SendNATKeepalive() error = %v", err)
	}
	if inner.keepaliveCalls != 1 {
		t.Fatalf("inner keepalive calls = %d, want 1", inner.keepaliveCalls)
	}
	entries := observed.FilterMessage("SWu transport packet").All()
	if len(entries) != 1 {
		t.Fatalf("diagnostic entry count = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["udp_port"] != int64(4500) || fields["packet_len"] != int64(1) {
		t.Fatalf("keepalive diagnostic fields = %#v", fields)
	}
}

func TestObservedSWuTransportCountsUDP4500ReceiveAndBoundsPacketLogs(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	inner := newDiagnosticFakeTransport()
	wrapped := newObservedSWUTransport(inner, epdgCandidate{Family: "ipv6", Index: 1, Total: 1}, zap.New(core))
	setter := wrapped.(interface{ SetRemotePort(int) })
	setter.SetRemotePort(4500)
	wrapped.Start()

	packet := syntheticIKEPacket(0xa1b2c3d4e5f60718, 0, true)
	for index := 0; index < maxSWUPacketDiagnosticEvents+5; index++ {
		inner.ikeCh <- packet
		<-wrapped.IKEPackets()
	}
	wrapped.Stop()

	entries := observed.FilterMessage("SWu transport packet").All()
	if len(entries) != maxSWUPacketDiagnosticEvents {
		t.Fatalf("bounded packet diagnostic entries = %d, want %d", len(entries), maxSWUPacketDiagnosticEvents)
	}
	summaries := observed.FilterMessage("SWu transport summary").All()
	if len(summaries) != 1 {
		t.Fatalf("summary entry count = %d, want 1", len(summaries))
	}
	if got := summaries[0].ContextMap()["udp4500_rx_count"]; got != uint64(maxSWUPacketDiagnosticEvents+5) {
		t.Fatalf("udp4500_rx_count = %#v, want %d", got, maxSWUPacketDiagnosticEvents+5)
	}
}
