package swu

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestNetstackESPStatsSnapshotAndSummary(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	s := &Session{Logger: zap.New(core)}
	s.espRxCount.Store(7)
	s.espInboundSACount.Store(2)
	s.espDecapsulateCount.Store(3)
	s.espInnerRxCount.Store(1)
	s.espInnerQueueDropCount.Store(4)

	stats := s.NetstackESPStats()
	want := map[string]uint64{
		"esp_rx_count":                 7,
		"esp_inbound_sa_missing_count": 2,
		"esp_decapsulate_error_count":  3,
		"esp_inner_rx_count":           1,
		"esp_inner_queue_drop_count":   4,
	}
	for key, value := range want {
		if got := stats[key]; got != value {
			t.Fatalf("%s = %d, want %d", key, got, value)
		}
	}

	s.logNetstackESPStats()
	entries := observed.FilterMessage("SWu ESP netstack summary").All()
	if len(entries) != 1 {
		t.Fatalf("summary entries = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	for key, value := range want {
		if got := fields[key]; got != value {
			t.Fatalf("summary %s = %#v, want %d", key, got, value)
		}
	}
}

func TestObserveInnerPacketClassifiesICMPv6PacketTooBig(t *testing.T) {
	s := &Session{}
	packet := make([]byte, 48)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 8)
	packet[6] = 58
	packet[7] = 64
	copy(packet[8:24], net.ParseIP("2001:db8::1").To16())
	copy(packet[24:40], net.ParseIP("2001:db8::2").To16())
	packet[40] = 2
	binary.BigEndian.PutUint32(packet[44:48], 1240)

	s.observeInnerPacket(packet)
	stats := s.NetstackESPStats()
	want := map[string]uint64{
		"inner_ipv6_count":            1,
		"inner_icmpv6_count":          1,
		"icmpv6_packet_too_big_count": 1,
		"icmpv6_reported_mtu":         1240,
	}
	for key, value := range want {
		if got := stats[key]; got != value {
			t.Fatalf("%s = %d, want %d", key, got, value)
		}
	}
}

func TestObserveInnerPacketClassifiesProtocols(t *testing.T) {
	s := &Session{}
	ipv4 := make([]byte, 20)
	ipv4[0] = 0x45
	ipv4[9] = 17
	s.observeInnerPacket(ipv4)

	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	ipv6[6] = 50
	s.observeInnerPacket(ipv6)

	stats := s.NetstackESPStats()
	for key, want := range map[string]uint64{
		"inner_ipv4_count": 1,
		"inner_ipv6_count": 1,
		"inner_udp_count":  1,
		"inner_esp_count":  1,
	} {
		if got := stats[key]; got != want {
			t.Fatalf("%s = %d, want %d", key, got, want)
		}
	}
}

func TestObserveICMPv6ClassifiesInformationalTypes(t *testing.T) {
	tests := []struct {
		icmpType byte
		key      string
	}{
		{128, "icmpv6_echo_request_count"},
		{129, "icmpv6_echo_reply_count"},
		{133, "icmpv6_router_solicit_count"},
		{134, "icmpv6_router_advert_count"},
		{135, "icmpv6_neighbor_solicit_count"},
		{136, "icmpv6_neighbor_advert_count"},
		{137, "icmpv6_redirect_count"},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			s := &Session{}
			s.observeICMPv6([]byte{tt.icmpType})
			if got := s.NetstackESPStats()[tt.key]; got != 1 {
				t.Fatalf("%s = %d, want 1", tt.key, got)
			}
		})
	}
}

func TestNetstackESPStatsNilSafe(t *testing.T) {
	var s *Session
	if got := s.NetstackESPStats(); len(got) != 0 {
		t.Fatalf("nil stats = %#v, want empty", got)
	}
}

func TestNetstackESPQueueDropCounter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Session{
		ctx:         ctx,
		innerClosed: make(chan struct{}),
		innerRx:     make(chan []byte),
		Logger:      zap.NewNop(),
	}
	s.espInnerQueueDropCount.Add(1)
	if got := s.NetstackESPStats()["esp_inner_queue_drop_count"]; got != 1 {
		t.Fatalf("queue drop count = %d, want 1", got)
	}
}
