//go:build linux

package runtimehost

import (
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	externalipsec "github.com/1239t/swu-go/pkg/ipsec"
	externalswu "github.com/1239t/swu-go/pkg/swu"
	"go.uber.org/zap"
)

const maxSWUPacketDiagnosticEvents = 32

const (
	ikeHeaderLen             = 28
	ikePayloadNotify         = 41
	ikeExchangeSAInit        = 34
	ikeFlagInitiator         = 0x08
	ikeFlagResponse          = 0x20
	ikeNotifyInvalidKE       = 17
	ikeNotifyNoProposal      = 14
	ikeNotifyCookie          = 16390
	ikeNotifyHeaderLen       = 8
	invalidKEGroupDataLength = 2
)

type ikeResponseObservation struct {
	firstResponse    bool
	correlated       bool
	notifyType       string
	suggestedDHGroup uint16
}

type swuPacketCounters struct {
	tx500  atomic.Uint64
	rx500  atomic.Uint64
	tx4500 atomic.Uint64
	rx4500 atomic.Uint64
}

func (c *swuPacketCounters) increment(direction string, port int) uint64 {
	switch {
	case direction == "tx" && port == 500:
		return c.tx500.Add(1)
	case direction == "rx" && port == 500:
		return c.rx500.Add(1)
	case direction == "tx" && port == 4500:
		return c.tx4500.Add(1)
	case direction == "rx" && port == 4500:
		return c.rx4500.Add(1)
	default:
		return 0
	}
}

type swuTransportDiagnostics struct {
	candidate epdgCandidate
	logger    *zap.Logger
	counters  swuPacketCounters
	events    atomic.Uint32

	headerMu                sync.Mutex
	firstRequestSet         bool
	firstRequestSPI         uint64
	firstRequestMessageID   uint32
	firstResponseSeen       bool
	firstResponseCorrelated bool
}

func newSWUTransportDiagnostics(candidate epdgCandidate, logger *zap.Logger) *swuTransportDiagnostics {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &swuTransportDiagnostics{candidate: candidate, logger: logger}
}

func (d *swuTransportDiagnostics) observe(direction string, port int, packet []byte, ike bool) {
	count := d.counters.increment(direction, port)
	if count == 0 {
		return
	}
	ikeObservation := ikeResponseObservation{}
	if ike {
		ikeObservation = d.observeIKEHeader(direction, packet)
	}
	if d.events.Add(1) > maxSWUPacketDiagnosticEvents {
		return
	}
	fields := []zap.Field{
		zap.String("address_family", d.candidate.Family),
		zap.Int("candidate_index", d.candidate.Index),
		zap.Int("candidate_total", d.candidate.Total),
		zap.String("direction", direction),
		zap.Int("udp_port", port),
		zap.Uint64("packet_count", count),
		zap.Int("packet_len", len(packet)),
	}
	if ikeObservation.firstResponse {
		fields = append(fields, zap.Bool("first_response_correlated", ikeObservation.correlated))
		if ikeObservation.notifyType != "" {
			fields = append(fields, zap.String("notify_type", ikeObservation.notifyType))
		}
		if ikeObservation.suggestedDHGroup != 0 {
			fields = append(fields, zap.Uint16("suggested_dh_group", ikeObservation.suggestedDHGroup))
		}
	}
	d.logger.Info("SWu transport packet", fields...)
}

func (d *swuTransportDiagnostics) observeIKEHeader(direction string, packet []byte) ikeResponseObservation {
	if len(packet) < ikeHeaderLen || packet[17] != 0x20 {
		return ikeResponseObservation{}
	}
	spi := binary.BigEndian.Uint64(packet[0:8])
	messageID := binary.BigEndian.Uint32(packet[20:24])
	isResponse := packet[19]&0x20 != 0

	d.headerMu.Lock()
	defer d.headerMu.Unlock()
	if direction == "tx" && !isResponse && !d.firstRequestSet {
		d.firstRequestSet = true
		d.firstRequestSPI = spi
		d.firstRequestMessageID = messageID
		return ikeResponseObservation{}
	}
	if direction != "rx" || !isResponse || d.firstResponseSeen {
		return ikeResponseObservation{}
	}
	d.firstResponseSeen = true
	d.firstResponseCorrelated = d.firstRequestSet && d.firstRequestSPI == spi && d.firstRequestMessageID == messageID
	observation := ikeResponseObservation{firstResponse: true, correlated: d.firstResponseCorrelated}
	if !observation.correlated {
		return observation
	}
	observation.notifyType, observation.suggestedDHGroup, _ = parseIKESAInitNotifyMetadata(packet)
	return observation
}

func parseIKESAInitNotifyMetadata(packet []byte) (string, uint16, bool) {
	if len(packet) < ikeHeaderLen || packet[17] != 0x20 || packet[18] != ikeExchangeSAInit || packet[19]&ikeFlagResponse == 0 || packet[19]&ikeFlagInitiator != 0 {
		return "", 0, false
	}
	if binary.BigEndian.Uint32(packet[20:24]) != 0 {
		return "", 0, false
	}
	totalLength := int(binary.BigEndian.Uint32(packet[24:28]))
	if totalLength != len(packet) {
		return "", 0, false
	}

	nextPayload := packet[16]
	offset := ikeHeaderLen
	notifyType := ""
	var suggestedGroup uint16
	for nextPayload != 0 {
		if offset+4 > totalLength {
			return "", 0, false
		}
		followingPayload := packet[offset]
		payloadLength := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		if payloadLength < 4 || offset+payloadLength > totalLength {
			return "", 0, false
		}
		if nextPayload == ikePayloadNotify {
			if payloadLength < ikeNotifyHeaderLen {
				return "", 0, false
			}
			protocolID := packet[offset+4]
			spiSize := int(packet[offset+5])
			if ikeNotifyHeaderLen+spiSize > payloadLength {
				return "", 0, false
			}
			typeCode := binary.BigEndian.Uint16(packet[offset+6 : offset+8])
			notifyDataLength := payloadLength - ikeNotifyHeaderLen - spiSize
			switch typeCode {
			case ikeNotifyInvalidKE:
				if notifyType != "" || protocolID != 0 || spiSize != 0 || notifyDataLength != invalidKEGroupDataLength {
					return "", 0, false
				}
				notifyType = "invalid_ke_payload"
				suggestedGroup = binary.BigEndian.Uint16(packet[offset+8 : offset+10])
				if suggestedGroup == 0 {
					return "", 0, false
				}
			case ikeNotifyNoProposal:
				if notifyType == "" {
					notifyType = "no_proposal_chosen"
				}
			case ikeNotifyCookie:
				if notifyType == "" {
					notifyType = "cookie"
				}
			}
		}
		offset += payloadLength
		nextPayload = followingPayload
	}
	if offset != totalLength || notifyType == "" {
		return "", 0, false
	}
	return notifyType, suggestedGroup, true
}

func (d *swuTransportDiagnostics) logSummary() {
	d.headerMu.Lock()
	firstResponseSeen := d.firstResponseSeen
	firstResponseCorrelated := d.firstResponseCorrelated
	d.headerMu.Unlock()
	d.logger.Info("SWu transport summary",
		zap.String("address_family", d.candidate.Family),
		zap.Int("candidate_index", d.candidate.Index),
		zap.Int("candidate_total", d.candidate.Total),
		zap.Uint64("udp500_tx_count", d.counters.tx500.Load()),
		zap.Uint64("udp500_rx_count", d.counters.rx500.Load()),
		zap.Uint64("udp4500_tx_count", d.counters.tx4500.Load()),
		zap.Uint64("udp4500_rx_count", d.counters.rx4500.Load()),
		zap.Bool("first_response_seen", firstResponseSeen),
		zap.Bool("first_response_correlated", firstResponseCorrelated))
}

type observedSWUTransport struct {
	inner       externalswu.Transport
	diagnostics *swuTransportDiagnostics
	ikeCh       chan []byte
	espCh       chan []byte
	stopCh      chan struct{}
	startOnce   sync.Once
	stopOnce    sync.Once
	wg          sync.WaitGroup
	remotePort  atomic.Int64
}

func newObservedSWUTransport(inner externalswu.Transport, candidate epdgCandidate, logger *zap.Logger) externalswu.Transport {
	port := 500
	if provider, ok := inner.(interface{ RemotePort() int }); ok {
		if current := provider.RemotePort(); current > 0 {
			port = current
		}
	}
	t := &observedSWUTransport{
		inner:       inner,
		diagnostics: newSWUTransportDiagnostics(candidate, logger),
		ikeCh:       make(chan []byte, 100),
		espCh:       make(chan []byte, 1000),
		stopCh:      make(chan struct{}),
	}
	t.remotePort.Store(int64(port))
	if sender, ok := inner.(interface{ SendNATKeepalive() error }); ok {
		return &observedSWUNATTransport{observedSWUTransport: t, sender: sender}
	}
	return t
}

type observedSWUNATTransport struct {
	*observedSWUTransport
	sender interface{ SendNATKeepalive() error }
}

func (t *observedSWUNATTransport) SendNATKeepalive() error {
	if err := t.sender.SendNATKeepalive(); err != nil {
		return err
	}
	t.diagnostics.observe("tx", int(t.remotePort.Load()), []byte{0xff}, false)
	return nil
}

func (t *observedSWUTransport) Start() {
	t.startOnce.Do(func() {
		t.inner.Start()
		t.wg.Add(2)
		go t.relay(t.inner.IKEPackets(), t.ikeCh, true)
		go t.relay(t.inner.ESPPackets(), t.espCh, false)
	})
}

func (t *observedSWUTransport) relay(source <-chan []byte, destination chan<- []byte, ike bool) {
	defer t.wg.Done()
	for {
		select {
		case <-t.stopCh:
			return
		case packet, ok := <-source:
			if !ok {
				return
			}
			t.diagnostics.observe("rx", int(t.remotePort.Load()), packet, ike)
			select {
			case destination <- packet:
			case <-t.stopCh:
				return
			}
		}
	}
}

func (t *observedSWUTransport) Stop() {
	t.stopOnce.Do(func() {
		close(t.stopCh)
		t.inner.Stop()
		t.wg.Wait()
		close(t.ikeCh)
		close(t.espCh)
		t.diagnostics.logSummary()
	})
}

func (t *observedSWUTransport) SendIKE(packet []byte) error {
	if err := t.inner.SendIKE(packet); err != nil {
		return err
	}
	t.diagnostics.observe("tx", int(t.remotePort.Load()), packet, true)
	return nil
}

func (t *observedSWUTransport) SendESP(packet []byte) error {
	if err := t.inner.SendESP(packet); err != nil {
		return err
	}
	t.diagnostics.observe("tx", int(t.remotePort.Load()), packet, false)
	return nil
}

func (t *observedSWUTransport) IKEPackets() <-chan []byte { return t.ikeCh }
func (t *observedSWUTransport) ESPPackets() <-chan []byte { return t.espCh }
func (t *observedSWUTransport) NetEventsChan() <-chan externalipsec.NetEvent {
	return t.inner.NetEventsChan()
}

func (t *observedSWUTransport) SetRemotePort(port int) {
	if port <= 0 {
		return
	}
	if setter, ok := t.inner.(interface{ SetRemotePort(int) }); ok {
		setter.SetRemotePort(port)
	}
	t.remotePort.Store(int64(port))
}

func (t *observedSWUTransport) RemotePort() int { return int(t.remotePort.Load()) }

func (t *observedSWUTransport) LocalPort() uint16 {
	if provider, ok := t.inner.(interface{ LocalPort() uint16 }); ok {
		return provider.LocalPort()
	}
	return 0
}

func (t *observedSWUTransport) LocalIP() net.IP {
	if provider, ok := t.inner.(interface{ LocalIP() net.IP }); ok {
		return provider.LocalIP()
	}
	return nil
}

func (t *observedSWUTransport) RemoteIP() net.IP {
	if provider, ok := t.inner.(interface{ RemoteIP() net.IP }); ok {
		return provider.RemoteIP()
	}
	return nil
}

func (t *observedSWUTransport) LocalAddrString() string {
	return "local-" + t.diagnostics.candidate.Family
}
func (t *observedSWUTransport) RemoteAddrString() string {
	return "candidate-" + strconv.Itoa(t.diagnostics.candidate.Index) + "-" + t.diagnostics.candidate.Family
}
