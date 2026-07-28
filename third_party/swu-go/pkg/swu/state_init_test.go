package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	swucrypto "github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type initTestTransport struct {
	ikeCh          chan []byte
	espCh          chan []byte
	netCh          chan ipsec.NetEvent
	onSendIKE      func([]byte)
	stopOnce       sync.Once
	localIP        net.IP
	remoteIP       net.IP
	localPort      uint16
	remotePort     int
	setRemoteCalls int
	keepaliveCalls int
}

func newInitTestTransport(onSendIKE func([]byte)) *initTestTransport {
	return &initTestTransport{
		ikeCh:     make(chan []byte, 4),
		espCh:     make(chan []byte),
		netCh:     make(chan ipsec.NetEvent),
		onSendIKE: onSendIKE,
	}
}

func (*initTestTransport) Start() {}

func (t *initTestTransport) Stop() {
	t.stopOnce.Do(func() {
		close(t.ikeCh)
		close(t.espCh)
		close(t.netCh)
	})
}

func (t *initTestTransport) SendIKE(packet []byte) error {
	if t.onSendIKE != nil {
		t.onSendIKE(append([]byte(nil), packet...))
	}
	return nil
}

func (*initTestTransport) SendESP([]byte) error                   { return nil }
func (t *initTestTransport) IKEPackets() <-chan []byte            { return t.ikeCh }
func (t *initTestTransport) ESPPackets() <-chan []byte            { return t.espCh }
func (t *initTestTransport) NetEventsChan() <-chan ipsec.NetEvent { return t.netCh }
func (t *initTestTransport) LocalIP() net.IP                      { return t.localIP }
func (t *initTestTransport) RemoteIP() net.IP                     { return t.remoteIP }
func (t *initTestTransport) LocalPort() uint16                    { return t.localPort }
func (t *initTestTransport) RemotePort() int                      { return t.remotePort }
func (t *initTestTransport) SetRemotePort(port int) {
	t.remotePort = port
	t.setRemoteCalls++
}
func (t *initTestTransport) SendNATKeepalive() error {
	t.keepaliveCalls++
	return nil
}

type parsedIKESAInitRequest struct {
	spiI           uint64
	messageID      uint32
	keGroup        ikev2.AlgorithmType
	keData         []byte
	nonce          []byte
	proposalGroups []ikev2.AlgorithmType
}

func parseIKESAInitRequest(t *testing.T, raw []byte) parsedIKESAInitRequest {
	t.Helper()
	packet, err := ikev2.DecodePacket(raw)
	if err != nil {
		t.Fatalf("DecodePacket() error = %v", err)
	}
	if packet.Header.ExchangeType != ikev2.IKE_SA_INIT {
		t.Fatalf("exchange type = %d, want IKE_SA_INIT", packet.Header.ExchangeType)
	}
	result := parsedIKESAInitRequest{spiI: packet.Header.SPIi, messageID: packet.Header.MessageID}
	for _, payload := range packet.Payloads {
		switch typed := payload.(type) {
		case *ikev2.EncryptedPayloadSA:
			for _, proposal := range typed.Proposals {
				for _, transform := range proposal.Transforms {
					if transform.Type == ikev2.TransformTypeDH {
						result.proposalGroups = append(result.proposalGroups, transform.ID)
					}
				}
			}
		case *ikev2.EncryptedPayloadKE:
			result.keGroup = typed.DHGroup
			result.keData = append([]byte(nil), typed.KEData...)
		case *ikev2.EncryptedPayloadNonce:
			result.nonce = append([]byte(nil), typed.NonceData...)
		}
	}
	return result
}

func syntheticInvalidKEPayloadResponse(spiI, spiR uint64, group uint16) []byte {
	packet := make([]byte, 38)
	binary.BigEndian.PutUint64(packet[0:8], spiI)
	binary.BigEndian.PutUint64(packet[8:16], spiR)
	packet[16] = byte(ikev2.N)
	packet[17] = 0x20
	packet[18] = byte(ikev2.IKE_SA_INIT)
	packet[19] = ikev2.FlagResponse
	binary.BigEndian.PutUint32(packet[20:24], 0)
	binary.BigEndian.PutUint32(packet[24:28], uint32(len(packet)))
	binary.BigEndian.PutUint16(packet[30:32], 10)
	binary.BigEndian.PutUint16(packet[34:36], ikev2.INVALID_KE_PAYLOAD)
	binary.BigEndian.PutUint16(packet[36:38], group)
	return packet
}

func syntheticCookieAndInvalidKEResponse(t *testing.T, spiI, spiR uint64, cookieFirst bool) []byte {
	t.Helper()
	cookie := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.COOKIE,
		NotifyData: []byte{1, 2, 3, 4},
	}
	invalidKE := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.INVALID_KE_PAYLOAD,
		NotifyData: []byte{0, 15},
	}
	payloads := []ikev2.Payload{invalidKE, cookie}
	if cookieFirst {
		payloads[0], payloads[1] = payloads[1], payloads[0]
	}
	packet := ikev2.NewIKEPacket()
	packet.Header.SPIi = spiI
	packet.Header.SPIr = spiR
	packet.Header.Version = 0x20
	packet.Header.ExchangeType = ikev2.IKE_SA_INIT
	packet.Header.Flags = ikev2.FlagResponse
	packet.Header.MessageID = 0
	packet.Payloads = payloads
	raw, err := packet.Encode()
	if err != nil {
		t.Fatalf("encode Cookie + INVALID_KE response: %v", err)
	}
	return raw
}

func syntheticSuccessfulIKESAInitResponse(t *testing.T, request []byte, spiR uint64) []byte {
	t.Helper()
	return syntheticSuccessfulIKESAInitResponseWithProposal(t, request, spiR, 0)
}

func syntheticSuccessfulIKESAInitResponseWithProposal(t *testing.T, request []byte, spiR uint64, proposalIndex int) []byte {
	t.Helper()
	decoded, err := ikev2.DecodePacket(request)
	if err != nil {
		t.Fatalf("decode IKE_SA_INIT request: %v", err)
	}
	var requestSA *ikev2.EncryptedPayloadSA
	for _, payload := range decoded.Payloads {
		if sa, ok := payload.(*ikev2.EncryptedPayloadSA); ok {
			requestSA = sa
			break
		}
	}
	if requestSA == nil || proposalIndex < 0 || proposalIndex >= len(requestSA.Proposals) {
		t.Fatal("request contains no IKE SA proposal")
	}
	selectedProposal := requestSA.Proposals[proposalIndex]
	var requestGroup ikev2.AlgorithmType
	for _, transform := range selectedProposal.Transforms {
		if transform.Type == ikev2.TransformTypeDH {
			requestGroup = transform.ID
		}
	}
	if requestGroup == 0 {
		t.Fatal("request proposal contains no DH transform")
	}
	responderDH, err := swucrypto.NewDiffieHellman(uint16(requestGroup))
	if err != nil {
		t.Fatalf("create responder DH: %v", err)
	}
	if err := responderDH.GenerateKey(); err != nil {
		t.Fatalf("generate responder DH: %v", err)
	}
	response := ikev2.NewIKEPacket()
	response.Header.SPIi = decoded.Header.SPIi
	response.Header.SPIr = spiR
	response.Header.Version = 0x20
	response.Header.ExchangeType = ikev2.IKE_SA_INIT
	response.Header.Flags = ikev2.FlagResponse
	response.Header.MessageID = 0
	response.Payloads = []ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{selectedProposal}},
		&ikev2.EncryptedPayloadKE{DHGroup: requestGroup, KEData: responderDH.PublicKeyBytes()},
		&ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{0x42}, 32)},
	}
	raw, err := response.Encode()
	if err != nil {
		t.Fatalf("encode successful IKE_SA_INIT response: %v", err)
	}
	return raw
}

type suggestedDHGroupError interface {
	error
	SuggestedDHGroup() uint16
}

func TestBuildIKESAInitPacketKeepsProposalDHAlignedWithKE(t *testing.T) {
	session := &Session{
		cfg: &Config{
			LocalAddr: "192.0.2.10",
			EpDGAddr:  "192.0.2.20",
			LocalPort: 45000,
			EpDGPort:  500,
		},
		SPIi:   0x0102030405060708,
		Logger: zap.NewNop(),
	}

	raw, err := session.buildIKESAInitPacket()
	if err != nil {
		t.Fatalf("buildIKESAInitPacket() error = %v", err)
	}
	packet, err := ikev2.DecodePacket(raw)
	if err != nil {
		t.Fatalf("DecodePacket() error = %v", err)
	}

	var sa *ikev2.EncryptedPayloadSA
	var ke *ikev2.EncryptedPayloadKE
	for _, payload := range packet.Payloads {
		switch typed := payload.(type) {
		case *ikev2.EncryptedPayloadSA:
			sa = typed
		case *ikev2.EncryptedPayloadKE:
			ke = typed
		}
	}
	if sa == nil || ke == nil {
		t.Fatalf("IKE_SA_INIT payloads missing: SA=%t KE=%t", sa != nil, ke != nil)
	}
	if session.DH == nil || uint16(ke.DHGroup) != session.DH.Group {
		t.Fatalf("KE group = %d, generated DH group = %v", ke.DHGroup, session.DH)
	}
	if len(sa.Proposals) == 0 {
		t.Fatal("IKE_SA_INIT contains no SA proposals")
	}
	for index, proposal := range sa.Proposals {
		var groups []ikev2.AlgorithmType
		for _, transform := range proposal.Transforms {
			if transform.Type == ikev2.TransformTypeDH {
				groups = append(groups, transform.ID)
			}
		}
		if len(groups) != 1 || groups[0] != ke.DHGroup {
			t.Fatalf("proposal %d DH groups = %v, KE group = %d", index+1, groups, ke.DHGroup)
		}
	}
}

func TestHandleIKESAInitResponseParsesStrictInvalidKEPayload(t *testing.T) {
	const (
		spiI  = uint64(0x0102030405060708)
		spiR  = uint64(0x1112131415161718)
		group = uint16(19)
	)
	session := &Session{SPIi: spiI, Logger: zap.NewNop()}

	err := session.handleIKESAInitResp(syntheticInvalidKEPayloadResponse(spiI, spiR, group))
	var invalidKE suggestedDHGroupError
	if !errors.As(err, &invalidKE) {
		t.Fatalf("handleIKESAInitResp() error = %v, want typed INVALID_KE_PAYLOAD", err)
	}
	if got := invalidKE.SuggestedDHGroup(); got != group {
		t.Fatalf("suggested DH group = %d, want %d", got, group)
	}
}

func TestHandleIKESAInitResponseRejectsMalformedOrUncorrelatedInvalidKEPayload(t *testing.T) {
	const (
		spiI = uint64(0x0102030405060708)
		spiR = uint64(0x1112131415161718)
	)
	valid := func() []byte {
		return syntheticInvalidKEPayloadResponse(spiI, spiR, 19)
	}
	tests := map[string]func([]byte) []byte{
		"wrong initiator SPI": func(packet []byte) []byte {
			binary.BigEndian.PutUint64(packet[0:8], spiI+1)
			return packet
		},
		"non-zero message ID": func(packet []byte) []byte {
			binary.BigEndian.PutUint32(packet[20:24], 1)
			return packet
		},
		"wrong version": func(packet []byte) []byte {
			packet[17] = 0x21
			return packet
		},
		"wrong exchange": func(packet []byte) []byte {
			packet[18] = byte(ikev2.IKE_AUTH)
			return packet
		},
		"not a response": func(packet []byte) []byte {
			packet[19] = ikev2.FlagInitiator
			return packet
		},
		"response has initiator flag": func(packet []byte) []byte {
			packet[19] = ikev2.FlagResponse | ikev2.FlagInitiator
			return packet
		},
		"declared length mismatch": func(packet []byte) []byte {
			binary.BigEndian.PutUint32(packet[24:28], uint32(len(packet)+1))
			return packet
		},
		"truncated payload chain": func(packet []byte) []byte {
			packet[28] = byte(ikev2.N)
			return packet
		},
		"notify SPI present": func(packet []byte) []byte {
			packet[33] = 1
			return packet
		},
		"group data too short": func(packet []byte) []byte {
			packet = packet[:37]
			binary.BigEndian.PutUint32(packet[24:28], uint32(len(packet)))
			binary.BigEndian.PutUint16(packet[30:32], 9)
			return packet
		},
		"group data too long": func(packet []byte) []byte {
			packet = append(packet, 0)
			binary.BigEndian.PutUint32(packet[24:28], uint32(len(packet)))
			binary.BigEndian.PutUint16(packet[30:32], 11)
			return packet
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			session := &Session{SPIi: spiI, Logger: zap.NewNop()}
			err := session.handleIKESAInitResp(mutate(valid()))
			if err == nil {
				t.Fatal("handleIKESAInitResp() accepted malformed response")
			}
			var invalidKE suggestedDHGroupError
			if errors.As(err, &invalidKE) {
				t.Fatalf("malformed response classified as INVALID_KE_PAYLOAD: group=%d", invalidKE.SuggestedDHGroup())
			}
			if session.SPIr != 0 {
				t.Fatalf("malformed response installed responder SPI")
			}
		})
	}
}

func TestConnectRetriesCorrelatedGroup15InvalidKEInSameSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu        sync.Mutex
		requests  [][]byte
		transport *initTestTransport
	)
	transport = newInitTestTransport(func(request []byte) {
		mu.Lock()
		requests = append(requests, request)
		attempt := len(requests)
		mu.Unlock()

		header, err := ikev2.DecodeHeader(request)
		if err != nil {
			cancel()
			return
		}
		switch attempt {
		case 1:
			transportResponse := syntheticInvalidKEPayloadResponse(header.SPIi, 0x1112131415161718, 15)
			transport.ikeCh <- transportResponse
		case 2:
			cancel()
		}
	})
	factoryCalls := 0
	logCore, observedLogs := observer.New(zap.InfoLevel)
	session := NewSession(&Config{
		LocalAddr: "192.0.2.10",
		EpDGAddr:  "192.0.2.20",
		LocalPort: 45000,
		EpDGPort:  500,
		TransportFactory: func(string, string) (Transport, error) {
			factoryCalls++
			return transport, nil
		},
	}, zap.New(logCore))

	result := make(chan error, 1)
	go func() { result <- session.Connect(ctx) }()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect() error = %v, want context.Canceled after second request", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect() did not finish after retry cancellation")
	}

	mu.Lock()
	gotRequests := append([][]byte(nil), requests...)
	mu.Unlock()
	if len(gotRequests) != 2 {
		t.Fatalf("IKE_SA_INIT request count = %d, want 2", len(gotRequests))
	}
	if factoryCalls != 1 {
		t.Fatalf("transport factory calls = %d, want one session transport", factoryCalls)
	}
	first := parseIKESAInitRequest(t, gotRequests[0])
	second := parseIKESAInitRequest(t, gotRequests[1])
	if first.spiI != second.spiI || first.messageID != 0 || second.messageID != 0 {
		t.Fatalf("retry correlation changed: SPI same=%t message IDs=%d/%d", first.spiI == second.spiI, first.messageID, second.messageID)
	}
	expectedGroups := []ikev2.AlgorithmType{ikev2.MODP_2048_bit, ikev2.MODP_3072_bit}
	for attempt, request := range []parsedIKESAInitRequest{first, second} {
		if request.keGroup != expectedGroups[attempt] {
			t.Fatalf("attempt %d KE group = %d, want %d", attempt+1, request.keGroup, expectedGroups[attempt])
		}
		for _, group := range request.proposalGroups {
			if group != request.keGroup {
				t.Fatalf("attempt %d proposal DH = %d, KE group = %d", attempt+1, group, request.keGroup)
			}
		}
	}
	if bytes.Equal(first.keData, second.keData) {
		t.Fatal("retry reused IKE_SA_INIT KE material")
	}
	if bytes.Equal(first.nonce, second.nonce) {
		t.Fatal("retry reused IKE_SA_INIT nonce")
	}
	entries := observedLogs.FilterMessage("IKE_SA_INIT negotiation feedback").All()
	if len(entries) != 1 {
		t.Fatalf("negotiation feedback log count = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["notify_type"] != "invalid_ke_payload" || fields["suggested_dh_group"] != int64(15) {
		t.Fatalf("negotiation feedback metadata = %#v", fields)
	}
	allowed := map[string]bool{"notify_type": true, "suggested_dh_group": true}
	for key := range fields {
		if !allowed[key] {
			t.Fatalf("negotiation feedback log contains disallowed field %q", key)
		}
	}
}

func TestHandleIKESAInitResponsePreservesCookieWithInvalidKEPayload(t *testing.T) {
	const (
		spiI = uint64(0x0102030405060708)
		spiR = uint64(0x1112131415161718)
	)
	for _, cookieFirst := range []bool{false, true} {
		name := "invalid-ke-first"
		if cookieFirst {
			name = "cookie-first"
		}
		t.Run(name, func(t *testing.T) {
			session := &Session{SPIi: spiI, Logger: zap.NewNop()}
			err := session.handleIKESAInitResp(syntheticCookieAndInvalidKEResponse(t, spiI, spiR, cookieFirst))
			var invalidKE suggestedDHGroupError
			if !errors.As(err, &invalidKE) || invalidKE.SuggestedDHGroup() != 15 {
				t.Fatalf("handleIKESAInitResp() error = %v, want INVALID_KE_PAYLOAD group 15", err)
			}
			if !session.sendCookie || !bytes.Equal(session.cookie, []byte{1, 2, 3, 4}) {
				t.Fatal("response Cookie was not preserved for the INVALID_KE retry")
			}
		})
	}
}

func TestHandleIKESAInitResponseLogsSafeNegotiatedAlgorithms(t *testing.T) {
	logCore, observedLogs := observer.New(zap.InfoLevel)
	session := &Session{
		cfg: &Config{
			LocalAddr: "192.0.2.10",
			EpDGAddr:  "192.0.2.20",
			LocalPort: 45000,
			EpDGPort:  500,
		},
		SPIi:   0x0102030405060708,
		Logger: zap.New(logCore),
	}
	if err := session.prepareIKESAInitRetry(uint16(ikev2.MODP_3072_bit)); err != nil {
		t.Fatal("prepare group 15 IKE_SA_INIT")
	}
	request, err := session.buildIKESAInitPacket()
	if err != nil {
		t.Fatal("build group 15 IKE_SA_INIT request")
	}
	response := syntheticSuccessfulIKESAInitResponse(t, request, 0x1112131415161718)
	if err := session.handleIKESAInitResp(response); err != nil {
		t.Fatal("handle group 15 IKE_SA_INIT response")
	}

	entries := observedLogs.FilterMessage("IKE_SA_INIT algorithms selected").All()
	if len(entries) != 1 {
		t.Fatalf("negotiated algorithm log count = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	want := map[string]any{
		"encr":          "AES_GCM_16",
		"encr_key_bits": int64(256),
		"integ":         "NONE",
		"prf":           "HMAC_SHA2_384",
		"dh":            "MODP_3072",
	}
	if len(fields) != len(want) {
		t.Fatalf("negotiated algorithm field count = %d, want %d", len(fields), len(want))
	}
	for key, value := range want {
		if fields[key] != value {
			t.Fatalf("negotiated algorithm field %q = %#v, want %#v", key, fields[key], value)
		}
	}
}

func TestConnectDirectGroup14SuccessUsesOneIKESAInitStateMachine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu             sync.Mutex
		transport      *initTestTransport
		saInitRequests int
		authRequests   int
	)
	transport = newInitTestTransport(func(request []byte) {
		header, err := ikev2.DecodeHeader(request)
		if err != nil {
			cancel()
			return
		}
		mu.Lock()
		switch header.ExchangeType {
		case ikev2.IKE_SA_INIT:
			saInitRequests++
		case ikev2.IKE_AUTH:
			authRequests++
		}
		mu.Unlock()
		switch header.ExchangeType {
		case ikev2.IKE_SA_INIT:
			transport.ikeCh <- syntheticSuccessfulIKESAInitResponse(t, request, 0x1112131415161718)
		case ikev2.IKE_AUTH:
			cancel()
		}
	})
	factoryCalls := 0
	session := NewSession(&Config{
		LocalAddr:    "192.0.2.10",
		EpDGAddr:     "192.0.2.20",
		LocalPort:    45000,
		EpDGPort:     500,
		APN:          "ims.test.invalid",
		FastReauthID: "synthetic-test-id",
		TransportFactory: func(string, string) (Transport, error) {
			factoryCalls++
			return transport, nil
		},
	}, zap.NewNop())

	result := make(chan error, 1)
	go func() { result <- session.Connect(ctx) }()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect() error = %v, want context.Canceled after IKE_AUTH", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect() did not reach IKE_AUTH")
	}

	mu.Lock()
	gotSAInit, gotAuth := saInitRequests, authRequests
	mu.Unlock()
	if gotSAInit != 1 || gotAuth != 1 {
		t.Fatalf("request counts: IKE_SA_INIT=%d IKE_AUTH=%d, want 1/1", gotSAInit, gotAuth)
	}
	if factoryCalls != 1 {
		t.Fatalf("transport factory calls = %d, want 1", factoryCalls)
	}
}

func TestConnectDoesNotRetryUnsupportedOrWeakInvalidKEGroups(t *testing.T) {
	for _, group := range []uint16{2, 16, 19} {
		t.Run("group-"+strconv.Itoa(int(group)), func(t *testing.T) {
			if _, err := swucrypto.NewDiffieHellman(group); err == nil {
				t.Fatalf("test requires group %d to be unsupported by the crypto implementation", group)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var (
				mu        sync.Mutex
				requests  int
				transport *initTestTransport
			)
			transport = newInitTestTransport(func(request []byte) {
				header, err := ikev2.DecodeHeader(request)
				if err != nil {
					cancel()
					return
				}
				mu.Lock()
				requests++
				mu.Unlock()
				transport.ikeCh <- syntheticInvalidKEPayloadResponse(header.SPIi, 0x1112131415161718, group)
			})
			session := NewSession(&Config{
				LocalAddr: "192.0.2.10",
				EpDGAddr:  "192.0.2.20",
				LocalPort: 45000,
				EpDGPort:  500,
				TransportFactory: func(string, string) (Transport, error) {
					return transport, nil
				},
			}, zap.NewNop())

			err := session.Connect(ctx)
			cancel()
			if err == nil {
				t.Fatalf("Connect() accepted unsupported DH group %d", group)
			}
			mu.Lock()
			gotRequests := requests
			mu.Unlock()
			if gotRequests != 1 {
				t.Fatalf("IKE_SA_INIT request count = %d, want 1", gotRequests)
			}
		})
	}
}

func TestConnectDoesNotLoopOnRepeatedOrLateInvalidKENotify(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var (
		mu        sync.Mutex
		requests  int
		transport *initTestTransport
	)
	transport = newInitTestTransport(func(request []byte) {
		header, err := ikev2.DecodeHeader(request)
		if err != nil {
			cancel()
			return
		}
		mu.Lock()
		requests++
		mu.Unlock()
		transport.ikeCh <- syntheticInvalidKEPayloadResponse(header.SPIi, 0x1112131415161718, 15)
	})
	session := NewSession(&Config{
		LocalAddr: "192.0.2.10",
		EpDGAddr:  "192.0.2.20",
		LocalPort: 45000,
		EpDGPort:  500,
		TransportFactory: func(string, string) (Transport, error) {
			return transport, nil
		},
	}, zap.NewNop())

	err := session.Connect(ctx)
	cancel()
	if err == nil {
		t.Fatal("Connect() accepted repeated INVALID_KE_PAYLOAD")
	}
	mu.Lock()
	gotRequests := requests
	mu.Unlock()
	if gotRequests != 2 {
		t.Fatalf("IKE_SA_INIT request count = %d, want exactly 2", gotRequests)
	}
}

func TestConnectCancellationJoinsIKETaskManager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	firstSend := make(chan struct{})
	var sentOnce sync.Once
	transport := newInitTestTransport(func([]byte) {
		sentOnce.Do(func() { close(firstSend) })
	})
	session := NewSession(&Config{
		LocalAddr: "192.0.2.10",
		EpDGAddr:  "192.0.2.20",
		LocalPort: 45000,
		EpDGPort:  500,
		TransportFactory: func(string, string) (Transport, error) {
			return transport, nil
		},
	}, zap.NewNop())

	result := make(chan error, 1)
	go func() { result <- session.Connect(ctx) }()
	select {
	case <-firstSend:
	case <-time.After(2 * time.Second):
		t.Fatal("Connect() did not send IKE_SA_INIT")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect() did not return after cancellation")
	}

	joined, ok := any(session.taskMgr).(interface{ Done() <-chan struct{} })
	if !ok {
		t.Fatal("IKE TaskManager exposes no join completion signal")
	}
	select {
	case <-joined.Done():
	default:
		t.Fatal("Connect() returned before IKE TaskManager stopped")
	}
}

func TestHandleIKESAInitResponseDoesNotRetryNoProposalChosen(t *testing.T) {
	const (
		spiI = uint64(0x0102030405060708)
		spiR = uint64(0x1112131415161718)
	)
	packet := ikev2.NewIKEPacket()
	packet.Header.SPIi = spiI
	packet.Header.SPIr = spiR
	packet.Header.Version = 0x20
	packet.Header.ExchangeType = ikev2.IKE_SA_INIT
	packet.Header.Flags = ikev2.FlagResponse
	packet.Header.MessageID = 0
	packet.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: 14,
	}}
	raw, err := packet.Encode()
	if err != nil {
		t.Fatalf("encode NO_PROPOSAL_CHOSEN response: %v", err)
	}
	session := &Session{SPIi: spiI, Logger: zap.NewNop()}
	err = session.handleIKESAInitResp(raw)
	if err == nil {
		t.Fatal("handleIKESAInitResp() accepted NO_PROPOSAL_CHOSEN")
	}
	var invalidKE suggestedDHGroupError
	if errors.As(err, &invalidKE) {
		t.Fatal("NO_PROPOSAL_CHOSEN entered INVALID_KE retry branch")
	}
	if session.SPIr != 0 {
		t.Fatal("NO_PROPOSAL_CHOSEN installed responder SPI")
	}
}

func TestConnectGroup15InvalidKERetryCreatesOnlyOneIKEAuthState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var (
		mu             sync.Mutex
		transport      *initTestTransport
		saInitRequests int
		authRequests   int
	)
	transport = newInitTestTransport(func(request []byte) {
		header, err := ikev2.DecodeHeader(request)
		if err != nil {
			cancel()
			return
		}
		mu.Lock()
		if header.ExchangeType == ikev2.IKE_SA_INIT {
			saInitRequests++
		} else if header.ExchangeType == ikev2.IKE_AUTH {
			authRequests++
		}
		attempt := saInitRequests
		mu.Unlock()
		switch {
		case header.ExchangeType == ikev2.IKE_SA_INIT && attempt == 1:
			transport.ikeCh <- syntheticInvalidKEPayloadResponse(header.SPIi, 0x1112131415161718, 15)
		case header.ExchangeType == ikev2.IKE_SA_INIT && attempt == 2:
			transport.ikeCh <- syntheticSuccessfulIKESAInitResponse(t, request, 0x2122232425262728)
		case header.ExchangeType == ikev2.IKE_AUTH:
			cancel()
		}
	})
	factoryCalls := 0
	session := NewSession(&Config{
		LocalAddr:    "192.0.2.10",
		EpDGAddr:     "192.0.2.20",
		LocalPort:    45000,
		EpDGPort:     500,
		APN:          "ims.test.invalid",
		FastReauthID: "synthetic-test-id",
		TransportFactory: func(string, string) (Transport, error) {
			factoryCalls++
			return transport, nil
		},
	}, zap.NewNop())

	result := make(chan error, 1)
	go func() { result <- session.Connect(ctx) }()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect() error = %v, want context.Canceled after IKE_AUTH", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect() did not reach IKE_AUTH after INVALID_KE retry")
	}

	mu.Lock()
	gotSAInit, gotAuth := saInitRequests, authRequests
	mu.Unlock()
	if gotSAInit != 2 || gotAuth != 1 {
		t.Fatalf("request counts: IKE_SA_INIT=%d IKE_AUTH=%d, want 2/1", gotSAInit, gotAuth)
	}
	if factoryCalls != 1 {
		t.Fatalf("transport factory calls = %d, want 1", factoryCalls)
	}
}

func TestHandleIKESAInitResponseRejectsSelectedDHOrKEMismatch(t *testing.T) {
	tests := map[string]func(*ikev2.IKEPacket){
		"KE group differs from proposal": func(packet *ikev2.IKEPacket) {
			for _, payload := range packet.Payloads {
				if ke, ok := payload.(*ikev2.EncryptedPayloadKE); ok {
					ke.DHGroup = ikev2.MODP_3072_bit
				}
			}
		},
		"proposal differs from generated group": func(packet *ikev2.IKEPacket) {
			for _, payload := range packet.Payloads {
				if sa, ok := payload.(*ikev2.EncryptedPayloadSA); ok {
					for _, transform := range sa.Proposals[0].Transforms {
						if transform.Type == ikev2.TransformTypeDH {
							transform.ID = ikev2.MODP_3072_bit
						}
					}
				}
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			session := &Session{
				cfg: &Config{
					LocalAddr: "192.0.2.10",
					EpDGAddr:  "192.0.2.20",
					LocalPort: 45000,
					EpDGPort:  500,
				},
				SPIi:   0x0102030405060708,
				Logger: zap.NewNop(),
			}
			request, err := session.buildIKESAInitPacket()
			if err != nil {
				t.Fatalf("buildIKESAInitPacket() error = %v", err)
			}
			response := syntheticSuccessfulIKESAInitResponse(t, request, 0x1112131415161718)
			decoded, err := ikev2.DecodePacket(response)
			if err != nil {
				t.Fatalf("decode successful response: %v", err)
			}
			mutate(decoded)
			response, err = decoded.Encode()
			if err != nil {
				t.Fatalf("encode mismatched response: %v", err)
			}
			if err := session.handleIKESAInitResp(response); err == nil {
				t.Fatal("handleIKESAInitResp() accepted mismatched DH selection")
			}
			if session.Keys != nil {
				t.Fatal("mismatched DH selection generated IKE SA keys")
			}
			if session.SPIr != 0 || len(session.nr) != 0 {
				t.Fatal("mismatched DH selection committed responder state")
			}
		})
	}
}

func TestHandleIKESAInitResponseNATTransitionRequiresValidatedSA(t *testing.T) {
	for _, valid := range []bool{true, false} {
		name := "valid"
		if !valid {
			name = "dh-mismatch"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			transport := newInitTestTransport(nil)
			transport.localIP = net.ParseIP("192.0.2.10")
			transport.remoteIP = net.ParseIP("192.0.2.20")
			transport.localPort = 45000
			transport.remotePort = 500
			session := &Session{
				cfg: &Config{
					LocalAddr: "192.0.2.10",
					EpDGAddr:  "192.0.2.20",
					LocalPort: 45000,
					EpDGPort:  500,
				},
				SPIi:   0x0102030405060708,
				Logger: zap.NewNop(),
				socket: transport,
				ctx:    ctx,
			}
			request, err := session.buildIKESAInitPacket()
			if err != nil {
				t.Fatalf("buildIKESAInitPacket() error = %v", err)
			}
			response := syntheticSuccessfulIKESAInitResponse(t, request, 0x1112131415161718)
			decoded, err := ikev2.DecodePacket(response)
			if err != nil {
				t.Fatalf("decode successful response: %v", err)
			}
			decoded.Payloads = append(decoded.Payloads,
				ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_SOURCE_IP, bytes.Repeat([]byte{0x01}, 20)),
				ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_DESTINATION_IP, bytes.Repeat([]byte{0x02}, 20)))
			if !valid {
				for _, payload := range decoded.Payloads {
					if ke, ok := payload.(*ikev2.EncryptedPayloadKE); ok {
						ke.DHGroup = ikev2.MODP_3072_bit
					}
				}
			}
			response, err = decoded.Encode()
			if err != nil {
				t.Fatalf("encode response: %v", err)
			}
			err = session.handleIKESAInitResp(response)
			if valid {
				if err != nil {
					t.Fatalf("handleIKESAInitResp() error = %v", err)
				}
				if transport.setRemoteCalls != 1 || transport.remotePort != 4500 || !session.natKeepaliveStarted {
					t.Fatalf("valid NAT transition: calls=%d port=%d keepalive=%t", transport.setRemoteCalls, transport.remotePort, session.natKeepaliveStarted)
				}
				return
			}
			if err == nil {
				t.Fatal("handleIKESAInitResp() accepted mismatched DH selection")
			}
			if transport.setRemoteCalls != 0 || session.natKeepaliveStarted {
				t.Fatalf("invalid SA caused NAT side effects: calls=%d keepalive=%t", transport.setRemoteCalls, session.natKeepaliveStarted)
			}
		})
	}
}
