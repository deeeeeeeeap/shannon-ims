package imscore

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

type registerSessionTestNetwork struct {
	dialCount int
	serve     func(net.Conn)
}

func (n *registerSessionTestNetwork) DialContext(_ context.Context, _ string, _ net.Addr, _ string, _ DialOptions) (net.Conn, error) {
	n.dialCount++
	conn, peer := net.Pipe()
	go n.serve(peer)
	return conn, nil
}

func (*registerSessionTestNetwork) HasLocalIP([]byte) bool { return false }
func (*registerSessionTestNetwork) ListenPacket(context.Context, string, net.Addr) (net.PacketConn, error) {
	return nil, nil
}
func (*registerSessionTestNetwork) ListenTCP(context.Context, *net.TCPAddr) (net.Listener, error) {
	return nil, nil
}
func (*registerSessionTestNetwork) LocalIP() []byte { return nil }
func (*registerSessionTestNetwork) ResolveIP(context.Context, string, bool) ([]byte, error) {
	return nil, nil
}

type registerSessionTestCapture struct {
	requests []*sip.Request
	err      error
}

type repeatedSyncFailureAKA struct {
	calls atomic.Int32
}

func (p *repeatedSyncFailureAKA) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	_ = rand16
	_ = autn16
	p.calls.Add(1)
	syncToken := make([]byte, 14)
	for i := range syncToken {
		syncToken[i] = byte(i + 1)
	}
	return sim.AKAResult{AUTS: syncToken}, sim.ErrSyncFailure
}

type resyncThenSuccessAKA struct {
	calls atomic.Int32
}

func (p *resyncThenSuccessAKA) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	_ = rand16
	_ = autn16
	switch p.calls.Add(1) {
	case 1:
		syncToken := make([]byte, 14)
		for i := range syncToken {
			syncToken[i] = byte(i + 1)
		}
		return sim.AKAResult{AUTS: syncToken}, sim.ErrSyncFailure
	case 2:
		result := sim.AKAResult{
			RES: make([]byte, 8),
			CK:  make([]byte, 16),
			IK:  make([]byte, 16),
		}
		for i := range result.RES {
			result.RES[i] = byte(i + 1)
		}
		for i := range result.CK {
			result.CK[i] = byte(i + 17)
			result.IK[i] = byte(i + 33)
		}
		return result, nil
	default:
		return sim.AKAResult{}, fmt.Errorf("unexpected AKA call")
	}
}

type registerSessionTestPacketDataplane struct {
	inner      chan []byte
	sent       chan []byte
	espPackets atomic.Int32
}

func newRegisterSessionTestPacketDataplane() *registerSessionTestPacketDataplane {
	return &registerSessionTestPacketDataplane{
		inner: make(chan []byte, 8),
		sent:  make(chan []byte, 8),
	}
}

func (d *registerSessionTestPacketDataplane) SendInnerPacket(packet []byte) error {
	copyPacket := append([]byte(nil), packet...)
	if registerSessionTestIPProtocol(copyPacket) == 50 {
		d.espPackets.Add(1)
	}
	d.sent <- copyPacket
	return nil
}

func (d *registerSessionTestPacketDataplane) InnerPackets() <-chan []byte { return d.inner }

type registerSessionTestPacketRelay struct {
	read   <-chan []byte
	write  chan<- []byte
	local  net.Addr
	remote net.Addr
}

func (c *registerSessionTestPacketRelay) Read(p []byte) (int, error) {
	packet := <-c.read
	packet, err := reassembleRegisterSessionTestIPv4Packet(packet, c.read)
	if err != nil {
		return 0, err
	}
	return copy(p, packet), nil
}

func reassembleRegisterSessionTestIPv4Packet(first []byte, more <-chan []byte) ([]byte, error) {
	if len(first) < 20 || first[0]>>4 != 4 {
		return first, nil
	}
	headerLen := int(first[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(first) {
		return nil, fmt.Errorf("invalid test IPv4 fragment header length")
	}
	flagsOffset := binary.BigEndian.Uint16(first[6:8])
	if flagsOffset&0x3fff == 0 {
		return first, nil
	}
	if flagsOffset&0x1fff != 0 {
		return nil, fmt.Errorf("first test IPv4 fragment has non-zero offset")
	}
	identification := binary.BigEndian.Uint16(first[4:6])
	header := append([]byte(nil), first[:headerLen]...)
	payload := append([]byte(nil), first[headerLen:]...)
	moreFragments := flagsOffset&0x2000 != 0
	for moreFragments {
		fragment := <-more
		if len(fragment) < headerLen || fragment[0]>>4 != 4 {
			return nil, fmt.Errorf("invalid test IPv4 continuation fragment")
		}
		if binary.BigEndian.Uint16(fragment[4:6]) != identification {
			return nil, fmt.Errorf("test IPv4 fragment identification mismatch")
		}
		fragmentFlagsOffset := binary.BigEndian.Uint16(fragment[6:8])
		if got, want := int(fragmentFlagsOffset&0x1fff)*8, len(payload); got != want {
			return nil, fmt.Errorf("test IPv4 fragment offset = %d, want %d", got, want)
		}
		payload = append(payload, fragment[headerLen:]...)
		moreFragments = fragmentFlagsOffset&0x2000 != 0
	}
	packet := append(header, payload...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[6:8], 0)
	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], registerSessionTestIPv4Checksum(packet[:headerLen]))
	return packet, nil
}

func registerSessionTestIPv4Checksum(header []byte) uint16 {
	var sum uint32
	for len(header) > 1 {
		sum += uint32(binary.BigEndian.Uint16(header[:2]))
		header = header[2:]
	}
	if len(header) == 1 {
		sum += uint32(header[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (c *registerSessionTestPacketRelay) Write(p []byte) (int, error) {
	c.write <- append([]byte(nil), p...)
	return len(p), nil
}

func (*registerSessionTestPacketRelay) Close() error                     { return nil }
func (c *registerSessionTestPacketRelay) LocalAddr() net.Addr            { return c.local }
func (c *registerSessionTestPacketRelay) RemoteAddr() net.Addr           { return c.remote }
func (*registerSessionTestPacketRelay) SetDeadline(time.Time) error      { return nil }
func (*registerSessionTestPacketRelay) SetReadDeadline(time.Time) error  { return nil }
func (*registerSessionTestPacketRelay) SetWriteDeadline(time.Time) error { return nil }

type registerSessionTestRawSWU struct {
	base     voiceclient.SWUTCPDialer
	dp       *registerSessionTestPacketDataplane
	state    func() *registerState
	secureCh chan<- registerSessionTestCapture
	rawCalls atomic.Int32
	tcpCalls atomic.Int32
}

func (s *registerSessionTestRawSWU) DialContextIP(ctx context.Context, localIP net.IP, remoteIP net.IP, protocol uint8) (net.Conn, error) {
	s.rawCalls.Add(1)
	if protocol != 50 {
		return nil, fmt.Errorf("raw protocol = %d, want ESP", protocol)
	}
	rawDialer, ok := s.base.(voiceclient.SWURawIPDialer)
	if !ok {
		return nil, fmt.Errorf("base SWu dialer lacks raw IP support")
	}
	state := s.state()
	if state == nil || state.transport == nil || len(state.ck) == 0 || len(state.ik) == 0 {
		return nil, fmt.Errorf("raw ESP dial before IPsec state is ready")
	}
	serverPolicy := reverseRegisterSessionTestPolicy(state.ipsecPolicy)
	serverTransport, err := ipsec3gpp.NewTransport(serverPolicy)
	if err != nil {
		return nil, err
	}
	serverRaw := &registerSessionTestPacketRelay{
		read:   s.dp.sent,
		write:  s.dp.inner,
		local:  &net.IPAddr{IP: remoteIP},
		remote: &net.IPAddr{IP: localIP},
	}
	securePeer := ipsec3gpp.WrapSecureChannelUDP(serverRaw, serverTransport, serverPolicy)
	go func() {
		defer securePeer.Close()
		capture := registerSessionTestCapture{}
		defer func() { s.secureCh <- capture }()

		request, readErr := readRegisterSessionTestRequest(bufio.NewReader(securePeer))
		if readErr != nil {
			capture.err = readErr
			return
		}
		capture.requests = append(capture.requests, request)
		response := sip.NewResponseFromRequest(request, sip.StatusOK, "OK", nil)
		if _, writeErr := io.WriteString(securePeer, response.String()); writeErr != nil {
			capture.err = writeErr
		}
	}()
	return rawDialer.DialContextIP(ctx, localIP, remoteIP, protocol)
}

func (s *registerSessionTestRawSWU) DialContextTCP(context.Context, net.IP, int, net.IP, int) (net.Conn, error) {
	s.tcpCalls.Add(1)
	return nil, fmt.Errorf("unexpected secure TCP dial")
}

func (s *registerSessionTestRawSWU) DialContextUDP(ctx context.Context, localIP net.IP, localPort int, remoteIP net.IP, remotePort int) (net.Conn, error) {
	return s.base.DialContextUDP(ctx, localIP, localPort, remoteIP, remotePort)
}

func (s *registerSessionTestRawSWU) ListenContextTCP(ctx context.Context, localIP net.IP, localPort int) (net.Listener, error) {
	return s.base.ListenContextTCP(ctx, localIP, localPort)
}

func (s *registerSessionTestRawSWU) ListenContextUDP(ctx context.Context, localIP net.IP, localPort int) (net.PacketConn, error) {
	return s.base.ListenContextUDP(ctx, localIP, localPort)
}

func (s *registerSessionTestRawSWU) Close() error { return s.base.Close() }

func registerSessionTestIPProtocol(packet []byte) byte {
	if len(packet) < 1 {
		return 0
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) >= 20 {
			return packet[9]
		}
	case 6:
		if len(packet) >= 40 {
			return packet[6]
		}
	}
	return 0
}

func TestAUTSResyncRejectsRepeatedChallengeNonceBeforeSecondUSIMCall(t *testing.T) {
	challengeBytes := make([]byte, 32)
	for i := range challengeBytes {
		challengeBytes[i] = byte(i + 1)
	}
	challengeNonce := base64.StdEncoding.EncodeToString(challengeBytes)

	captureCh := make(chan registerSessionTestCapture, 1)
	network := &registerSessionTestNetwork{}
	network.serve = func(peer net.Conn) {
		defer peer.Close()
		capture := registerSessionTestCapture{}
		defer func() { captureCh <- capture }()

		reader := bufio.NewReader(peer)
		initial, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			capture.err = fmt.Errorf("read initial REGISTER: %w", err)
			return
		}
		capture.requests = append(capture.requests, initial)
		if err := writeRegisterSessionTestAKAChallenge(peer, initial, challengeNonce); err != nil {
			capture.err = fmt.Errorf("write initial 401: %w", err)
			return
		}

		resync, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			capture.err = fmt.Errorf("read AUTS REGISTER: %w", err)
			return
		}
		capture.requests = append(capture.requests, resync)
		if err := peer.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			capture.err = err
			return
		}
		if err := writeRegisterSessionTestAKAChallenge(peer, resync, challengeNonce); err != nil {
			capture.err = fmt.Errorf("write repeated 401: %w", err)
			return
		}

		third, err := readRegisterSessionTestRequest(reader)
		if err == nil {
			capture.requests = append(capture.requests, third)
			if writeErr := writeRegisterSessionTestResponse(peer, third, sip.StatusForbidden, "Forbidden", false); writeErr != nil {
				capture.err = writeErr
			}
		}
	}

	aka := &repeatedSyncFailureAKA{}
	cfg := registerSessionTestConfig()
	cfg.AKA = aka
	session := newRegisterSession(cfg, nil, network, "udp", 0)
	session.jitter = false
	session.localPort = 41234

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := session.runInitialRegisterFlow(ctx)
	if err == nil || !strings.Contains(err.Error(), "repeated AKA challenge nonce") {
		t.Fatalf("runInitialRegisterFlow error = %v, want repeated AKA challenge nonce", err)
	}

	capture := <-captureCh
	if capture.err != nil {
		t.Fatal(capture.err)
	}
	if got := aka.calls.Load(); got != 1 {
		t.Fatalf("AKA calls = %d, want 1", got)
	}
	if len(capture.requests) != 2 {
		t.Fatalf("REGISTER request count = %d, want 2", len(capture.requests))
	}
	resync := capture.requests[1]
	authorization := registerSessionTestHeaderValue(resync, "Authorization")
	if !strings.Contains(strings.ToLower(authorization), "auts=") {
		t.Fatal("AUTS REGISTER Authorization is missing auts directive")
	}
	if got := resync.GetHeader("Security-Verify"); got != nil {
		t.Fatalf("AUTS REGISTER Security-Verify = %q, want omitted", got.Value())
	}
}

func TestAUTSResyncRejectsRepeatedAUTSBeforeSecondResyncRegister(t *testing.T) {
	nonceForSeed := func(seed byte) string {
		challengeBytes := make([]byte, 32)
		for i := range challengeBytes {
			challengeBytes[i] = seed + byte(i)
		}
		return base64.StdEncoding.EncodeToString(challengeBytes)
	}

	captureCh := make(chan registerSessionTestCapture, 1)
	network := &registerSessionTestNetwork{}
	network.serve = func(peer net.Conn) {
		defer peer.Close()
		capture := registerSessionTestCapture{}
		defer func() { captureCh <- capture }()

		reader := bufio.NewReader(peer)
		initial, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			capture.err = err
			return
		}
		capture.requests = append(capture.requests, initial)
		if err := writeRegisterSessionTestAKAChallenge(peer, initial, nonceForSeed(1)); err != nil {
			capture.err = err
			return
		}

		resync, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			capture.err = err
			return
		}
		capture.requests = append(capture.requests, resync)
		if err := peer.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			capture.err = err
			return
		}
		if err := writeRegisterSessionTestAKAChallenge(peer, resync, nonceForSeed(65)); err != nil {
			capture.err = err
			return
		}

		third, err := readRegisterSessionTestRequest(reader)
		if err == nil {
			capture.requests = append(capture.requests, third)
			if writeErr := writeRegisterSessionTestResponse(peer, third, sip.StatusForbidden, "Forbidden", false); writeErr != nil {
				capture.err = writeErr
			}
		}
	}

	aka := &repeatedSyncFailureAKA{}
	cfg := registerSessionTestConfig()
	cfg.AKA = aka
	session := newRegisterSession(cfg, nil, network, "udp", 0)
	session.jitter = false
	session.localPort = 41234

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := session.runInitialRegisterFlow(ctx)
	if err == nil || !strings.Contains(err.Error(), "repeated AUTS resync state") {
		t.Fatalf("runInitialRegisterFlow error = %v, want repeated AUTS resync state", err)
	}

	capture := <-captureCh
	if capture.err != nil {
		t.Fatal(capture.err)
	}
	if got := aka.calls.Load(); got != 2 {
		t.Fatalf("AKA calls = %d, want 2", got)
	}
	if len(capture.requests) != 2 {
		t.Fatalf("REGISTER request count = %d, want 2", len(capture.requests))
	}
}

func TestAUTSResyncFreshChallengeInstallsIPSecThenProtectedRegister(t *testing.T) {
	nonceForSeed := func(seed byte) string {
		challengeBytes := make([]byte, 32)
		for i := range challengeBytes {
			challengeBytes[i] = seed + byte(i)
		}
		return base64.StdEncoding.EncodeToString(challengeBytes)
	}
	firstNonce := nonceForSeed(1)
	freshNonce := nonceForSeed(65)

	unprotectedCh := make(chan registerSessionTestCapture, 1)
	network := &registerSessionTestNetwork{}
	network.serve = func(peer net.Conn) {
		defer peer.Close()
		capture := registerSessionTestCapture{}
		defer func() { unprotectedCh <- capture }()

		reader := bufio.NewReader(peer)
		initial, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			capture.err = fmt.Errorf("read initial REGISTER: %w", err)
			return
		}
		capture.requests = append(capture.requests, initial)
		if err := writeRegisterSessionTestAKAChallenge(peer, initial, firstNonce); err != nil {
			capture.err = fmt.Errorf("write initial 401: %w", err)
			return
		}

		resync, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			capture.err = fmt.Errorf("read AUTS REGISTER: %w", err)
			return
		}
		capture.requests = append(capture.requests, resync)
		if err := writeRegisterSessionTestAKAChallenge(peer, resync, freshNonce); err != nil {
			capture.err = fmt.Errorf("write fresh 401: %w", err)
		}
	}

	aka := &resyncThenSuccessAKA{}
	secureCh := make(chan registerSessionTestCapture, 1)
	cfg := registerSessionTestConfig()
	cfg.Template.RequireSecAgree = true
	cfg.Template.ProxyRequireSecAgree = true
	cfg.AKA = aka
	dp := newRegisterSessionTestPacketDataplane()
	baseSWU, err := voiceclient.NewSWUTCPDialer(cfg.LocalIP, dp)
	if err != nil {
		t.Fatalf("NewSWUTCPDialer: %v", err)
	}
	var session *registerSession
	swu := &registerSessionTestRawSWU{
		base:     baseSWU,
		dp:       dp,
		state:    func() *registerState { return session.state },
		secureCh: secureCh,
	}
	defer swu.Close()
	session = newRegisterSession(cfg, swu, network, "udp", 0)
	session.jitter = false
	session.localPort = 41234
	session.state.spiC = 2001
	session.state.spiS = 2002

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := session.runInitialRegisterFlow(ctx)
	if err != nil {
		select {
		case secure := <-secureCh:
			t.Fatalf(
				"runInitialRegisterFlow: %v; secure_peer_error=%v protected_requests=%d",
				err,
				secure.err,
				len(secure.requests),
			)
		case <-time.After(time.Second):
			t.Fatalf("runInitialRegisterFlow: %v; secure peer did not finish", err)
		}
	}
	if result == nil || result.secureConn == nil {
		t.Fatal("REGISTER succeeded without a secure connection")
	}
	defer result.secureConn.Close()

	unprotected := <-unprotectedCh
	if unprotected.err != nil {
		t.Fatal(unprotected.err)
	}
	if len(unprotected.requests) != 2 {
		t.Fatalf("unprotected REGISTER count = %d, want 2", len(unprotected.requests))
	}
	resync := unprotected.requests[1]
	if !strings.Contains(strings.ToLower(registerSessionTestHeaderValue(resync, "Authorization")), "auts=") {
		t.Fatal("AUTS REGISTER Authorization is missing auts directive")
	}
	if resync.GetHeader("Security-Verify") != nil {
		t.Fatal("AUTS REGISTER must not include Security-Verify")
	}
	if strings.Contains(strings.ToLower(registerSessionTestHeaderValue(resync, "Authorization")), "integrity-protected=") {
		t.Fatal("AUTS REGISTER Authorization must not claim integrity protection")
	}

	secure := <-secureCh
	if secure.err != nil {
		t.Fatal(secure.err)
	}
	if len(secure.requests) != 1 {
		t.Fatalf("protected REGISTER count = %d, want 1", len(secure.requests))
	}
	protected := secure.requests[0]
	if protected.GetHeader("Security-Verify") == nil {
		t.Fatal("protected REGISTER is missing Security-Verify")
	}
	if got, want := registerSessionTestHeaderValue(protected, "Security-Client"), registerSessionTestHeaderValue(resync, "Security-Client"); got == "" || got != want {
		t.Fatalf("protected REGISTER Security-Client = %q, want challenged value %q", got, want)
	}
	if strings.Contains(strings.ToLower(registerSessionTestHeaderValue(protected, "Authorization")), "auts=") {
		t.Fatal("protected REGISTER reused AUTS Authorization")
	}
	if strings.Contains(strings.ToLower(registerSessionTestHeaderValue(protected, "Authorization")), "integrity-protected=") {
		t.Fatal("UE protected REGISTER Authorization must leave integrity-protected insertion to the P-CSCF")
	}
	wantProtectedHeaderOrder := []string{
		"Via",
		"Max-Forwards",
		"From",
		"To",
		"Call-ID",
		"CSeq",
		"Contact",
		"Expires",
		"Supported",
		"Authorization",
		"Security-Client",
		"Security-Verify",
		"Require",
		"Proxy-Require",
		"User-Agent",
		"Content-Length",
	}
	if got := registerSessionTestHeaderNames(protected); !reflect.DeepEqual(got, wantProtectedHeaderOrder) {
		t.Fatalf("protected REGISTER header order = %v, want %v", got, wantProtectedHeaderOrder)
	}
	wantServerPort := result.ipsecPolicy.FlowS.LocalPort
	if wantServerPort <= 0 || wantServerPort == result.ipsecPolicy.FlowC.LocalPort {
		t.Fatalf("invalid protected server port mapping: flow_c=%d flow_s=%d", result.ipsecPolicy.FlowC.LocalPort, wantServerPort)
	}
	wantServerPortToken := ":" + strconv.Itoa(wantServerPort)
	if got := registerSessionTestHeaderValue(protected, "Via"); !strings.Contains(got, wantServerPortToken) {
		t.Fatalf("protected REGISTER Via = %q, want protected server port %d", got, wantServerPort)
	}
	if got := registerSessionTestHeaderValue(protected, "Contact"); !strings.Contains(got, wantServerPortToken) {
		t.Fatalf("protected REGISTER Contact = %q, want protected server port %d", got, wantServerPort)
	}
	if got := aka.calls.Load(); got != 2 {
		t.Fatalf("AKA calls = %d, want 2", got)
	}
	if got := swu.rawCalls.Load(); got != 1 {
		t.Fatalf("secure raw ESP dials = %d, want 1", got)
	}
	if got := swu.tcpCalls.Load(); got != 0 {
		t.Fatalf("secure TCP dials = %d, want 0", got)
	}
	if got := dp.espPackets.Load(); got == 0 {
		t.Fatal("protected REGISTER did not emit an ESP/IP packet")
	}
}

func TestVodafoneUKRetriesSecAgreeOnSameRegisterSessionAfter421(t *testing.T) {
	captureCh := make(chan registerSessionTestCapture, 1)
	network := &registerSessionTestNetwork{}
	network.serve = func(peer net.Conn) {
		defer peer.Close()
		capture := registerSessionTestCapture{}
		defer func() { captureCh <- capture }()

		reader := bufio.NewReader(peer)
		first, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			capture.err = fmt.Errorf("read first REGISTER: %w", err)
			return
		}
		capture.requests = append(capture.requests, first)
		if err := writeRegisterSessionTestResponse(peer, first, sip.StatusExtensionRequired, "Extension Required", true); err != nil {
			capture.err = fmt.Errorf("write 421: %w", err)
			return
		}

		second, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			capture.err = fmt.Errorf("read second REGISTER: %w", err)
			return
		}
		capture.requests = append(capture.requests, second)
		if err := writeRegisterSessionTestResponse(peer, second, sip.StatusForbidden, "Forbidden", false); err != nil {
			capture.err = fmt.Errorf("write 403: %w", err)
		}
	}

	cfg := registerSessionTestConfig()
	session := newRegisterSession(cfg, nil, network, "udp", 0)
	session.jitter = false
	session.localPort = 41234

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := session.runInitialRegisterFlow(ctx); err == nil {
		t.Fatalf("runInitialRegisterFlow succeeded, want final 403 failure")
	}

	capture := <-captureCh
	if capture.err != nil {
		t.Fatal(capture.err)
	}
	if network.dialCount != 1 {
		t.Fatalf("REGISTER connection count = %d, want 1", network.dialCount)
	}
	if len(capture.requests) != 2 {
		t.Fatalf("REGISTER request count = %d, want 2", len(capture.requests))
	}

	first, second := capture.requests[0], capture.requests[1]
	if got := first.GetHeader("Require"); got != nil {
		t.Fatalf("first REGISTER Require = %q, want omitted", got.Value())
	}
	if got := first.GetHeader("Proxy-Require"); got != nil {
		t.Fatalf("first REGISTER Proxy-Require = %q, want omitted", got.Value())
	}
	require := second.GetHeader("Require")
	if require == nil || !strings.EqualFold(strings.TrimSpace(require.Value()), "sec-agree") {
		t.Fatalf("second REGISTER Require = %v, want sec-agree", require)
	}
	proxyRequire := second.GetHeader("Proxy-Require")
	if proxyRequire == nil || !strings.EqualFold(strings.TrimSpace(proxyRequire.Value()), "sec-agree") {
		t.Fatalf("second REGISTER Proxy-Require = %v, want sec-agree", proxyRequire)
	}

	firstCallID := registerSessionTestHeaderValue(first, "Call-ID")
	secondCallID := registerSessionTestHeaderValue(second, "Call-ID")
	if firstCallID == "" || secondCallID != firstCallID {
		t.Fatalf("Call-ID changed across 421 retry: first=%q second=%q", firstCallID, secondCallID)
	}
	firstCSeq := registerSessionTestCSeq(t, first)
	secondCSeq := registerSessionTestCSeq(t, second)
	if secondCSeq != firstCSeq+1 {
		t.Fatalf("CSeq after 421 = %d, want %d", secondCSeq, firstCSeq+1)
	}
	firstSecurityClient := registerSessionTestHeaderValue(first, "Security-Client")
	secondSecurityClient := registerSessionTestHeaderValue(second, "Security-Client")
	if firstSecurityClient == "" || secondSecurityClient != firstSecurityClient {
		t.Fatalf("Security-Client changed across 421 retry: first=%q second=%q", firstSecurityClient, secondSecurityClient)
	}
	wantHeaderOrder := []string{
		"Via",
		"Max-Forwards",
		"From",
		"To",
		"Call-ID",
		"CSeq",
		"Contact",
		"Expires",
		"Supported",
		"Authorization",
		"Security-Client",
		"Require",
		"Proxy-Require",
		"User-Agent",
		"Content-Length",
	}
	if got := registerSessionTestHeaderNames(second); !reflect.DeepEqual(got, wantHeaderOrder) {
		t.Fatalf("421 retry header order = %v, want %v", got, wantHeaderOrder)
	}
}

func TestVodafoneUKAUTSResyncReusesChallengedRawRegisterProfile(t *testing.T) {
	captureCh := make(chan registerSessionTestCapture, 1)
	network := &registerSessionTestNetwork{}
	network.serve = func(peer net.Conn) {
		defer peer.Close()
		capture := registerSessionTestCapture{}
		defer func() { captureCh <- capture }()

		reader := bufio.NewReader(peer)
		first, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			capture.err = fmt.Errorf("read first REGISTER: %w", err)
			return
		}
		capture.requests = append(capture.requests, first)
		if err := writeRegisterSessionTestResponse(peer, first, sip.StatusExtensionRequired, "Extension Required", true); err != nil {
			capture.err = fmt.Errorf("write 421: %w", err)
			return
		}

		challenged, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			capture.err = fmt.Errorf("read challenged REGISTER: %w", err)
			return
		}
		capture.requests = append(capture.requests, challenged)
		challengeBytes := make([]byte, 32)
		for i := range challengeBytes {
			challengeBytes[i] = byte(i + 1)
		}
		if err := writeRegisterSessionTestAKAChallenge(peer, challenged, base64.StdEncoding.EncodeToString(challengeBytes)); err != nil {
			capture.err = fmt.Errorf("write 401: %w", err)
			return
		}

		resync, err := readRegisterSessionTestRequest(reader)
		if err != nil {
			capture.err = fmt.Errorf("read AUTS REGISTER: %w", err)
			return
		}
		capture.requests = append(capture.requests, resync)
		if err := writeRegisterSessionTestResponse(peer, resync, sip.StatusForbidden, "Forbidden", false); err != nil {
			capture.err = fmt.Errorf("write final response: %w", err)
		}
	}

	cfg := registerSessionTestConfig()
	cfg.AKA = &repeatedSyncFailureAKA{}
	session := newRegisterSession(cfg, nil, network, "udp", 0)
	session.jitter = false
	session.localPort = 41234

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := session.runInitialRegisterFlow(ctx); err == nil {
		t.Fatal("runInitialRegisterFlow succeeded, want final 403 failure")
	}

	capture := <-captureCh
	if capture.err != nil {
		t.Fatal(capture.err)
	}
	if len(capture.requests) != 3 {
		t.Fatalf("REGISTER request count = %d, want 3", len(capture.requests))
	}

	challenged, resync := capture.requests[1], capture.requests[2]
	if !strings.Contains(strings.ToLower(registerSessionTestHeaderValue(resync, "Authorization")), "auts=") {
		t.Fatal("AUTS REGISTER Authorization is missing auts directive")
	}
	if resync.GetHeader("Security-Verify") != nil {
		t.Fatal("AUTS REGISTER must not include Security-Verify")
	}
	for _, name := range []string{"Allow", "P-Preferred-Identity", "P-Visited-Network-ID", "P-Access-Network-Info", "Cellular-Network-Info", "Accept-Contact"} {
		if header := resync.GetHeader(name); header != nil {
			t.Fatalf("AUTS REGISTER unexpectedly added %s", name)
		}
	}
	wantHeaderOrder := []string{
		"Via",
		"Max-Forwards",
		"From",
		"To",
		"Call-ID",
		"CSeq",
		"Contact",
		"Expires",
		"Supported",
		"Authorization",
		"Security-Client",
		"Require",
		"Proxy-Require",
		"User-Agent",
		"Content-Length",
	}
	if got := registerSessionTestHeaderNames(resync); !reflect.DeepEqual(got, wantHeaderOrder) {
		t.Fatalf("AUTS REGISTER header profile = %v, want %v", got, wantHeaderOrder)
	}
	if got, want := registerSessionTestHeaderValue(resync, "Call-ID"), registerSessionTestHeaderValue(challenged, "Call-ID"); got != want {
		t.Fatalf("AUTS REGISTER Call-ID = %q, want %q", got, want)
	}
	if got, want := registerSessionTestCSeq(t, resync), registerSessionTestCSeq(t, challenged)+1; got != want {
		t.Fatalf("AUTS REGISTER CSeq = %d, want %d", got, want)
	}
	for _, name := range []string{"From", "To", "Contact", "Expires", "Supported", "Security-Client", "Require", "Proxy-Require", "User-Agent"} {
		if got, want := registerSessionTestHeaderValue(resync, name), registerSessionTestHeaderValue(challenged, name); got != want {
			t.Fatalf("AUTS REGISTER %s = %q, want challenged value %q", name, got, want)
		}
	}
}

func TestVodafoneUKKeepsSecAgreeWhenAdvancingAlgorithmAfter400(t *testing.T) {
	captureCh := make(chan registerSessionTestCapture, 1)
	network := &registerSessionTestNetwork{}
	network.serve = func(peer net.Conn) {
		defer peer.Close()
		capture := registerSessionTestCapture{}
		defer func() { captureCh <- capture }()

		reader := bufio.NewReader(peer)
		responses := []struct {
			status          int
			reason          string
			requireSecAgree bool
		}{
			{status: sip.StatusExtensionRequired, reason: "Extension Required", requireSecAgree: true},
			{status: sip.StatusBadRequest, reason: "Bad Request"},
			{status: sip.StatusForbidden, reason: "Forbidden"},
		}
		for i, response := range responses {
			req, err := readRegisterSessionTestRequest(reader)
			if err != nil {
				capture.err = fmt.Errorf("read REGISTER %d: %w", i+1, err)
				return
			}
			capture.requests = append(capture.requests, req)
			if err := writeRegisterSessionTestResponse(peer, req, response.status, response.reason, response.requireSecAgree); err != nil {
				capture.err = fmt.Errorf("write response %d: %w", i+1, err)
				return
			}
		}
	}

	cfg := registerSessionTestConfig()
	session := newRegisterSession(cfg, nil, network, "udp", 0)
	session.jitter = false
	session.localPort = 41234

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := session.runInitialRegisterFlow(ctx); err == nil {
		t.Fatalf("runInitialRegisterFlow succeeded, want final 403 failure")
	}

	capture := <-captureCh
	if capture.err != nil {
		t.Fatal(capture.err)
	}
	if network.dialCount != 1 {
		t.Fatalf("REGISTER connection count = %d, want 1", network.dialCount)
	}
	if len(capture.requests) != 3 {
		t.Fatalf("REGISTER request count = %d, want 3", len(capture.requests))
	}

	first, retry, nextAlgorithm := capture.requests[0], capture.requests[1], capture.requests[2]
	for requestIndex, req := range []*sip.Request{retry, nextAlgorithm} {
		require := req.GetHeader("Require")
		if require == nil || !strings.EqualFold(strings.TrimSpace(require.Value()), "sec-agree") {
			t.Fatalf("REGISTER %d Require = %v, want sec-agree", requestIndex+2, require)
		}
		header := req.GetHeader("Proxy-Require")
		if header == nil || !strings.EqualFold(strings.TrimSpace(header.Value()), "sec-agree") {
			t.Fatalf("REGISTER %d Proxy-Require = %v, want sec-agree", requestIndex+2, header)
		}
	}
	firstSecurityClient := registerSessionTestHeaderValue(first, "Security-Client")
	retrySecurityClient := registerSessionTestHeaderValue(retry, "Security-Client")
	nextSecurityClient := registerSessionTestHeaderValue(nextAlgorithm, "Security-Client")
	if retrySecurityClient != firstSecurityClient {
		t.Fatalf("421 retry changed Security-Client: first=%q retry=%q", firstSecurityClient, retrySecurityClient)
	}
	if nextSecurityClient == retrySecurityClient {
		t.Fatalf("400 did not advance Security-Client algorithm: %q", nextSecurityClient)
	}
	for _, want := range []string{"alg=hmac-sha-1-96", "ealg=null"} {
		if !strings.Contains(nextSecurityClient, want) {
			t.Fatalf("next Security-Client = %q, missing %q", nextSecurityClient, want)
		}
	}

	wantCallID := registerSessionTestHeaderValue(first, "Call-ID")
	wantCSeq := registerSessionTestCSeq(t, first)
	for i, req := range []*sip.Request{retry, nextAlgorithm} {
		if got := registerSessionTestHeaderValue(req, "Call-ID"); got != wantCallID {
			t.Fatalf("REGISTER %d Call-ID = %q, want %q", i+2, got, wantCallID)
		}
		if got := registerSessionTestCSeq(t, req); got != wantCSeq+uint64(i)+1 {
			t.Fatalf("REGISTER %d CSeq = %d, want %d", i+2, got, wantCSeq+uint64(i)+1)
		}
	}
}

func registerSessionTestConfig() Config {
	return Config{
		HomeDomain:         "ims.mnc015.mcc234.3gppnetwork.org",
		Realm:              "ims.mnc015.mcc234.3gppnetwork.org",
		PrivateID:          "subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		PublicURI:          "sip:subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		IMSI:               "234150000000000",
		LocalIP:            net.ParseIP("10.0.0.2"),
		PCSCFAddr:          "10.0.0.3:5060",
		TransportPCSCFAddr: "10.0.0.3:5060",
		Template:           policy.VodafoneUKTemplate(),
		UserAgent:          "Vodafone VOLTE Qualcomm",
	}
}

func readRegisterSessionTestRequest(reader *bufio.Reader) (*sip.Request, error) {
	var raw strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		raw.WriteString(line)
		if strings.HasSuffix(raw.String(), "\r\n\r\n") {
			break
		}
	}
	msg, err := sip.NewParser().ParseSIP([]byte(raw.String()))
	if err != nil {
		return nil, err
	}
	req, ok := msg.(*sip.Request)
	if !ok {
		return nil, fmt.Errorf("parsed %T, want *sip.Request", msg)
	}
	return req, nil
}

func writeRegisterSessionTestResponse(conn net.Conn, req *sip.Request, status int, reason string, requireSecAgree bool) error {
	res := sip.NewResponseFromRequest(req, status, reason, nil)
	if requireSecAgree {
		res.AppendHeader(sip.NewHeader("Require", "sec-agree"))
	}
	_, err := io.WriteString(conn, res.String())
	return err
}

func writeRegisterSessionTestAKAChallenge(conn net.Conn, req *sip.Request, nonce string) error {
	res := sip.NewResponseFromRequest(req, sip.StatusUnauthorized, "Unauthorized", nil)
	res.AppendHeader(sip.NewHeader(
		"WWW-Authenticate",
		fmt.Sprintf(`Digest realm="ims.example.invalid", nonce="%s", algorithm=AKAv1-MD5`, nonce),
	))
	res.AppendHeader(sip.NewHeader(
		"Security-Server",
		"ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;prot=esp;mod=trans;spi-c=100;spi-s=101;port-c=5090;port-s=5091",
	))
	_, err := io.WriteString(conn, res.String())
	return err
}

func reverseRegisterSessionTestPolicy(client ipsec3gpp.Policy) ipsec3gpp.Policy {
	reverseFlow := func(flow ipsec3gpp.Flow) ipsec3gpp.Flow {
		return ipsec3gpp.Flow{
			OutboundSPI: flow.InboundSPI,
			InboundSPI:  flow.OutboundSPI,
			LocalPort:   flow.RemotePort,
			RemotePort:  flow.LocalPort,
			AuthAlg:     flow.AuthAlg,
			EncAlg:      flow.EncAlg,
			CK:          append([]byte(nil), flow.CK...),
			IK:          append([]byte(nil), flow.IK...),
		}
	}
	return ipsec3gpp.Policy{
		LocalIP:     append([]byte(nil), client.RemoteIP...),
		RemoteIP:    append([]byte(nil), client.LocalIP...),
		LocalPortC:  client.RemotePortC,
		LocalPortS:  client.RemotePortS,
		RemotePortC: client.LocalPortC,
		RemotePortS: client.LocalPortS,
		FlowC:       reverseFlow(client.FlowC),
		FlowS:       reverseFlow(client.FlowS),
	}
}

func registerSessionTestHeaderValue(req *sip.Request, name string) string {
	if req == nil {
		return ""
	}
	header := req.GetHeader(name)
	if header == nil {
		return ""
	}
	return strings.TrimSpace(header.Value())
}

func registerSessionTestHeaderNames(req *sip.Request) []string {
	if req == nil {
		return nil
	}
	lines := strings.Split(req.String(), "\r\n")
	names := make([]string, 0, len(lines))
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		name, _, ok := strings.Cut(line, ":")
		if ok {
			names = append(names, name)
		}
	}
	return names
}

func registerSessionTestCSeq(t *testing.T, req *sip.Request) uint64 {
	t.Helper()
	value := registerSessionTestHeaderValue(req, "CSeq")
	fields := strings.Fields(value)
	if len(fields) != 2 || !strings.EqualFold(fields[1], "REGISTER") {
		t.Fatalf("CSeq = %q, want '<number> REGISTER'", value)
	}
	cseq, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		t.Fatalf("parse CSeq %q: %v", value, err)
	}
	return cseq
}
