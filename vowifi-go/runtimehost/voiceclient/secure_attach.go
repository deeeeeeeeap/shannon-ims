package voiceclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/google/uuid"
)

// AttachSecureMessaging binds the messaging client to an already-authenticated
// IMS ESP channel. It does not create another SWu netstack or repeat REGISTER.
func AttachSecureMessaging(ctx context.Context, cfg Config, conn net.Conn) (*Client, error) {
	return attachSecureMessaging(ctx, cfg, conn, "udp")
}

type secureStreamMessagingConn interface {
	net.Conn
	ReadSIPMessage() ([]byte, error)
	WriteServerFlow([]byte) (int, error)
}

// AttachSecureStreamMessaging binds messaging to the already-authenticated
// protected TCP flows. The connection supplies message framing because a TCP
// Read is not a SIP message boundary, and supplies the terminating-flow writer
// so responses return on the connection that carried the request.
func AttachSecureStreamMessaging(ctx context.Context, cfg Config, conn net.Conn) (*Client, error) {
	if _, ok := conn.(secureStreamMessagingConn); !ok {
		return nil, errors.New("voiceclient: secure stream messaging requires framed dual-flow connection")
	}
	return attachSecureMessaging(ctx, cfg, conn, "tcp")
}

func attachSecureMessaging(ctx context.Context, cfg Config, conn net.Conn, transport string) (*Client, error) {
	if conn == nil {
		return nil, errors.New("voiceclient: secure messaging connection is required")
	}
	if cfg.LocalIP == nil || cfg.LocalPort <= 0 {
		return nil, errors.New("voiceclient: secure messaging local endpoint is required")
	}
	if strings.TrimSpace(cfg.PCSCFAddr) == "" {
		return nil, errors.New("voiceclient: secure messaging P-CSCF is required")
	}
	if strings.TrimSpace(cfg.PrivateID) == "" || strings.TrimSpace(cfg.PublicURI) == "" || strings.TrimSpace(cfg.HomeDomain) == "" {
		return nil, errors.New("voiceclient: secure messaging IMS identity is required")
	}
	cfg.Transport = transport
	cfg.SkipRegister = true
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("voiceclient: clear inherited secure messaging deadline: %w", err)
	}

	registerProfile := registerProfileForConfig(cfg).Normalized()
	if strings.TrimSpace(cfg.RegisterProfile.ContactFeatures) != "" {
		registerProfile = cfg.RegisterProfile.Normalized()
	}
	sipInstanceURN := strings.TrimSpace(cfg.SIPInstanceURN)
	if sipInstanceURN == "" {
		sipInstanceURN = NewSIPInstanceURN()
	}
	contactUser := ""
	if registerProfile.ContactUserRandom {
		contactUser = newContactUserUUID()
	}
	c := &Client{
		cfg:             cfg,
		registerProfile: registerProfile,
		sipInstanceURN:  sipInstanceURN,
		contactUser:     contactUser,
		basePrivateID:   cfg.PrivateID,
		basePublicURI:   cfg.PublicURI,
		securityClient:  newSecurityClientState(),
		stopCh:          make(chan struct{}),
		stopDone:        make(chan struct{}),
	}
	c.secure = newSecureMessagingTransport(c, conn)
	go func() {
		select {
		case <-ctx.Done():
		case <-c.stopCh:
		}
		close(c.stopDone)
	}()
	return c, nil
}

type secureMessagingTransport struct {
	client *Client
	conn   net.Conn

	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[string]chan *sip.Response
	cseq    atomic.Uint32
	rpAcks  chan smsRPAckTask

	done      chan struct{}
	doneOnce  sync.Once
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func newSecureMessagingTransport(client *Client, conn net.Conn) *secureMessagingTransport {
	t := &secureMessagingTransport{
		client:  client,
		conn:    conn,
		pending: make(map[string]chan *sip.Response),
		rpAcks:  make(chan smsRPAckTask, 16),
		done:    make(chan struct{}),
	}
	t.cseq.Store(1)
	t.wg.Add(2)
	go t.readLoop()
	go t.rpAckLoop()
	return t
}

func (t *secureMessagingTransport) RoundTrip(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	if t == nil || t.conn == nil || req == nil {
		return nil, errors.New("voiceclient: secure messaging transport unavailable")
	}
	if err := t.decorateRequest(req); err != nil {
		return nil, err
	}
	key, err := secureMessagingTransactionKey(req)
	if err != nil {
		return nil, err
	}
	responses := make(chan *sip.Response, 1)
	t.mu.Lock()
	if _, exists := t.pending[key]; exists {
		t.mu.Unlock()
		return nil, fmt.Errorf("voiceclient: duplicate secure transaction %s", key)
	}
	t.pending[key] = responses
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		delete(t.pending, key)
		t.mu.Unlock()
	}()

	payload := []byte(req.String())
	t.writeMu.Lock()
	n, writeErr := t.conn.Write(payload)
	t.writeMu.Unlock()
	if writeErr != nil {
		return nil, writeErr
	}
	if n != len(payload) {
		return nil, fmt.Errorf("voiceclient: short secure SIP write (%d of %d bytes)", n, len(payload))
	}

	select {
	case response := <-responses:
		return response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.done:
		return nil, net.ErrClosed
	}
}

func (t *secureMessagingTransport) Close() error {
	if t == nil {
		return nil
	}
	var err error
	t.closeOnce.Do(func() {
		err = t.conn.Close()
		t.signalDone()
	})
	t.wg.Wait()
	return err
}

func (t *secureMessagingTransport) decorateRequest(req *sip.Request) error {
	localPort := t.client.cfg.localPort()
	if localPort <= 0 {
		return errors.New("voiceclient: secure local port unavailable")
	}
	req.RemoveHeader("Via")
	req.RemoveHeader("Max-Forwards")
	req.RemoveHeader("Call-ID")
	req.RemoveHeader("CSeq")
	viaHost := net.JoinHostPort(t.client.cfg.LocalIP.String(), fmt.Sprintf("%d", localPort))
	transport := strings.ToUpper(t.client.cfg.transportNetwork())
	viaValue := fmt.Sprintf("SIP/2.0/%s %s;branch=%s", transport, viaHost, sip.GenerateBranchN(16))
	if transport == "UDP" {
		viaValue += ";rport"
	}
	req.PrependHeader(sip.NewHeader("Via", viaValue))
	req.AppendHeader(sip.NewHeader("Max-Forwards", "70"))
	req.AppendHeader(sip.NewHeader("Call-ID", uuid.NewString()))
	req.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d %s", t.cseq.Add(1), req.Method)))
	if verify := strings.TrimSpace(t.client.cfg.SecurityVerify); verify != "" {
		req.RemoveHeader("Security-Verify")
		req.AppendHeader(sip.NewHeader("Security-Verify", verify))
		appendHeaderToken(req, "Require", "sec-agree")
		appendHeaderToken(req, "Proxy-Require", "sec-agree")
	}
	req.SetTransport(transport)
	req.SetDestination(t.client.cfg.PCSCFAddr)
	return nil
}

func appendHeaderToken(req *sip.Request, headerName, token string) {
	if req == nil {
		return
	}
	for _, header := range req.GetHeaders(headerName) {
		if header == nil {
			continue
		}
		for _, existing := range strings.Split(header.Value(), ",") {
			if strings.EqualFold(strings.TrimSpace(existing), token) {
				return
			}
		}
	}
	req.AppendHeader(sip.NewHeader(headerName, token))
}

func (t *secureMessagingTransport) readLoop() {
	defer t.wg.Done()
	defer t.signalDone()
	buf := make([]byte, 64*1024)
	for {
		var payload []byte
		if stream, ok := t.conn.(interface{ ReadSIPMessage() ([]byte, error) }); ok {
			message, err := stream.ReadSIPMessage()
			if err != nil {
				return
			}
			payload = message
		} else {
			n, err := t.conn.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			payload = append([]byte(nil), buf[:n]...)
		}
		message, err := sip.NewParser().ParseSIP(payload)
		if err != nil {
			continue
		}
		switch value := message.(type) {
		case *sip.Response:
			t.deliverResponse(value)
		case *sip.Request:
			t.respondToRequest(value)
		}
	}
}

func (t *secureMessagingTransport) deliverResponse(response *sip.Response) {
	key, err := secureMessagingTransactionKey(response)
	if err != nil {
		return
	}
	t.mu.Lock()
	responses := t.pending[key]
	t.mu.Unlock()
	if responses == nil {
		return
	}
	select {
	case responses <- response:
	default:
	}
}

func (t *secureMessagingTransport) respondToRequest(request *sip.Request) {
	var response *sip.Response
	var rpAck *smsRPAckTask
	if request.Method == sip.MESSAGE {
		response, rpAck = t.client.incomingMessageResult(request)
	} else {
		response = sip.NewResponseFromRequest(request, 501, "Not Implemented", nil)
	}
	payload := []byte(response.String())
	if writer, ok := t.conn.(interface{ WriteServerFlow([]byte) (int, error) }); ok {
		n, err := writer.WriteServerFlow(payload)
		if err == nil && n == len(payload) && rpAck != nil {
			t.enqueueRPAck(*rpAck)
		}
		return
	}
	t.writeMu.Lock()
	n, err := t.conn.Write(payload)
	t.writeMu.Unlock()
	if err == nil && n == len(payload) && rpAck != nil {
		t.enqueueRPAck(*rpAck)
	}
}

func (t *secureMessagingTransport) enqueueRPAck(task smsRPAckTask) {
	select {
	case <-t.done:
		t.client.logStatusReportRPAckResult("canceled")
	case t.rpAcks <- task:
	default:
		t.client.logStatusReportRPAckResult("queue_full")
	}
}

func (t *secureMessagingTransport) rpAckLoop() {
	defer t.wg.Done()
	for {
		select {
		case <-t.done:
			return
		case task := <-t.rpAcks:
			t.client.sendStatusReportRPAck(task)
		}
	}
}

func (t *secureMessagingTransport) signalDone() {
	t.doneOnce.Do(func() { close(t.done) })
}

func secureMessagingTransactionKey(message sip.Message) (string, error) {
	var callID sip.Header
	var cseq sip.Header
	switch value := message.(type) {
	case *sip.Request:
		callID = value.GetHeader("Call-ID")
		cseq = value.GetHeader("CSeq")
	case *sip.Response:
		callID = value.GetHeader("Call-ID")
		cseq = value.GetHeader("CSeq")
	default:
		return "", errors.New("voiceclient: unsupported secure SIP message")
	}
	if callID == nil || cseq == nil {
		return "", errors.New("voiceclient: secure SIP message missing transaction headers")
	}
	return strings.TrimSpace(callID.Value()) + "|" + strings.TrimSpace(cseq.Value()), nil
}
