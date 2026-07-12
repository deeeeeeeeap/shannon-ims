package voiceclient

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

func TestAttachSecureMessagingClearsInheritedDeadlineAndSendsMESSAGE(t *testing.T) {
	const securityVerify = "ipsec-3gpp;alg=hmac-md5-96;ealg=aes-cbc;spi-c=1;spi-s=2;port-c=5062;port-s=5063"
	const serviceCentreURI = "sip:+15550102030@ims.example.invalid;user=phone"
	serviceRoutes := []string{
		"<sip:pcscf.ims.example.invalid;lr>",
		"<sip:orig@scscf.ims.example.invalid;lr>",
	}
	clientPolicy := secureMessagingTestPolicy(t)
	serverPolicy := reverseSecureMessagingTestPolicy(clientPolicy)
	clientTransport, err := ipsec3gpp.NewTransport(clientPolicy)
	if err != nil {
		t.Fatalf("NewTransport(client): %v", err)
	}
	serverTransport, err := ipsec3gpp.NewTransport(serverPolicy)
	if err != nil {
		t.Fatalf("NewTransport(server): %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	clientSecure := ipsec3gpp.WrapSecureChannelUDP(clientRaw, clientTransport, clientPolicy)
	serverSecure := ipsec3gpp.WrapSecureChannelUDP(serverRaw, serverTransport, serverPolicy)
	defer serverSecure.Close()
	if err := clientSecure.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("seed inherited REGISTER deadline: %v", err)
	}

	serverDone := make(chan error, 1)
	go func() {
		request, err := readSecureMessagingTestRequest(bufio.NewReader(serverSecure))
		if err != nil {
			serverDone <- err
			return
		}
		if request.Method != sip.MESSAGE {
			serverDone <- fmt.Errorf("method = %s, want MESSAGE", request.Method)
			return
		}
		via := request.GetHeader("Via")
		if via == nil || !strings.Contains(strings.ToUpper(via.Value()), "SIP/2.0/UDP") {
			serverDone <- fmt.Errorf("Via = %v, want protected UDP", via)
			return
		}
		verify := request.GetHeader("Security-Verify")
		require := request.GetHeader("Require")
		proxyRequire := request.GetHeader("Proxy-Require")
		if verify == nil || strings.TrimSpace(verify.Value()) != securityVerify ||
			require == nil || !strings.Contains(strings.ToLower(require.Value()), "sec-agree") ||
			proxyRequire == nil || !strings.Contains(strings.ToLower(proxyRequire.Value()), "sec-agree") {
			response := sip.NewResponseFromRequest(request, 494, "Security Agreement Required", nil)
			_, writeErr := io.WriteString(serverSecure, response.String())
			if writeErr != nil {
				serverDone <- writeErr
			} else {
				serverDone <- fmt.Errorf("protected MESSAGE missing verified sec-agree headers")
			}
			return
		}
		to := request.GetHeader("To")
		preferredIdentity := request.GetHeader("P-Preferred-Identity")
		routes := request.GetHeaders("Route")
		routingOK := request.Recipient.String() == serviceCentreURI &&
			to != nil && strings.TrimSpace(to.Value()) == "<"+serviceCentreURI+">" &&
			preferredIdentity != nil && strings.TrimSpace(preferredIdentity.Value()) == "<sip:subscriber@ims.example.invalid>" &&
			len(routes) == len(serviceRoutes)
		if routingOK {
			for index, route := range routes {
				if route == nil || strings.TrimSpace(route.Value()) != serviceRoutes[index] {
					routingOK = false
					break
				}
			}
		}
		if !routingOK {
			response := sip.NewResponseFromRequest(request, 504, "Server Time-out", nil)
			_, writeErr := io.WriteString(serverSecure, response.String())
			if writeErr != nil {
				serverDone <- writeErr
			} else {
				serverDone <- fmt.Errorf("protected MESSAGE missing SC PSI or service route")
			}
			return
		}
		if !bytes.Equal(request.Body(), []byte{0x01, 0x02, 0x03}) {
			serverDone <- fmt.Errorf("MESSAGE body changed")
			return
		}
		response := sip.NewResponseFromRequest(request, 202, "Accepted", nil)
		_, err = io.WriteString(serverSecure, response.String())
		serverDone <- err
	}()

	store := &secureMessagingTestDeliveryStore{parts: make(chan secureMessagingTestPart, 1)}
	cfg := Config{
		DeviceID:        "test-device",
		LocalIP:         net.ParseIP("10.0.0.2"),
		LocalPort:       clientPolicy.FlowC.LocalPort,
		PCSCFAddr:       net.JoinHostPort("10.0.0.3", fmt.Sprintf("%d", clientPolicy.FlowC.RemotePort)),
		SecurityVerify:  securityVerify,
		SMSC:            "+15550102030",
		ServiceRoutes:   serviceRoutes,
		Realm:           "ims.example.invalid",
		PrivateID:       "subscriber@ims.example.invalid",
		PublicURI:       "sip:subscriber@ims.example.invalid",
		HomeDomain:      "ims.example.invalid",
		Transport:       "udp",
		SkipRegister:    true,
		DeliveryStore:   store,
		RegisterProfile: SimAdminGBEERegisterProfile(),
	}
	client, err := AttachSecureMessaging(context.Background(), cfg, clientSecure)
	if err != nil {
		t.Fatalf("AttachSecureMessaging: %v", err)
	}
	defer client.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := client.SendSMS(ctx, "sip:safe.invalid", "test", []messaging.SMSPart{{RPMR: 1, Body: []byte{0x01, 0x02, 0x03}}})
	if err != nil {
		t.Fatalf("SendSMS: %v", err)
	}
	if result.PartsTotal != 1 {
		t.Fatalf("PartsTotal = %d, want 1", result.PartsTotal)
	}
	select {
	case got := <-store.parts:
		if got.partNo != 1 {
			t.Fatalf("delivery part number = %d, want 1-based part number", got.partNo)
		}
	case <-time.After(time.Second):
		t.Fatal("delivery part was not stored")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestAttachSecureMessagingHandlesDeliveryReportOnFlowS(t *testing.T) {
	clientPolicy := secureMessagingTestPolicy(t)
	serverPolicy := reverseSecureMessagingTestPolicy(clientPolicy)
	clientTransport, err := ipsec3gpp.NewTransport(clientPolicy)
	if err != nil {
		t.Fatalf("NewTransport(client): %v", err)
	}
	serverTransport, err := ipsec3gpp.NewTransport(serverPolicy)
	if err != nil {
		t.Fatalf("NewTransport(server): %v", err)
	}
	clientRaw, serverRaw := net.Pipe()
	clientSecure := ipsec3gpp.WrapSecureChannelUDP(clientRaw, clientTransport, clientPolicy)
	serverSecure := ipsec3gpp.WrapSecureChannelUDP(serverRaw, serverTransport, serverPolicy)
	defer serverSecure.Close()

	store := &secureMessagingTestDeliveryStore{reports: make(chan secureMessagingTestReport, 1)}
	cfg := Config{
		DeviceID:        "test-device",
		LocalIP:         net.ParseIP("10.0.0.2"),
		LocalPort:       clientPolicy.FlowC.LocalPort,
		PCSCFAddr:       net.JoinHostPort("10.0.0.3", fmt.Sprintf("%d", clientPolicy.FlowC.RemotePort)),
		Realm:           "ims.example.invalid",
		PrivateID:       "subscriber@ims.example.invalid",
		PublicURI:       "sip:subscriber@ims.example.invalid",
		HomeDomain:      "ims.example.invalid",
		Transport:       "udp",
		SkipRegister:    true,
		DeliveryStore:   store,
		RegisterProfile: SimAdminGBEERegisterProfile(),
	}
	client, err := AttachSecureMessaging(context.Background(), cfg, clientSecure)
	if err != nil {
		t.Fatalf("AttachSecureMessaging: %v", err)
	}
	defer client.Close(context.Background())

	var recipient sip.Uri
	if err := sip.ParseUri("sip:subscriber@ims.example.invalid", &recipient); err != nil {
		t.Fatalf("ParseUri: %v", err)
	}
	report := sip.NewRequest(sip.MESSAGE, recipient)
	report.AppendHeader(sip.NewHeader("Via", "SIP/2.0/UDP 10.0.0.3:5090;branch=z9hG4bK-report;rport"))
	report.AppendHeader(sip.NewHeader("From", "<sip:network@ims.example.invalid>;tag=report"))
	report.AppendHeader(sip.NewHeader("To", "<sip:subscriber@ims.example.invalid>"))
	report.AppendHeader(sip.NewHeader("Call-ID", "delivery-report"))
	report.AppendHeader(sip.NewHeader("CSeq", "1 MESSAGE"))
	report.AppendHeader(sip.NewHeader("Content-Type", smsContentType))
	report.SetBody([]byte{0x03, 0x2a})

	writeDone := make(chan error, 1)
	go func() {
		_, err := serverSecure.WriteServerFlow([]byte(report.String()))
		writeDone <- err
	}()
	if err := serverSecure.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := serverSecure.Read(buf)
	if err != nil {
		t.Fatalf("read delivery response: %v", err)
	}
	message, err := sip.NewParser().ParseSIP(buf[:n])
	if err != nil {
		t.Fatalf("parse delivery response: %v", err)
	}
	response, ok := message.(*sip.Response)
	if !ok || response.StatusCode != sip.StatusOK {
		t.Fatalf("delivery response = %T status=%v, want 200", message, response)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write delivery report: %v", err)
	}
	select {
	case got := <-store.reports:
		if got.rpMR != 0x2a || got.state != "acked" {
			t.Fatalf("delivery report = %+v, want RP-MR 42 acked", got)
		}
	case <-time.After(time.Second):
		t.Fatal("delivery report was not recorded")
	}
}

type secureMessagingTestReport struct {
	rpMR  int
	state string
}

type secureMessagingTestPart struct {
	partNo int
}

type secureMessagingTestDeliveryStore struct {
	reports chan secureMessagingTestReport
	parts   chan secureMessagingTestPart
}

func (*secureMessagingTestDeliveryStore) CreateSMSDelivery(string, string, string, string, string, int, time.Time) error {
	return nil
}

func (s *secureMessagingTestDeliveryStore) UpsertSMSDeliveryPart(_ string, partNo int, _ string, _ int, _ string, _ time.Time) error {
	if s.parts != nil {
		s.parts <- secureMessagingTestPart{partNo: partNo}
	}
	return nil
}

func (s *secureMessagingTestDeliveryStore) MarkSMSDeliveryPartReport(_ string, _ string, _ string, rpMR int, state string, _ int, _ int, _ string, _ time.Time) (messaging.DeliveryPartMatch, error) {
	s.reports <- secureMessagingTestReport{rpMR: rpMR, state: state}
	return messaging.DeliveryPartMatch{}, nil
}

func (*secureMessagingTestDeliveryStore) RecomputeSMSDelivery(string, time.Time) error { return nil }
func (*secureMessagingTestDeliveryStore) UpdateSMSDeliveryState(string, string, string, int, time.Time) error {
	return nil
}
func (*secureMessagingTestDeliveryStore) GetSMSDeliveryStatus(string) (*messaging.DeliveryStatus, error) {
	return nil, messaging.ErrDeliveryNotFound
}

func readSecureMessagingTestRequest(reader *bufio.Reader) (*sip.Request, error) {
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
	contentLength := 0
	for _, line := range strings.Split(raw.String(), "\r\n") {
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			fmt.Sscanf(strings.TrimSpace(value), "%d", &contentLength)
		}
	}
	if contentLength > 0 {
		body := make([]byte, contentLength)
		if _, err := io.ReadFull(reader, body); err != nil {
			return nil, err
		}
		raw.Write(body)
	}
	message, err := sip.NewParser().ParseSIP([]byte(raw.String()))
	if err != nil {
		return nil, err
	}
	request, ok := message.(*sip.Request)
	if !ok {
		return nil, fmt.Errorf("parsed %T, want request", message)
	}
	return request, nil
}

func secureMessagingTestPolicy(t *testing.T) ipsec3gpp.Policy {
	t.Helper()
	policy, err := ipsec3gpp.NewPolicy(ipsec3gpp.PolicyInput{
		LocalIP:  net.ParseIP("10.0.0.2"),
		RemoteIP: net.ParseIP("10.0.0.3"),
		CK:       bytes.Repeat([]byte{0x11}, 16),
		IK:       bytes.Repeat([]byte{0x22}, 16),
		Mech: ipsec3gpp.SecurityMechanism{
			Alg:   "hmac-sha-1-96",
			EAlg:  "aes-cbc",
			Prot:  "esp",
			Mode:  "trans",
			SPIc:  100,
			SPIs:  101,
			PortC: 5090,
			PortS: 5091,
		},
		UEPortC: 5062,
		UEPortS: 5063,
		UESPIc:  200,
		UESPIs:  201,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return policy
}

func reverseSecureMessagingTestPolicy(client ipsec3gpp.Policy) ipsec3gpp.Policy {
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
