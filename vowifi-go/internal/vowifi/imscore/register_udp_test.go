package imscore

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

type recordingIMSNetwork struct {
	network   string
	addr      net.Addr
	transport string
	peer      net.Conn
}

func (n *recordingIMSNetwork) DialContext(_ context.Context, network string, addr net.Addr, transport string, _ DialOptions) (net.Conn, error) {
	n.network = network
	n.addr = addr
	n.transport = transport
	conn, peer := net.Pipe()
	n.peer = peer
	return conn, nil
}

func (*recordingIMSNetwork) HasLocalIP([]byte) bool { return false }
func (*recordingIMSNetwork) ListenPacket(context.Context, string, net.Addr) (net.PacketConn, error) {
	return nil, nil
}
func (*recordingIMSNetwork) ListenTCP(context.Context, *net.TCPAddr) (net.Listener, error) {
	return nil, nil
}
func (*recordingIMSNetwork) LocalIP() []byte { return nil }
func (*recordingIMSNetwork) ResolveIP(context.Context, string, bool) ([]byte, error) {
	return nil, nil
}

func TestVodafoneUKAutoRegisterTransportPrefersUDPThenTCP(t *testing.T) {
	cfg := Config{Template: policy.VodafoneUKTemplate()}
	want := []string{"udp", "tcp"}

	if got := registerTransportCandidates(cfg, "auto"); !reflect.DeepEqual(got, want) {
		t.Fatalf("register transports = %v, want %v", got, want)
	}
}

func TestUDPRegisterUsesSessionPortInViaAndContact(t *testing.T) {
	cfg := Config{
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
	session := newRegisterSession(cfg, nil, nil, "udp", 1)
	session.localPort = 41234

	req, err := buildRegisterRequest(cfg, *session.state, true, initialRegisterVariant{})
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}
	if err := session.decorateRegisterRequest(req); err != nil {
		t.Fatalf("decorateRegisterRequest: %v", err)
	}

	if got := req.Transport(); got != "UDP" {
		t.Fatalf("request transport = %q, want UDP", got)
	}
	via := req.GetHeader("Via")
	if via == nil || !strings.HasPrefix(via.Value(), "SIP/2.0/UDP 10.0.0.2:41234;") {
		t.Fatalf("Via = %v, want UDP with session port", via)
	}
	if !strings.Contains(via.Value(), ";rport") {
		t.Fatalf("Via = %v, want rport", via)
	}
	contact := req.GetHeader("Contact")
	if contact == nil || !strings.Contains(contact.Value(), "@10.0.0.2:41234;transport=udp") {
		t.Fatalf("Contact = %v, want UDP with session port", contact)
	}
	contentLength := req.GetHeader("Content-Length")
	if contentLength == nil || strings.TrimSpace(contentLength.Value()) != "0" {
		t.Fatalf("Content-Length = %v, want 0", contentLength)
	}
}

func TestUDPRegisterDialsUDPAddress(t *testing.T) {
	cfg := Config{
		LocalIP:            net.ParseIP("10.0.0.2"),
		PCSCFAddr:          "10.0.0.3:5060",
		TransportPCSCFAddr: "10.0.0.4:5060",
		Template:           policy.VodafoneUKTemplate(),
	}
	network := &recordingIMSNetwork{}
	session := newRegisterSession(cfg, nil, network, "udp", 0)

	conn, err := session.dialRegisterConn(context.Background())
	if err != nil {
		t.Fatalf("dialRegisterConn: %v", err)
	}
	defer conn.Close()
	if network.peer != nil {
		defer network.peer.Close()
	}

	if network.network != "udp" || network.transport != "udp" {
		t.Fatalf("dial network/transport = %q/%q, want udp/udp", network.network, network.transport)
	}
	addr, ok := network.addr.(*net.UDPAddr)
	if !ok || addr.Port != 5060 || !addr.IP.Equal(net.ParseIP("10.0.0.4")) {
		t.Fatalf("dial addr = %#v, want UDP 10.0.0.4:5060", network.addr)
	}
}
