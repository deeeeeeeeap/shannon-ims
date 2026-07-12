package imscore

import (
	"net"

	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

// Config configures the RE-based imscore IMS register + messaging service.
type Config struct {
	DeviceID string
	TraceID  string

	LocalIP   net.IP
	Dataplane voiceclient.PacketDataplane
	PCSCFAddr string
	// TransportPCSCFAddr overrides the TCP destination for REGISTER when the
	// logical registrar (PCSCFAddr) is the UE inner IPv6 and userspace netstack
	// cannot hairpin to itself.
	TransportPCSCFAddr string
	// RegistrarCandidates is the ordered IKE/ePDG P-CSCF list used for initial
	// REGISTER probing when the first node returns a location/forbidden reject.
	RegistrarCandidates []string

	Realm      string
	PrivateID  string
	PublicURI  string
	HomeDomain string
	IMSI       string
	SMSC       string

	AKA sim.AKAProvider

	Template policy.IMSRegisterTemplate

	MCC    string
	MNC    string
	CellID string

	SIPInstanceURN string
	UserAgent      string

	RegisterExpirySeconds int

	DeliveryStore messaging.DeliveryStore
}
