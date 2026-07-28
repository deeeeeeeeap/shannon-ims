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

	// ProtectedTransport is the operator's intent for the ipsec-3gpp protected
	// REGISTER only: "udp", "tcp", or "" / "auto" to derive it from the request
	// size.
	//
	// It is deliberately separate from the transport of the UNPROTECTED phase.
	// The unprotected transport is chosen per attempt by
	// registerTransportCandidates, and reusing that decision here would mean
	// re-sending the initial REGISTER to switch the protected one - abandoning the
	// session that already answered 401 and risking a second AKA vector, a second
	// CSeq and a different candidate.
	//
	// An explicit "tcp" expresses transport intent only. It is not permission to
	// register without a server flow: authorizeProtectedTCPActivation still
	// requires a ready port_us listener for the current SA generation.
	ProtectedTransport string

	Realm      string
	PrivateID  string
	PublicURI  string
	HomeDomain string
	IMSI       string
	SMSC       string

	AKA sim.AKAProvider

	CarrierBehavior policy.CarrierBehavior

	MCC    string
	MNC    string
	CellID string

	SIPInstanceURN string
	UserAgent      string

	RegisterExpirySeconds int

	DeliveryStore messaging.DeliveryStore
}
