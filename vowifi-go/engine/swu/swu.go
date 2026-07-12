// Package swu implements the SWu reference point (3GPP TS 23.402): the
// IKEv2/IPsec tunnel a UE establishes to an ePDG to carry IMS traffic over
// non-3GPP (WiFi/broadband) access.
//
// The control plane (IKE_SA_INIT, IKE_AUTH/EAP-AKA, CHILD_SA negotiation,
// rekey, MOBIKE) is delegated to strongSwan's charon daemon, driven entirely
// over its vici control socket — this package supervises that subprocess
// rather than reimplementing IKEv2. The data plane runs charon's
// kernel-libipsec plugin: ESP is encoded/decoded in userspace over a TUN
// device, so no kernel IPsec (XFRM) support is required on the host, which
// matters for the stripped-down kernels common on router targets.
//
// EAP-AKA needs RAND/AUTN -> RES/CK/IK computed live, mid-exchange, by
// whatever already talks to the SIM (here: sim.AKAProvider over APDU/QMI).
// strongSwan's built-in EAP-AKA card backends only support PC/SC readers or
// static test vectors, neither of which fits a SIM behind a QMI modem, so a
// small companion C plugin (not part of this Go module) bridges charon's
// simaka_card_t callback to this package's akabridge listener, which
// forwards the request to the AKAProvider passed in Config.
package swu

import (
	"context"
	"net"
	"time"

	swusim "github.com/1239t/vowifi-go/engine/sim"
)

const (
	// DataplaneModeUserspace runs ESP over charon's kernel-libipsec plugin
	// (userspace codec + TUN device). No kernel IPsec support required; the
	// default and generally the only mode worth using on router targets.
	DataplaneModeUserspace = "userspace"
	// DataplaneModeKernel installs the negotiated SAs into the Linux kernel's
	// XFRM subsystem via charon's kernel-netlink plugin. Only meaningful on
	// hosts with full kernel IPsec support and no conflicting global policy.
	DataplaneModeKernel = "kernel"
)

// Config is everything Dial needs to bring up one device's SWu tunnel.
type Config struct {
	DeviceID string

	// EPDGAddr is the ePDG FQDN or IP to dial (identity.PreparedSession.EPDGAddr).
	EPDGAddr string

	// Identity is the IKEv2 IDi: an ISIM IMPI when available, otherwise the
	// IMSI-derived root NAI (identity.PreparedSession.IMSIdentity).
	Identity string

	// AKA computes EAP-AKA quintuplets for Identity. Required: without it
	// there is nothing for the akabridge listener to forward requests to.
	AKA swusim.AKAProvider

	// CACerts trusts the ePDG's server certificate chain (the operator's own
	// CA, or a public one they use) -- found missing from the original
	// design during the vici spike: the network authenticates via pubkey,
	// never EAP/PSK, so without this the connection loads fine but fails
	// certificate validation against any real ePDG.
	//
	// Each entry is a file path to one or more PEM-encoded certificates
	// (e.g. an operator's CA bundle, or the system trust store); Dial reads
	// and splits them into individual certificates before loading, since
	// charon's vici interface only accepts one certificate per cacerts
	// entry (see cacerts.go's doc comment). DER isn't supported directly --
	// convert to PEM first.
	CACerts []string

	// DataplaneMode selects the ESP dataplane; empty defaults to
	// DataplaneModeUserspace. This is a daemon-wide charon setting (see
	// engine/swu/charon.Options.DataplaneMode) -- it's carried here so Dial
	// can assert consistency with however the shared charon instance was
	// actually started, not because it's a per-connection vici field.
	DataplaneMode string

	// EnableMOBIKE turns on IKEv2 MOBIKE (RFC 4555) so a local address change
	// (DHCP renewal, WiFi roam) reattaches the same IKE_SA instead of a full
	// re-auth. Surfaced to callers via Session.TriggerMOBIKE.
	EnableMOBIKE bool

	// InitiateTimeout bounds how long charon's own initiate command will
	// retry before giving up. Empty defaults to 30s. Found necessary by
	// actually running Dial against an unresponsive ePDG
	// (spike/managertest): without an explicit timeout, charon's default
	// retry behavior keeps the IKE_SA in CONNECTING indefinitely, so
	// Session.Events() never receives a definitive outcome and callers get
	// no failure signal at all.
	InitiateTimeout time.Duration
}

// SessionState is the lifecycle state of one SWu tunnel.
type SessionState string

const (
	SessionConnecting SessionState = "connecting"
	SessionUp         SessionState = "up"
	SessionRekeying   SessionState = "rekeying"
	SessionDown       SessionState = "down"
)

// Event reports a Session lifecycle transition.
type Event struct {
	DeviceID string
	State    SessionState
	LocalIP  net.IP
	// PCSCFAddr is the P-CSCF server address learned via the IKEv2
	// configuration payload (RFC 7651 P_CSCF_IP4_ADDRESS/P_CSCF_IP6_ADDRESS,
	// see pcscfbridge), if any arrived by the time this event was emitted.
	// nil means either it hasn't arrived yet or the ePDG didn't send one —
	// callers can't distinguish those from the event alone; Session.PCSCFAddr
	// reflects the latest known value regardless of event timing.
	PCSCFAddr net.IP
	Err       error
}

// Session is a live (or connecting) SWu tunnel for one device.
type Session interface {
	// LocalIP is the virtual address assigned by the ePDG via IKEv2
	// configuration payload (INTERNAL_IP4_ADDRESS/INTERNAL_IP6_ADDRESS).
	LocalIP() net.IP

	// PCSCFAddr is the P-CSCF server address learned via the IKEv2
	// configuration payload (RFC 7651), pushed by the p-cscf-vohive charon
	// plugin (see pcscfbridge). nil if the ePDG hasn't sent one yet, or
	// never does — some deployments expect the UE to already know its
	// P-CSCF address by other means (see runtimehost.StartRequest.PCSCFAddr
	// for the manual-override fallback).
	PCSCFAddr() net.IP

	// InterfaceName is the TUN device carrying decrypted tunnel traffic --
	// "ipsec0" under kernel-libipsec. Diagnostic only: kernel-libipsec
	// creates exactly one such device for the whole charon daemon (at
	// plugin load, confirmed in its log), shared by every concurrent
	// device's tunnel. It does NOT identify this Session the way a modem's
	// own NIC does for vohive's proxy engine -- callers must bind SIP/RTP
	// sockets to LocalIP(), not SO_BINDTODEVICE(InterfaceName()), to
	// disambiguate between concurrent sessions.
	InterfaceName() string

	// Events streams lifecycle transitions until the Session is closed, at
	// which point the channel is closed.
	Events() <-chan Event

	// TriggerMOBIKE requests an IKEv2 MOBIKE address update. Returns an error
	// immediately if the Session wasn't configured with EnableMOBIKE.
	TriggerMOBIKE(oldIP, newIP string) error

	Close(ctx context.Context) error
}

// Dial is a convenience wrapper around a lazily-started, package-level
// default Manager (started on first call, using DefaultManagerOptions()).
// It exists so runtimehost doesn't need its own lifecycle management for
// the one shared charon+akabridge instance every device's tunnel goes
// through -- see Manager for explicit lifecycle control (tests, or a caller
// that wants Start/Stop tied to its own process lifecycle instead).
func Dial(ctx context.Context, cfg Config) (Session, error) {
	m, err := defaultManager(ctx)
	if err != nil {
		return nil, err
	}
	return m.Dial(ctx, cfg)
}
