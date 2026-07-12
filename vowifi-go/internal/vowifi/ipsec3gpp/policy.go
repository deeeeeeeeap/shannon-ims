package ipsec3gpp

import (
	"errors"
	"fmt"
	"net"
)

// Flow describes one direction of a 3GPP ipsec-3gpp security association.
type Flow struct {
	OutboundSPI uint32
	InboundSPI  uint32
	LocalPort   int
	RemotePort  int
	AuthAlg     string
	EncAlg      string
	CK          []byte
	IK          []byte
}

// Policy captures the negotiated ipsec-3gpp parameters for SIP-over-TCP ESP.
type Policy struct {
	LocalIP     []byte
	RemoteIP    []byte
	LocalPortC  int
	LocalPortS  int
	RemotePortC int
	RemotePortS int
	FlowC       Flow
	FlowS       Flow
}

// ReplayStats tracks anti-replay decisions.
type ReplayStats struct {
	Accepted  uint64
	Duplicate uint64
	TooOld    uint64
}

// TransportStats aggregates userspace ESP transform counters.
type TransportStats struct {
	OutboundPackets    uint64
	InboundPackets     uint64
	PassthroughPackets uint64
	TransformErrors    uint64
	Replay             ReplayStats
}

// PolicyInput is the minimum set of inputs required to build a Policy.
// Mech carries the selected Security-Server offer (P-CSCF ports/SPIs).
// UEPortC/UEPortS and UESPIc/UESPIs are the UE Security-Client values.
type PolicyInput struct {
	LocalIP  net.IP
	RemoteIP net.IP
	Mech     SecurityMechanism
	CK       []byte
	IK       []byte
	AuthAlg  string
	EncAlg   string
	// UE protected ports from Security-Client (defaults 5062/5063 if zero when remote is set).
	UEPortC int
	UEPortS int
	// UE SPIs from Security-Client; if zero, SPI direction uses Mech only (legacy).
	UESPIc uint32
	UESPIs uint32
}

// NewPolicy builds a Policy from negotiated Security-Server parameters, UE client
// ports/SPIs, and AKA keys.
//
// Mapping (UE perspective, 3GPP TS 33.203 / 24.229 practice):
//   - LocalPortC/S  = UE Security-Client port-c/port-s
//   - RemotePortC/S = P-CSCF Security-Server port-c/port-s (Mech.PortC/S)
//   - FlowC: UE client -> P-CSCF server uses P-CSCF spi-s; reverse uses UE spi-c
//   - FlowS: UE server -> P-CSCF client uses P-CSCF spi-c; reverse uses UE spi-s
func NewPolicy(in PolicyInput) (Policy, error) {
	localIP, err := normalizeIP(in.LocalIP)
	if err != nil {
		return Policy{}, fmt.Errorf("ipsec3gpp: local IP %w", err)
	}
	remoteIP, err := normalizeIP(in.RemoteIP)
	if err != nil {
		return Policy{}, fmt.Errorf("ipsec3gpp: remote IP %w", err)
	}
	if len(in.CK) == 0 || len(in.IK) == 0 {
		return Policy{}, errors.New("ipsec3gpp: CK and IK are required")
	}

	authAlg := canonicalAuthAlg(coalesce(in.AuthAlg, in.Mech.Alg))
	encAlg := canonicalEncAlg(coalesce(in.EncAlg, in.Mech.EAlg))
	if authAlg == "" || encAlg == "" {
		return Policy{}, errors.New("ipsec3gpp: authentication and encryption algorithms are required")
	}
	if in.Mech.SPIc == 0 || in.Mech.SPIs == 0 {
		return Policy{}, errors.New("ipsec3gpp: spi-c and spi-s are required")
	}

	ports := fillPortsFromInput(in)
	ck := append([]byte(nil), in.CK...)
	ik := append([]byte(nil), in.IK...)

	ueSPIc, ueSPIs := in.UESPIc, in.UESPIs
	if ueSPIc == 0 {
		ueSPIc = in.Mech.SPIc
	}
	if ueSPIs == 0 {
		ueSPIs = in.Mech.SPIs
	}

	flowC := Flow{
		OutboundSPI: in.Mech.SPIs,
		InboundSPI:  ueSPIc,
		LocalPort:   ports.localC,
		RemotePort:  ports.remoteS,
		AuthAlg:     authAlg,
		EncAlg:      encAlg,
		CK:          ck,
		IK:          ik,
	}
	flowS := Flow{
		OutboundSPI: in.Mech.SPIc,
		InboundSPI:  ueSPIs,
		LocalPort:   ports.localS,
		RemotePort:  ports.remoteC,
		AuthAlg:     authAlg,
		EncAlg:      encAlg,
		CK:          ck,
		IK:          ik,
	}

	return Policy{
		LocalIP:     localIP,
		RemoteIP:    remoteIP,
		LocalPortC:  ports.localC,
		LocalPortS:  ports.localS,
		RemotePortC: ports.remoteC,
		RemotePortS: ports.remoteS,
		FlowC:       flowC,
		FlowS:       flowS,
	}, nil
}

type portPair struct {
	localC, localS, remoteC, remoteS int
}

// fillPorts is retained for tests that document the old defect; prefer fillPortsFromInput.
func fillPorts(mech SecurityMechanism) portPair {
	// Legacy (defective) mapping: treat Mech ports as local, remote hardcoded 5060.
	localC, localS := mech.PortC, mech.PortS
	remoteC, remoteS := 5060, 5060
	if localC == 0 {
		localC = 5060
	}
	if localS == 0 {
		localS = localC
	}
	return portPair{
		localC:  localC,
		localS:  localS,
		remoteC: remoteC,
		remoteS: remoteS,
	}
}

// fillPortsFromInput maps UE Security-Client ports to local and Security-Server
// (Mech) ports to remote.
func fillPortsFromInput(in PolicyInput) portPair {
	localC, localS := in.UEPortC, in.UEPortS
	remoteC, remoteS := in.Mech.PortC, in.Mech.PortS
	if localC == 0 {
		localC = 5062
	}
	if localS == 0 {
		localS = 5063
	}
	if remoteC == 0 {
		remoteC = 5060
	}
	if remoteS == 0 {
		remoteS = 5060
	}
	return portPair{
		localC:  localC,
		localS:  localS,
		remoteC: remoteC,
		remoteS: remoteS,
	}
}

func normalizeIP(ip net.IP) ([]byte, error) {
	if ip == nil {
		return nil, errors.New("must not be nil")
	}
	if v4 := ip.To4(); v4 != nil {
		return append([]byte(nil), v4...), nil
	}
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
		return append([]byte(nil), v6...), nil
	}
	return nil, fmt.Errorf("invalid address %q", ip.String())
}

func normalizeIPPair(a, b []byte) (local, remote []byte, err error) {
	if len(a) == 0 || len(b) == 0 {
		return nil, nil, errors.New("ipsec3gpp: local/remote IP must not be nil")
	}
	if (len(a) == 4) != (len(b) == 4) {
		return nil, nil, errors.New("ipsec3gpp: local/remote IP family mismatch")
	}
	return append([]byte(nil), a...), append([]byte(nil), b...), nil
}

func coalesce(values ...string) string {
	for _, v := range values {
		if s := trimToken(v); s != "" {
			return s
		}
	}
	return ""
}

func ipEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
