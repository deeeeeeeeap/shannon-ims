package ipsec3gpp

import (
	"net"
	"testing"
)

// TestSecurityServerPortsMustNotBecomeUELocal: P-CSCF Security-Server ports
// (5090/5091) must be remote; UE Security-Client ports (5062/5063) must be local.
func TestSecurityServerPortsMustNotBecomeUELocal(t *testing.T) {
	ck := make([]byte, 16)
	ik := make([]byte, 16)
	for i := range ck {
		ck[i] = byte(i + 1)
		ik[i] = byte(0x80 + i)
	}

	pcscfMech := SecurityMechanism{
		Alg:   "hmac-sha-1-96",
		EAlg:  "aes-cbc",
		Prot:  "esp",
		Mode:  "trans",
		SPIc:  0x11110001,
		SPIs:  0x11110002,
		PortC: 5090,
		PortS: 5091,
	}

	pol, err := NewPolicy(PolicyInput{
		LocalIP:  net.ParseIP("10.0.0.2"),
		RemoteIP: net.ParseIP("10.0.0.3"),
		Mech:     pcscfMech,
		CK:       ck,
		IK:       ik,
		UEPortC:  5062,
		UEPortS:  5063,
		UESPIc:   0x00AA0001,
		UESPIs:   0x00AA0002,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	if pol.LocalPortC != 5062 || pol.LocalPortS != 5063 {
		t.Fatalf("UE local ports = %d/%d, want 5062/5063", pol.LocalPortC, pol.LocalPortS)
	}
	if pol.RemotePortC != 5090 || pol.RemotePortS != 5091 {
		t.Fatalf("P-CSCF remote ports = %d/%d, want 5090/5091", pol.RemotePortC, pol.RemotePortS)
	}
	if pol.FlowC.OutboundSPI != 0x11110002 {
		t.Fatalf("FlowC outbound SPI = %#x, want P-CSCF spi-s", pol.FlowC.OutboundSPI)
	}
	if pol.FlowC.InboundSPI != 0x00AA0001 {
		t.Fatalf("FlowC inbound SPI = %#x, want UE spi-c", pol.FlowC.InboundSPI)
	}
	if pol.FlowS.OutboundSPI != 0x11110001 {
		t.Fatalf("FlowS outbound SPI = %#x, want P-CSCF spi-c", pol.FlowS.OutboundSPI)
	}
	if pol.FlowS.InboundSPI != 0x00AA0002 {
		t.Fatalf("FlowS inbound SPI = %#x, want UE spi-s", pol.FlowS.InboundSPI)
	}
	if pol.FlowC.LocalPort != 5062 || pol.FlowC.RemotePort != 5091 {
		t.Fatalf(
			"FlowC ports = %d->%d, want UE port-c 5062 -> P-CSCF port-s 5091",
			pol.FlowC.LocalPort,
			pol.FlowC.RemotePort,
		)
	}
	if pol.FlowS.LocalPort != 5063 || pol.FlowS.RemotePort != 5090 {
		t.Fatalf(
			"FlowS ports = %d->%d, want UE port-s 5063 -> P-CSCF port-c 5090",
			pol.FlowS.LocalPort,
			pol.FlowS.RemotePort,
		)
	}
}

// TestLegacyFillPortsStillDocumentsOldHardcode keeps fillPorts() as the
// historical defective helper for regression documentation.
func TestLegacyFillPortsStillDocumentsOldHardcode(t *testing.T) {
	ports := fillPorts(SecurityMechanism{PortC: 5090, PortS: 5091})
	if ports.localC != 5090 || ports.remoteC != 5060 {
		t.Fatalf("legacy fillPorts changed unexpectedly: local=%d remote=%d", ports.localC, ports.remoteC)
	}
}
