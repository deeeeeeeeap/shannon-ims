package swu

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
)

func (s *Session) selectOutgoingSA(packet []byte) *ipsec.SecurityAssociation {
	if len(s.childOutPolicies) == 0 || s.ChildSAOut == nil {
		return s.ChildSAOut
	}

	dstIP, proto, dstPort, ok := extractDstTuple(packet)
	if !ok {
		return s.ChildSAOut
	}

	for _, pol := range s.childOutPolicies {
		if pol.saOut == nil {
			continue
		}
		if matchSelectors(dstIP, proto, dstPort, pol.tsr) {
			return pol.saOut
		}
	}

	return s.ChildSAOut
}

func matchSelectors(dstIP net.IP, proto uint8, dstPort uint16, selectors []*ikev2.TrafficSelector) bool {
	for _, ts := range selectors {
		if ts == nil {
			continue
		}

		if ts.IPProtocol != 0 && ts.IPProtocol != proto {
			continue
		}

		if ts.IPProtocol == 6 || ts.IPProtocol == 17 {
			if dstPort < ts.StartPort || dstPort > ts.EndPort {
				continue
			}
		}

		switch ts.TSType {
		case ikev2.TS_IPV4_ADDR_RANGE:
			ip4 := dstIP.To4()
			if ip4 == nil || len(ts.StartAddr) != 4 || len(ts.EndAddr) != 4 {
				continue
			}
			d := binary.BigEndian.Uint32(ip4)
			su := binary.BigEndian.Uint32(ts.StartAddr)
			eu := binary.BigEndian.Uint32(ts.EndAddr)
			if d >= su && d <= eu {
				return true
			}
		case ikev2.TS_IPV6_ADDR_RANGE:
			ip6 := dstIP.To16()
			if ip6 == nil || len(ts.StartAddr) != 16 || len(ts.EndAddr) != 16 {
				continue
			}
			if bytes.Compare(ip6, ts.StartAddr) >= 0 && bytes.Compare(ip6, ts.EndAddr) <= 0 {
				return true
			}
		}
	}
	return false
}

func extractDstTuple(packet []byte) (dstIP net.IP, proto uint8, dstPort uint16, ok bool) {
	if len(packet) < 1 {
		return nil, 0, 0, false
	}
	ver := packet[0] >> 4
	switch ver {
	case 4:
		if len(packet) < 20 {
			return nil, 0, 0, false
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return nil, 0, 0, false
		}
		proto = packet[9]
		dstIP = net.IP(packet[16:20]).To4()
		l4 := packet[ihl:]
		if (proto == 6 || proto == 17) && len(l4) >= 4 {
			dstPort = binary.BigEndian.Uint16(l4[2:4])
		}
		return dstIP, proto, dstPort, true
	case 6:
		if len(packet) < 40 {
			return nil, 0, 0, false
		}
		proto = packet[6]
		dstIP = net.IP(packet[24:40]).To16()
		l4 := packet[40:]
		if (proto == 6 || proto == 17) && len(l4) >= 4 {
			dstPort = binary.BigEndian.Uint16(l4[2:4])
		}
		return dstIP, proto, dstPort, true
	default:
		return nil, 0, 0, false
	}
}
