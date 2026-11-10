package runtimehost

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// A minimal DNS stub codec (RFC 1035) for the A and AAAA lookups of an ePDG
// host name. The system resolver cannot send its queries through a proxy's
// UDP relay and this module carries no DNS library, so the two message
// shapes that are needed are handled here: one question out, address
// records back.

const (
	dnsTypeA    uint16 = 1
	dnsTypeAAAA uint16 = 28
	dnsTypeOPT  uint16 = 41
	dnsClassIN  uint16 = 1

	dnsHeaderLen   = 12
	dnsMaxNameLen  = 253
	dnsMaxLabelLen = 63
	// dnsUDPPayloadSize is announced through EDNS(0) so that a reply with
	// many addresses is not cut off at 512 bytes. 1232 is the size that
	// passes any path without IP fragmentation.
	dnsUDPPayloadSize uint16 = 1232
	// dnsMaxPointerHops bounds the compression pointers followed in one name.
	dnsMaxPointerHops = 16

	dnsFlagResponse         uint16 = 0x8000
	dnsFlagTruncated        uint16 = 0x0200
	dnsFlagRecursionDesired uint16 = 0x0100
	dnsOpcodeMask           uint16 = 0x7800
	dnsRCodeMask            uint16 = 0x000f
)

var (
	// errDNSNotOurs marks a datagram that is not the reply to the query at
	// hand: another transaction, another question, or no reply at all. The
	// caller keeps waiting for the real one.
	errDNSNotOurs = errors.New("dns: not the reply to this query")
	// errDNSMalformed marks a reply to the query that cannot be read.
	errDNSMalformed = errors.New("dns: malformed reply")
)

// dnsRCodeError is a reply in which the server reports a failure, such as
// 2 (server failure), 3 (no such name) or 5 (refused).
type dnsRCodeError struct{ code int }

func (e *dnsRCodeError) Error() string {
	return fmt.Sprintf("dns: server answered with rcode %d", e.code)
}

// canonicalDNSName validates host as a name that can be asked for and
// returns it without the trailing dot. Only letters, digits, '-' and '_'
// are accepted in labels, which covers every ePDG name and keeps anything
// unexpected out of the query.
func canonicalDNSName(host string) (string, error) {
	name := strings.TrimSuffix(strings.TrimSpace(host), ".")
	if name == "" || len(name) > dnsMaxNameLen {
		return "", fmt.Errorf("dns: host name length %d is out of range", len(name))
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > dnsMaxLabelLen {
			return "", errors.New("dns: host name has an empty or oversized label")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
			digit := c >= '0' && c <= '9'
			if !letter && !digit && c != '-' && c != '_' {
				return "", errors.New("dns: host name has a character other than letters, digits, '-' and '_'")
			}
		}
	}
	return name, nil
}

// encodeDNSQuery builds a recursive query for one record type of host.
func encodeDNSQuery(id uint16, host string, qtype uint16) ([]byte, error) {
	name, err := canonicalDNSName(host)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, dnsHeaderLen, dnsHeaderLen+len(name)+2+4+11)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], dnsFlagRecursionDesired)
	binary.BigEndian.PutUint16(msg[4:], 1)  // one question
	binary.BigEndian.PutUint16(msg[10:], 1) // one additional record: OPT
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	// OPT pseudo-record (RFC 6891): root name, type, the payload size in the
	// class field, no extended flags, no options.
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeOPT)
	msg = binary.BigEndian.AppendUint16(msg, dnsUDPPayloadSize)
	msg = append(msg, 0, 0, 0, 0, 0, 0)
	return msg, nil
}

// parseDNSReply checks that msg is the reply to the query (id, host, qtype)
// and returns the addresses of that type from its answer section.
//
// The result is errDNSNotOurs when msg belongs to something else, a
// *dnsRCodeError when the server reports a failure, and errDNSMalformed when
// the reply cannot be read. A reply without records of the wanted type
// yields no addresses and no error. Records are taken from the whole answer
// section, so the addresses at the end of a CNAME chain are found; addresses
// no ePDG can have are left out.
func parseDNSReply(msg []byte, id uint16, host string, qtype uint16) ([]net.IP, error) {
	want, err := canonicalDNSName(host)
	if err != nil {
		return nil, err
	}
	if len(msg) < dnsHeaderLen || binary.BigEndian.Uint16(msg[0:]) != id {
		return nil, errDNSNotOurs
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&dnsFlagResponse == 0 || flags&dnsOpcodeMask != 0 {
		return nil, errDNSNotOurs
	}
	if binary.BigEndian.Uint16(msg[4:]) != 1 {
		return nil, errDNSNotOurs
	}
	question, off, err := readDNSName(msg, dnsHeaderLen)
	if err != nil || off+4 > len(msg) {
		return nil, errDNSNotOurs
	}
	if !strings.EqualFold(question, want) ||
		binary.BigEndian.Uint16(msg[off:]) != qtype ||
		binary.BigEndian.Uint16(msg[off+2:]) != dnsClassIN {
		return nil, errDNSNotOurs
	}
	off += 4

	if rcode := int(flags & dnsRCodeMask); rcode != 0 {
		return nil, &dnsRCodeError{code: rcode}
	}

	answers := int(binary.BigEndian.Uint16(msg[6:]))
	truncated := flags&dnsFlagTruncated != 0
	var ips []net.IP
	for i := 0; i < answers; i++ {
		next, rtype, class, rdata, err := readDNSRecord(msg, off)
		if err != nil {
			if truncated {
				// A truncated reply ends inside a record; the records that
				// were complete before it are still valid.
				break
			}
			return nil, err
		}
		off = next
		if class != dnsClassIN || rtype != qtype {
			continue
		}
		wantLen := net.IPv4len
		if qtype == dnsTypeAAAA {
			wantLen = net.IPv6len
		}
		if len(rdata) != wantLen {
			return nil, errDNSMalformed
		}
		if ip := append(net.IP(nil), rdata...); usableEPDGAddress(ip) {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// readDNSRecord reads the resource record at off and returns the offset of
// the one after it.
func readDNSRecord(msg []byte, off int) (next int, rtype, class uint16, rdata []byte, err error) {
	_, off, err = readDNSName(msg, off)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	// type(2) class(2) ttl(4) rdlength(2)
	if off+10 > len(msg) {
		return 0, 0, 0, nil, errDNSMalformed
	}
	rtype = binary.BigEndian.Uint16(msg[off:])
	class = binary.BigEndian.Uint16(msg[off+2:])
	rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
	off += 10
	if off+rdlen > len(msg) {
		return 0, 0, 0, nil, errDNSMalformed
	}
	return off + rdlen, rtype, class, msg[off : off+rdlen], nil
}

// readDNSName reads the possibly compressed name at off and returns it in
// dotted form together with the offset after it. Pointers may only point
// backwards and only a bounded number of them is followed, so no message
// can make this loop.
func readDNSName(msg []byte, off int) (name string, next int, err error) {
	var out []byte
	next = -1
	hops := 0
	for {
		if off < 0 || off >= len(msg) {
			return "", 0, errDNSMalformed
		}
		c := int(msg[off])
		switch c & 0xc0 {
		case 0x00:
			off++
			if c == 0 {
				if next < 0 {
					next = off
				}
				return string(out), next, nil
			}
			if off+c > len(msg) {
				return "", 0, errDNSMalformed
			}
			if len(out) > 0 {
				out = append(out, '.')
			}
			out = append(out, msg[off:off+c]...)
			if len(out) > dnsMaxNameLen {
				return "", 0, errDNSMalformed
			}
			off += c
		case 0xc0:
			if off+1 >= len(msg) {
				return "", 0, errDNSMalformed
			}
			target := (c&0x3f)<<8 | int(msg[off+1])
			if next < 0 {
				next = off + 2
			}
			hops++
			if hops > dnsMaxPointerHops || target >= off {
				return "", 0, errDNSMalformed
			}
			off = target
		default:
			// Label types 0x40 and 0x80 are not in use.
			return "", 0, errDNSMalformed
		}
	}
}

// usableEPDGAddress reports whether ip can be the address of an ePDG. It
// keeps a broken or hostile reply from pointing a tunnel at this host or
// at a neighbour on the link.
func usableEPDGAddress(ip net.IP) bool {
	return !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() &&
		!ip.IsLinkLocalUnicast() && !ip.Equal(net.IPv4bcast)
}
