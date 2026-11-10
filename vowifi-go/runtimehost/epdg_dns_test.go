package runtimehost

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

const testEPDGHost = "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org"

const dnsTypeCNAME uint16 = 5

// dnsTestReply describes the reply a simulated resolver gives to a query.
type dnsTestReply struct {
	rcode     int
	cnames    []string // alias chain placed before the addresses
	ips       []net.IP // addresses of the family that was asked for
	rawRData  [][]byte // extra records of the queried type with this exact data
	truncated bool     // set the TC flag
	idOffset  uint16   // added to the transaction id: a reply to some other query
	chop      int      // bytes cut off the end
}

// buildDNSTestReply answers query the way a recursive resolver does: the
// question is repeated, the aliases come first and every owner name is a
// compression pointer. It returns nil for a query it cannot read.
func buildDNSTestReply(query []byte, reply dnsTestReply) []byte {
	if len(query) < dnsHeaderLen {
		return nil
	}
	_, questionEnd, err := readDNSName(query, dnsHeaderLen)
	if err != nil || questionEnd+4 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[questionEnd:])

	msg := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(msg[0:], binary.BigEndian.Uint16(query[0:])+reply.idOffset)
	flags := dnsFlagResponse | dnsFlagRecursionDesired | 0x0080 | uint16(reply.rcode)
	if reply.truncated {
		flags |= dnsFlagTruncated
	}
	binary.BigEndian.PutUint16(msg[2:], flags)
	binary.BigEndian.PutUint16(msg[4:], 1)
	msg = append(msg, query[dnsHeaderLen:questionEnd+4]...)

	answers := 0
	owner := []byte{0xc0, dnsHeaderLen}
	record := func(rtype uint16, rdata []byte) {
		msg = append(msg, owner...)
		msg = binary.BigEndian.AppendUint16(msg, rtype)
		msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
		msg = binary.BigEndian.AppendUint32(msg, 60)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
		msg = append(msg, rdata...)
		answers++
	}
	for _, cname := range reply.cnames {
		var target []byte
		for _, label := range strings.Split(cname, ".") {
			target = append(target, byte(len(label)))
			target = append(target, label...)
		}
		target = append(target, 0)
		record(dnsTypeCNAME, target)
		targetOffset := len(msg) - len(target)
		owner = []byte{0xc0 | byte(targetOffset>>8), byte(targetOffset)}
	}
	for _, ip := range reply.ips {
		rdata := []byte(ip.To4())
		if qtype == dnsTypeAAAA {
			rdata = []byte(ip.To16())
		}
		record(qtype, rdata)
	}
	for _, rdata := range reply.rawRData {
		record(qtype, rdata)
	}
	binary.BigEndian.PutUint16(msg[6:], uint16(answers))
	if reply.chop > 0 && reply.chop < len(msg) {
		msg = msg[:len(msg)-reply.chop]
	}
	return msg
}

func mustDNSQuery(t *testing.T, id uint16, host string, qtype uint16) []byte {
	t.Helper()
	query, err := encodeDNSQuery(id, host, qtype)
	if err != nil {
		t.Fatalf("encodeDNSQuery(%q) error = %v", host, err)
	}
	return query
}

func testIPs(addrs ...string) []net.IP {
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, net.ParseIP(addr))
	}
	return ips
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func TestEncodeDNSQuery(t *testing.T) {
	got, err := encodeDNSQuery(0x1234, "epdg.example.org.", dnsTypeAAAA)
	if err != nil {
		t.Fatalf("encodeDNSQuery() error = %v", err)
	}
	want := []byte{
		0x12, 0x34, // id
		0x01, 0x00, // recursion desired
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // one question, one additional record
		4, 'e', 'p', 'd', 'g', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'o', 'r', 'g', 0,
		0x00, 0x1c, 0x00, 0x01, // AAAA, IN
		0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // OPT, 1232 bytes
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encodeDNSQuery() =\n% x\nwant\n% x", got, want)
	}
}

func TestEncodeDNSQueryRejectsNamesThatCannotBeAsked(t *testing.T) {
	for _, host := range []string{
		"",
		".",
		"epdg..example.org",
		strings.Repeat("a", 64) + ".example.org",
		strings.Repeat("abcdefgh.", 32) + "org",
		"epdg example.org",
		"epdg.example.org/path",
		"\u00e9pdg.example.org",
	} {
		if query, err := encodeDNSQuery(1, host, dnsTypeA); err == nil {
			t.Errorf("encodeDNSQuery(%q) = % x, want an error", host, query)
		}
	}
}

func TestParseDNSReplyReturnsTheAddressesOfTheAskedFamily(t *testing.T) {
	cases := []struct {
		name  string
		qtype uint16
		reply dnsTestReply
		want  []string
	}{
		{
			name:  "ipv4 addresses",
			qtype: dnsTypeA,
			reply: dnsTestReply{ips: testIPs("192.0.2.10", "192.0.2.11")},
			want:  []string{"192.0.2.10", "192.0.2.11"},
		},
		{
			name:  "ipv6 addresses",
			qtype: dnsTypeAAAA,
			reply: dnsTestReply{ips: testIPs("2001:db8::10", "2001:db8::11")},
			want:  []string{"2001:db8::10", "2001:db8::11"},
		},
		{
			name:  "addresses at the end of an alias chain",
			qtype: dnsTypeA,
			reply: dnsTestReply{
				cnames: []string{"epdg.region.example.net", "node7.epdg.example.net"},
				ips:    testIPs("192.0.2.20"),
			},
			want: []string{"192.0.2.20"},
		},
		{
			name:  "an alias without an address of this family",
			qtype: dnsTypeAAAA,
			reply: dnsTestReply{cnames: []string{"epdg.region.example.net"}},
			want:  nil,
		},
		{
			name:  "no records",
			qtype: dnsTypeA,
			reply: dnsTestReply{},
			want:  nil,
		},
		{
			name:  "addresses no ePDG can have are left out",
			qtype: dnsTypeA,
			reply: dnsTestReply{ips: testIPs("127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "255.255.255.255", "192.0.2.30")},
			want:  []string{"192.0.2.30"},
		},
		{
			name:  "ipv6 addresses no ePDG can have are left out",
			qtype: dnsTypeAAAA,
			reply: dnsTestReply{ips: testIPs("::1", "::", "ff02::1", "fe80::1", "2001:db8::30")},
			want:  []string{"2001:db8::30"},
		},
		{
			name:  "a truncated reply keeps its complete records",
			qtype: dnsTypeA,
			reply: dnsTestReply{ips: testIPs("192.0.2.40", "192.0.2.41"), truncated: true, chop: 3},
			want:  []string{"192.0.2.40"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query := mustDNSQuery(t, 0x4242, testEPDGHost, tc.qtype)
			ips, err := parseDNSReply(buildDNSTestReply(query, tc.reply), 0x4242, testEPDGHost, tc.qtype)
			if err != nil {
				t.Fatalf("parseDNSReply() error = %v", err)
			}
			if got := ipStrings(ips); !reflect.DeepEqual(got, append([]string{}, tc.want...)) {
				t.Fatalf("addresses = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseDNSReplyMatchesTheQuestionWithoutRegardToCase(t *testing.T) {
	query := mustDNSQuery(t, 7, testEPDGHost, dnsTypeA)
	reply := buildDNSTestReply(query, dnsTestReply{ips: testIPs("192.0.2.10")})
	copy(reply[dnsHeaderLen:], bytes.ToUpper(reply[dnsHeaderLen:dnsHeaderLen+len(testEPDGHost)+1]))

	ips, err := parseDNSReply(reply, 7, testEPDGHost, dnsTypeA)
	if err != nil || len(ips) != 1 {
		t.Fatalf("parseDNSReply() = %v, %v; want one address", ips, err)
	}
}

func TestParseDNSReplyTellsForeignDatagramsFromFailures(t *testing.T) {
	query := mustDNSQuery(t, 0x0101, testEPDGHost, dnsTypeA)
	good := buildDNSTestReply(query, dnsTestReply{ips: testIPs("192.0.2.10")})

	notOurs := map[string][]byte{
		"another transaction id":   buildDNSTestReply(query, dnsTestReply{ips: testIPs("192.0.2.10"), idOffset: 1}),
		"a query, not a reply":     query,
		"a reply for another name": buildDNSTestReply(mustDNSQuery(t, 0x0101, "epdg.other.example.org", dnsTypeA), dnsTestReply{ips: testIPs("192.0.2.10")}),
		"a reply for another type": buildDNSTestReply(mustDNSQuery(t, 0x0101, testEPDGHost, dnsTypeAAAA), dnsTestReply{ips: testIPs("2001:db8::10")}),
		"shorter than a header":    good[:dnsHeaderLen-1],
		"cut inside the question":  good[:dnsHeaderLen+5],
		"empty":                    nil,
	}
	for name, msg := range notOurs {
		if ips, err := parseDNSReply(msg, 0x0101, testEPDGHost, dnsTypeA); !errors.Is(err, errDNSNotOurs) {
			t.Errorf("%s: parseDNSReply() = %v, %v; want errDNSNotOurs", name, ips, err)
		}
	}

	for _, rcode := range []int{2, 3, 5} {
		var rcodeErr *dnsRCodeError
		_, err := parseDNSReply(buildDNSTestReply(query, dnsTestReply{rcode: rcode}), 0x0101, testEPDGHost, dnsTypeA)
		if !errors.As(err, &rcodeErr) || rcodeErr.code != rcode {
			t.Errorf("rcode %d: parseDNSReply() error = %v, want a dnsRCodeError with that code", rcode, err)
		}
	}

	malformed := map[string][]byte{
		"cut inside a record without the truncation flag": buildDNSTestReply(query, dnsTestReply{ips: testIPs("192.0.2.10"), chop: 2}),
		"an address record of the wrong size":             buildDNSTestReply(query, dnsTestReply{rawRData: [][]byte{{192, 0, 2}}}),
		"more answers announced than present": func() []byte {
			msg := append([]byte(nil), good...)
			binary.BigEndian.PutUint16(msg[6:], 5)
			return msg
		}(),
	}
	for name, msg := range malformed {
		if ips, err := parseDNSReply(msg, 0x0101, testEPDGHost, dnsTypeA); !errors.Is(err, errDNSMalformed) {
			t.Errorf("%s: parseDNSReply() = %v, %v; want errDNSMalformed", name, ips, err)
		}
	}
}

// Whatever arrives on the relay socket, parsing must end with a result: a
// stray or hostile datagram may not take the session start down.
func TestParseDNSReplySurvivesDamagedReplies(t *testing.T) {
	for _, qtype := range []uint16{dnsTypeA, dnsTypeAAAA} {
		query := mustDNSQuery(t, 0x7777, testEPDGHost, qtype)
		ips := testIPs("192.0.2.10", "192.0.2.11")
		if qtype == dnsTypeAAAA {
			ips = testIPs("2001:db8::10", "2001:db8::11")
		}
		good := buildDNSTestReply(query, dnsTestReply{
			cnames: []string{"epdg.region.example.net", "node7.epdg.example.net"},
			ips:    ips,
		})

		for length := 0; length <= len(good); length++ {
			_, _ = parseDNSReply(good[:length], 0x7777, testEPDGHost, qtype)
		}
		for position := range good {
			for _, value := range []byte{0x00, 0x01, 0x3f, 0x40, 0x80, 0xc0, 0xff} {
				damaged := append([]byte(nil), good...)
				damaged[position] = value
				_, _ = parseDNSReply(damaged, 0x7777, testEPDGHost, qtype)
			}
		}
	}
}

func TestReadDNSNameFollowsBackwardPointersOnly(t *testing.T) {
	// "org" at 0, "example" + pointer to 0 at 5, "epdg" + pointer to 5 at 15.
	msg := []byte{
		3, 'o', 'r', 'g', 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0xc0, 0,
		4, 'e', 'p', 'd', 'g', 0xc0, 5,
		0xee,
	}
	name, next, err := readDNSName(msg, 15)
	if err != nil || name != "epdg.example.org" || next != 22 {
		t.Fatalf("readDNSName() = %q, %d, %v; want epdg.example.org, 22, nil", name, next, err)
	}

	bad := map[string][]byte{
		"a pointer to itself":           {0xc0, 0},
		"a pointer forwards":            {0xc0, 2, 1, 'a', 0},
		"a loop through a label":        {1, 'a', 0xc0, 0},
		"a pointer without second byte": {0xc0},
		"a label past the end":          {5, 'a', 'b'},
		"no terminator":                 {1, 'a'},
		"a reserved label type":         {0x40, 'a', 0},
		"nothing":                       {},
	}
	for what, msg := range bad {
		start := 0
		if what == "a loop through a label" {
			start = 2
		}
		if name, _, err := readDNSName(msg, start); !errors.Is(err, errDNSMalformed) {
			t.Errorf("%s: readDNSName() = %q, %v; want errDNSMalformed", what, name, err)
		}
	}

	// 130 two-byte labels spell a name longer than any DNS name may be.
	long := bytes.Repeat([]byte{1, 'a'}, 130)
	long = append(long, 0)
	if name, _, err := readDNSName(long, 0); !errors.Is(err, errDNSMalformed) {
		t.Errorf("oversized name: readDNSName() = %d bytes, %v; want errDNSMalformed", len(name), err)
	}
}
