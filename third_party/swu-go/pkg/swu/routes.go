package swu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func isFullIPv4Range(ts *ikev2.TrafficSelector) bool {
	if ts == nil || ts.TSType != ikev2.TS_IPV4_ADDR_RANGE {
		return false
	}
	if len(ts.StartAddr) != 4 || len(ts.EndAddr) != 4 {
		return false
	}
	return binary.BigEndian.Uint32(ts.StartAddr) == 0 && binary.BigEndian.Uint32(ts.EndAddr) == 0xffffffff
}

func isFullIPv6Range(ts *ikev2.TrafficSelector) bool {
	if ts == nil || ts.TSType != ikev2.TS_IPV6_ADDR_RANGE {
		return false
	}
	if len(ts.StartAddr) != 16 || len(ts.EndAddr) != 16 {
		return false
	}
	// StartAddr == :: (all zeros)
	// EndAddr == ffff... (all ones)
	for _, b := range ts.StartAddr {
		if b != 0 {
			return false
		}
	}
	for _, b := range ts.EndAddr {
		if b != 0xff {
			return false
		}
	}
	return true
}

func ipv4RangeToCIDRs(start, end net.IP) ([]string, error) {
	s := start.To4()
	e := end.To4()
	if s == nil || e == nil {
		return nil, errors.New("不是 IPv4 地址")
	}
	su32 := binary.BigEndian.Uint32(s)
	eu32 := binary.BigEndian.Uint32(e)
	if su32 > eu32 {
		return nil, errors.New("IPv4 范围非法")
	}
	cur := uint64(su32)
	endU := uint64(eu32)

	var out []string
	for cur <= endU {
		var maxBlock uint64
		if cur == 0 {
			maxBlock = uint64(1) << 32
		} else {
			maxBlock = uint64(1) << uint(bits.TrailingZeros32(uint32(cur)))
		}

		remaining := endU - cur + 1
		for maxBlock > remaining {
			maxBlock >>= 1
		}

		prefix := 32 - (bits.Len64(maxBlock) - 1)

		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(cur))
		out = append(out, fmt.Sprintf("%s/%d", ip.String(), prefix))

		cur += maxBlock
	}
	return out, nil
}
