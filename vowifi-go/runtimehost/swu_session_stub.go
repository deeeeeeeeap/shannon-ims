//go:build !linux

package runtimehost

import (
	"context"
	"fmt"
	"net"
	"runtime"
)

type swuInnerDataplane interface {
	SendInnerPacket([]byte) error
	InnerPackets() <-chan []byte
}

func (i *Instance) startSWuSession(ctx context.Context, req StartRequest, epdgIP, epdgPort string) (swuSnapshot, net.IP, swuInnerDataplane, func(string, string) error, error) {
	return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu tunnel failed: full VoWiFi IPsec dataplane is only supported on Linux, current platform is %s", runtime.GOOS)
}
