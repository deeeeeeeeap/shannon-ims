//go:build !linux

package runtimehost

import (
	"context"
	"fmt"
	"runtime"
)

func (i *Instance) startSWuSession(ctx context.Context, req StartRequest, epdgIP, epdgPort string) (*swuSessionLease, error) {
	return nil, fmt.Errorf("SWu tunnel failed: full VoWiFi IPsec dataplane is only supported on Linux, current platform is %s", runtime.GOOS)
}
