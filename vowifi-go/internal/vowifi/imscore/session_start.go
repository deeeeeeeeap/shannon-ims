package imscore

import (
	"context"
	"fmt"
)

// StartSessionIMSCore is the author v1.1.2 IMS bootstrap entry: resolve service
// configuration, start the register FSM, and bring up the secure transport runtime.
func StartSessionIMSCore(ctx context.Context, imsCfg IMSConfig, network IMSNetwork, in StartSessionInput) (*Service, error) {
	svc, err := SetupService(imsCfg, network, in)
	if err != nil {
		return nil, err
	}
	if err := svc.Start(ctx); err != nil {
		_ = svc.Close(ctx)
		return nil, fmt.Errorf("imscore: start: %w", err)
	}
	return svc, nil
}