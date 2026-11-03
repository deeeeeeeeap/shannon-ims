package runtimehost

import (
	"context"
	"time"
)

// Keep the pipeline owner alive until stop, transport loss or registration
// expiry. A connected tunnel alone cannot keep SMS capability valid.
func (i *Instance) watchIMSHealth(ctx context.Context, generation uint64, channelDone, tunnelDone <-chan struct{}, expires <-chan time.Time) {
	class, reason := "ims", "ims_channel_closed"
	select {
	case <-ctx.Done():
		return
	case <-channelDone:
	case <-tunnelDone:
		class, reason = "tunnel", "tunnel_closed"
	case <-expires:
		reason = "ims_registration_expired"
	}
	i.failStageForGeneration(ctx, generation, class, reason, reason)
}
