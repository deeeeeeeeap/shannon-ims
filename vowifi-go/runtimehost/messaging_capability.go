package runtimehost

import (
	"context"
	"errors"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

func (i *Instance) acquireUSSDService() (messaging.Service, error) {
	if i == nil {
		return nil, errors.New("runtimehost: instance is nil")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped {
		return nil, errors.New("runtimehost: instance stopped")
	}
	if !i.state.IMSReady || i.svc == nil {
		return nil, errors.New("runtimehost: IMS USSD service not ready")
	}
	i.acquireServiceUseLocked()
	return i.svc, nil
}

func (i *Instance) SendUSSD(ctx context.Context, command string) (*messaging.USSDResult, error) {
	svc, err := i.acquireUSSDService()
	if err != nil {
		return nil, err
	}
	defer i.releaseServiceUse()
	return svc.SendUSSD(ctx, command)
}

func (i *Instance) ContinueUSSD(ctx context.Context, sessionID, input string) (*messaging.USSDResult, error) {
	svc, err := i.acquireUSSDService()
	if err != nil {
		return nil, err
	}
	defer i.releaseServiceUse()
	return svc.ContinueUSSD(ctx, sessionID, input)
}

func (i *Instance) CancelUSSD(ctx context.Context, sessionID string) error {
	svc, err := i.acquireUSSDService()
	if err != nil {
		return err
	}
	defer i.releaseServiceUse()
	return svc.CancelUSSD(ctx, sessionID)
}
