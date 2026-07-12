package voiceclient

import (
	"context"
	"errors"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

// USSD over IMS isn't implemented yet -- these exist only so *Client
// satisfies messaging.Service (Instance.Service() returns *Client
// directly). Out of scope for this phase, which is specifically SendSMS;
// unlike the SMS path, no spike has validated a USSD-over-SIP flow yet.
var errUSSDNotImplemented = errors.New("voiceclient: USSD over IMS is not implemented yet")

func (c *Client) SendUSSD(ctx context.Context, command string) (*messaging.USSDResult, error) {
	return nil, errUSSDNotImplemented
}

func (c *Client) ContinueUSSD(ctx context.Context, sessionID, input string) (*messaging.USSDResult, error) {
	return nil, errUSSDNotImplemented
}

func (c *Client) CancelUSSD(ctx context.Context, sessionID string) error {
	return errUSSDNotImplemented
}
