package eventhost

import (
	"context"
	"time"
)

// Event is the marker interface for all event types.
type Event interface {
	isEvent()
}

// SMSReceived is emitted when an incoming SMS arrives over IMS.
type SMSReceived struct {
	DevID   string
	Sender  string
	Content string
	Time    time.Time
	IMSI    string
}

func (SMSReceived) isEvent() {}

// SMSSent is emitted when an outgoing SMS is submitted over IMS.
type SMSSent struct {
	DevID      string
	TargetURI  string
	Content    string
	Time       time.Time
	TotalParts int
}

func (SMSSent) isEvent() {}

// LocalNumberLearned is emitted when the IMS stack learns the local phone number.
type LocalNumberLearned struct {
	DevID  string
	IMSI   string
	Number string
	// Source names where the number came from, e.g. "register" (P-Associated-URI
	// on a SIP REGISTER 200 OK) or "notify" (a reg-event NOTIFY body).
	Source string
}

func (LocalNumberLearned) isEvent() {}

// LogNotify is emitted for log-style notifications.
type LogNotify struct {
	Message string
}

func (LogNotify) isEvent() {}

// Dispatcher dispatches events to handlers.
type Dispatcher interface {
	Dispatch(ctx context.Context, e Event)
}
