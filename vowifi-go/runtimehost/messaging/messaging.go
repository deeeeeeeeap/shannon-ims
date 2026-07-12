package messaging

import (
	"context"
	"errors"
	"time"
)

var ErrDeliveryNotFound = errors.New("delivery not found")

// SMSPart is one already-encoded SMS TPDU part, wrapped in RP-DATA and
// ready to send as a SIP MESSAGE body. Building this (GSM 7-bit/UCS2 text
// encoding, concatenation, RP-DATA framing, RP-MR allocation) is the
// caller's job, not this package's: this package must not import vohive's
// pkg/smscodec (vohive depends on vowifi-go, not the reverse), and the
// caller already owns the SMSC relationship and delivery bookkeeping.
type SMSPart struct {
	// RPMR is this part's RP-Message-Reference. It's already embedded
	// inside Body, but passed explicitly too so the delivery-report
	// correlation path (which only needs to recognize an incoming
	// RP-ACK/RP-ERROR's type/cause, not decode a full TPDU) doesn't have to
	// re-parse it back out of encoded bytes.
	RPMR byte
	// Body is the complete RP-DATA(SUBMIT) octet string for this part,
	// exactly as it should appear in the SIP MESSAGE body
	// (Content-Type: application/vnd.3gpp.sms).
	Body []byte
}

type SendOutcome struct {
	MessageID     string
	PartsTotal    int
	DeliveryState string
}
type USSDResult struct{}

// --- Delivery types ---

type DeliveryPartMatch struct {
	MessageID string
	PartNo    int
	State     string
}

type DeliveryPartStatus struct {
	PartNo      int
	CallID      string
	InReplyTo   string
	RPMR        int
	State       string
	SIPCode     int
	RPCause     int
	RPCauseText string
	ErrorText   string
	SentAt      time.Time
	ReportAt    *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type DeliveryStatus struct {
	MessageID  string
	IMSI       string
	DeviceID   string
	Peer       string
	Content    string
	PartsTotal int
	Acks       int
	State      string
	LastError  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Parts      []DeliveryPartStatus
}

type DeliveryStore interface {
	CreateSMSDelivery(messageID, imsi, deviceID, peer, content string, partsTotal int, at time.Time) error
	UpsertSMSDeliveryPart(messageID string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error
	MarkSMSDeliveryPartReport(inReplyTo, callID, deviceID string, rpMR int, state string, sipCode int, rpCause int, errText string, at time.Time) (DeliveryPartMatch, error)
	RecomputeSMSDelivery(messageID string, at time.Time) error
	UpdateSMSDeliveryState(messageID, state, lastError string, acks int, at time.Time) error
	GetSMSDeliveryStatus(messageID string) (*DeliveryStatus, error)
}

type Service interface {
	// SendSMS transmits pre-encoded parts to peer (an MSISDN or SIP URI)
	// as SIP MESSAGE(s) and tracks delivery via DeliveryStore (this is what
	// calls DeliveryStore.CreateSMSDelivery/UpsertSMSDeliveryPart, so the
	// implementation needs to know content -- it can't recover the original
	// text from parts, which are already opaque encoded bytes). Encoding
	// itself is entirely the caller's job -- see SMSPart.
	SendSMS(ctx context.Context, peer, content string, parts []SMSPart) (SendOutcome, error)
	SendUSSD(ctx context.Context, command string) (*USSDResult, error)
	ContinueUSSD(ctx context.Context, sessionID, input string) (*USSDResult, error)
	CancelUSSD(ctx context.Context, sessionID string) error
}

func RPCauseText(code int) string { return "" }

func WithSuppressSendTGSuccess(ctx context.Context) context.Context { return ctx }
