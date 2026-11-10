package device

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/internal/modem"
	"github.com/1239t/vohive/internal/smsnotify"
	"github.com/1239t/vohive/pkg/logger"
	"github.com/1239t/vohive/pkg/smscodec"
)

const (
	// smsStartupPollDelay is how long after a worker starts its modem is asked
	// for waiting messages for the first time; smsPollInterval is the period of
	// the later reads.
	smsStartupPollDelay = 15 * time.Second
	smsPollInterval     = 60 * time.Second

	// cellularSMSRetryGrace bounds how long a received message is kept in the
	// modem because it cannot be stored yet: the SIM identity cannot be read, or
	// the database refuses the message. Both normally last moments. When the
	// condition persists the message is handed to the in-memory path, which
	// presents it as it was presented before the pipeline existed.
	cellularSMSRetryGrace = 3 * time.Minute

	// cellularSMSRetryLimit is the number of messages whose first failed
	// attempt is remembered at one time.
	cellularSMSRetryLimit = 128

	// incomingSMSJournalRetention is how long rows of the incoming part journal
	// are kept, and incomingSMSJournalPurgeInterval how often old rows are removed.
	incomingSMSJournalRetention     = 30 * 24 * time.Hour
	incomingSMSJournalPurgeInterval = 6 * time.Hour
)

var (
	// errIncomingSMSUnusable marks a TPDU the receive pipeline cannot store: it
	// is not an SMS-DELIVER, cannot be decoded, has no originator or service
	// centre time stamp, or carries inconsistent concatenation counters.
	errIncomingSMSUnusable = errors.New("incoming SMS is not a usable SMS-DELIVER")

	errCellularSMSIdentityUnknown = errors.New("SMS SIM identity unavailable")
)

// incomingSMSChannel names where a received message came from.
type incomingSMSChannel struct {
	source          string // shown in the notification
	messageIDPrefix string // starts the message ID of the history entry
}

var (
	incomingSMSViaIMS      = incomingSMSChannel{source: "VoWiFi", messageIDPrefix: db.IncomingSMSMessageIDPrefixIMS}
	incomingSMSViaCellular = incomingSMSChannel{source: "蜂窝", messageIDPrefix: db.IncomingSMSMessageIDPrefixCellular}
)

// storeIncomingDeliver is the receive pipeline shared by the channels that
// hand over SMS-DELIVER TPDUs (IMS, AT and MBIM): decode, drop carrier OTA
// payloads, store the part, reassembling and de-duplicating in the database,
// and notify once when a complete message was stored.
//
// A nil result means the caller may acknowledge or delete its copy: the
// message was stored, is a repeated delivery, is one part of a longer message
// that is now durable, or was dropped by the filter. errIncomingSMSUnusable
// means the pipeline does not handle this TPDU. Any other error is a storage
// failure and the caller has to keep its copy.
func (p *Pool) storeIncomingDeliver(imsi, deviceID string, tpdu []byte, channel incomingSMSChannel) error {
	if len(tpdu) == 0 || tpdu[0]&3 != 0 {
		return errIncomingSMSUnusable
	}
	sender, content, timestamp, concat, err := smscodec.DecodeDeliverTPDU(tpdu)
	if err != nil || sender == "" || timestamp.IsZero() {
		return errIncomingSMSUnusable
	}
	if smsnotify.ShouldSuppressReceivedSMS(content) {
		return nil
	}
	total, sequence := 1, 1
	if concat.IsConcat {
		total, sequence = concat.Total, concat.Seq
		if total < 2 || total > 255 || sequence < 1 || sequence > total {
			return errIncomingSMSUnusable
		}
	}
	// TP-MMS/TP-RP can change on network retransmission without changing the SMS.
	// The dedup key is SIM-scoped and excludes those envelope hint bits.
	h := sha256.New()
	_, _ = h.Write([]byte(imsi))
	_, _ = h.Write([]byte{0, tpdu[0] &^ 0x84})
	_, _ = h.Write(tpdu[1:])
	result, err := db.StoreIncomingSMSPart(db.IncomingSMSPart{
		Fingerprint: hex.EncodeToString(h.Sum(nil)), IMSI: imsi, Sender: sender,
		Content: content, Timestamp: timestamp, Reference: concat.Ref, ReferenceBits: concat.RefBits,
		Total: total, Sequence: sequence, MessageIDPrefix: channel.messageIDPrefix,
	}, vowifiReceivedSMSDuplicateWindow)
	if err != nil || !result.Stored {
		return err
	}
	p.notifyStoredIncomingSMS(deviceID, result.SMS, channel.source)
	return nil
}

// cellularSMSRetries remembers when storing a message first failed, so that a
// message that keeps failing does not stay in the modem for ever.
type cellularSMSRetries struct {
	mu      sync.Mutex
	pending map[[sha256.Size]byte]time.Time
}

// keep reports whether a message that could not be stored stays in the modem
// for another attempt. It stops doing so cellularSMSRetryGrace after the first
// failure, and at once when too many messages are waiting already.
func (r *cellularSMSRetries) keep(key [sha256.Size]byte, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if first, known := r.pending[key]; known {
		if now.Sub(first) < cellularSMSRetryGrace {
			return true
		}
		delete(r.pending, key)
		return false
	}
	if len(r.pending) >= cellularSMSRetryLimit {
		// Entries of messages that left the modem by other means are never
		// resolved. A live entry is resolved at the first read after the grace.
		for other, first := range r.pending {
			if now.Sub(first) >= 2*cellularSMSRetryGrace {
				delete(r.pending, other)
			}
		}
		if len(r.pending) >= cellularSMSRetryLimit {
			return false
		}
	}
	if r.pending == nil {
		r.pending = make(map[[sha256.Size]byte]time.Time)
	}
	r.pending[key] = now
	return true
}

func (r *cellularSMSRetries) forget(key [sha256.Size]byte) {
	r.mu.Lock()
	delete(r.pending, key)
	r.mu.Unlock()
}

// storeCellularDeliver feeds an SMS-DELIVER that was read from a modem's
// message storage (AT or MBIM) into the receive pipeline. The result follows
// modem.IncomingSMSSink: nil lets the caller delete the modem's copy,
// modem.ErrIncomingSMSNotTaken hands the message back to the in-memory path,
// and any other error keeps the copy in the modem for the next read.
//
// A message is only kept back for a limited time. While the SIM identity is
// unreadable, or while the database refuses a message, the modem's copy is
// the only one; after cellularSMSRetryGrace the in-memory path takes over so
// that the message is still presented and the modem's storage is released.
func (w *Worker) storeCellularDeliver(tpdu []byte) error {
	if db.DB == nil {
		// Without a database only the in-memory path can present the message.
		return modem.ErrIncomingSMSNotTaken
	}

	imsi := w.GetCachedIMSI()
	if imsi == "" {
		imsi = w.GetIMSI()
	}
	if imsi == "" {
		// The identity belongs to the SIM, not to one message: once it has been
		// unreadable for the grace, later messages are not kept back either.
		now := time.Now()
		since := w.smsIdentityUnknownSince.Load()
		if since == 0 {
			w.smsIdentityUnknownSince.CompareAndSwap(0, now.UnixNano())
			return errCellularSMSIdentityUnknown
		}
		if now.Sub(time.Unix(0, since)) < cellularSMSRetryGrace {
			return errCellularSMSIdentityUnknown
		}
		return modem.ErrIncomingSMSNotTaken
	}
	w.smsIdentityUnknownSince.Store(0)

	// Storage slots can pad a message. The fingerprint has to be the same for
	// every read of one message, so it is taken over the declared length only.
	if trimmed, ok := smscodec.TrimDeliverTPDUToDeclaredLength(tpdu); ok {
		tpdu = trimmed
	}
	key := sha256.Sum256(tpdu)
	err := w.Pool.storeIncomingDeliver(imsi, w.ID, tpdu, incomingSMSViaCellular)
	switch {
	case err == nil:
		w.smsRetries.forget(key)
		return nil
	case errors.Is(err, errIncomingSMSUnusable):
		return modem.ErrIncomingSMSNotTaken
	case w.smsRetries.keep(key, time.Now()):
		return err
	}
	logger.Warn(fmt.Sprintf("[%s] 短信持续无法入库，改由内存路径处理", w.ID), "pdu_len", len(tpdu), "err", err)
	return modem.ErrIncomingSMSNotTaken
}

// storeCellularDeliverPDU is storeCellularDeliver for a full PDU in hex, that
// is with the service centre address in front, as modems return it.
func (w *Worker) storeCellularDeliverPDU(pduHex string) error {
	raw, err := hex.DecodeString(pduHex)
	if err != nil {
		return modem.ErrIncomingSMSNotTaken
	}
	tpdu, err := smscodec.TPDUFromPDU(raw)
	if err != nil {
		return modem.ErrIncomingSMSNotTaken
	}
	return w.storeCellularDeliver(tpdu)
}

// attachATSMSReception routes the messages an AT-mode modem receives into the
// receive pipeline. The callback stays in place for what the pipeline hands
// back.
func (w *Worker) attachATSMSReception(m *modem.Manager) {
	m.SetSMSCallback(func(sender, content string, timestamp time.Time) {
		w.processSMS(sender, content, timestamp)
	})
	m.SetIncomingSMSSink(w.storeCellularDeliver)
}

// drainATInbox collects the received messages that are still in the storage
// of an AT-mode modem: those whose indication was missed while the program
// was not running or the port was reconnecting, and those that were kept back
// because they could not be stored.
func (w *Worker) drainATInbox(reason string) {
	if w == nil || w.Modem == nil {
		return
	}
	handled, err := w.Modem.DrainStoredSMS()
	if err != nil {
		logger.Warn(fmt.Sprintf("[%s] 补收模组短信失败", w.ID), "reason", reason, "handled", handled, "err", err)
	}
}

// pollStoredSMS asks the modem for waiting messages over the channel the
// worker currently receives on.
func (w *Worker) pollStoredSMS(reason string) {
	switch w.smsMode {
	case smsModeAT:
		w.drainATInbox(reason)
	case smsModeQMI:
		if w.QMICore != nil {
			if err := w.CheckAllSMSQMI(); err != nil {
				logger.Warn(fmt.Sprintf("[%s] QMI 轮询短信失败", w.ID), "err", err)
			}
		}
	case smsModeMBIM:
		w.handleNewSMSMBIM(reason)
	case smsModeVoWiFi:
		// Messages arrive over IMS; the modem's storage is not read.
	}
}

// runSMSPoll reads waiting messages shortly after the worker started and then
// once per smsPollInterval, until the worker or the pool stops.
func (p *Pool) runSMSPoll(worker *Worker) {
	p.runSMSPollEvery(worker, smsStartupPollDelay, smsPollInterval)
}

func (p *Pool) runSMSPollEvery(worker *Worker, startupDelay, interval time.Duration) {
	startup := time.NewTimer(startupDelay)
	defer startup.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-worker.stop:
			return
		case <-startup.C:
			worker.pollStoredSMS("startup")
		case <-ticker.C:
			worker.pollStoredSMS("poll")
		}
	}
}

// incomingSMSJournalPurgedAt is the time of the last purge in Unix nanoseconds.
// The journal is one table for all devices, so the purge is process-wide.
var incomingSMSJournalPurgedAt atomic.Int64

// purgeIncomingSMSJournalIfDue removes journal rows that are older than
// incomingSMSJournalRetention, at most once per incomingSMSJournalPurgeInterval.
//
// Rows of completed messages only serve to recognise a repeated delivery, and
// parts that are still incomplete after the retention can no longer be
// completed. Such parts are removed without being presented, as the in-memory
// reassembly has always discarded them.
func purgeIncomingSMSJournalIfDue(now time.Time) {
	if db.DB == nil {
		return
	}
	last := incomingSMSJournalPurgedAt.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < incomingSMSJournalPurgeInterval {
		return
	}
	if !incomingSMSJournalPurgedAt.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	removed, err := db.PurgeIncomingSMSJournal(now.Add(-incomingSMSJournalRetention))
	if err != nil {
		logger.Warn("清理短信分片记录失败", "err", err)
		return
	}
	if removed.Completed > 0 || removed.Incomplete > 0 {
		logger.Info("已清理过期的短信分片记录", "completed", removed.Completed, "incomplete", removed.Incomplete)
	}
}
