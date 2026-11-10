package device

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/internal/modem"
	"github.com/1239t/vohive/internal/simulation/smssim"
	"github.com/1239t/vohive/pkg/smscodec"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

// The test network identity 001/01 with an invented subscriber number.
const incomingSMSTestIMSI = "001010123456789"

var incomingSMSTestTime = time.Date(2026, 3, 9, 8, 30, 15, 0, time.UTC)

// openIncomingSMSTestDB opens an empty history database and returns its path,
// so that a test can close the database and open it again.
func openIncomingSMSTestDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history.db")
	if err := db.Init(path); err != nil {
		t.Fatalf("db.Init() error = %v", err)
	}
	t.Cleanup(func() {
		closeIncomingSMSTestDB(t)
		db.DB = nil
	})
	return path
}

// withoutIncomingSMSTestDB runs the test without a history database, whatever
// an earlier test left behind.
func withoutIncomingSMSTestDB(t *testing.T) {
	t.Helper()
	previous := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = previous })
}

// closeIncomingSMSTestDB closes the connection and leaves db.DB in place, the
// state of a database that has stopped answering.
func closeIncomingSMSTestDB(t *testing.T) {
	t.Helper()
	if db.DB == nil {
		return
	}
	database, err := db.DB.DB()
	if err != nil {
		t.Fatalf("db.DB.DB() error = %v", err)
	}
	_ = database.Close()
}

type incomingSMSNotice struct {
	DeviceID, Sender, Content, Source string
}

// incomingSMSNotifierStub records notifications. The receive pipeline names
// the channel a message came from; the in-memory path does not, so its
// notices have an empty Source.
type incomingSMSNotifierStub struct {
	mu      sync.Mutex
	notices []incomingSMSNotice
}

func (s *incomingSMSNotifierStub) NotifySMS(deviceID, sender, content string, _ time.Time) {
	s.NotifySMSWithSource(deviceID, sender, content, "", time.Time{})
}

func (s *incomingSMSNotifierStub) NotifySMSWithSource(deviceID, sender, content, source string, _ time.Time) {
	s.mu.Lock()
	s.notices = append(s.notices, incomingSMSNotice{DeviceID: deviceID, Sender: sender, Content: content, Source: source})
	s.mu.Unlock()
}

func (s *incomingSMSNotifierStub) NotifyIPRotated(string, string, string, time.Duration) {}
func (s *incomingSMSNotifierStub) NotifyRaw(string)                                      {}

func (s *incomingSMSNotifierStub) seen() []incomingSMSNotice {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]incomingSMSNotice(nil), s.notices...)
}

// newIncomingSMSTestWorker returns a worker as it is after a start: nothing
// in memory, and the SIM identity given (empty when it has not been read).
func newIncomingSMSTestWorker(imsi string) (*Worker, *incomingSMSNotifierStub) {
	notifier := &incomingSMSNotifierStub{}
	w := &Worker{ID: "dev1", Pool: &Pool{notifier: notifier}, reassembler: smscodec.NewReassembler()}
	setIncomingSMSTestIMSI(w, imsi)
	return w, notifier
}

func setIncomingSMSTestIMSI(w *Worker, imsi string) {
	w.cacheMu.Lock()
	w.state.Identity.IMSI = imsi
	w.cacheMu.Unlock()
}

// expireIncomingSMSRetries makes every message that is waiting for another
// attempt look as if its first attempt failed longer ago than the grace.
func expireIncomingSMSRetries(w *Worker) {
	w.smsRetries.mu.Lock()
	for key := range w.smsRetries.pending {
		w.smsRetries.pending[key] = time.Now().Add(-cellularSMSRetryGrace - time.Second)
	}
	w.smsRetries.mu.Unlock()
}

func deliverTPDUs(t *testing.T, from, text string, reference int) [][]byte {
	t.Helper()
	parts, err := smssim.Deliver(smssim.Message{From: from, Text: text, Time: incomingSMSTestTime, Reference: reference})
	if err != nil {
		t.Fatalf("smssim.Deliver() error = %v", err)
	}
	return parts
}

func deliverTPDU(t *testing.T, from, text string) []byte {
	t.Helper()
	parts := deliverTPDUs(t, from, text, 1)
	if len(parts) != 1 {
		t.Fatalf("%q needs %d parts, want 1", text, len(parts))
	}
	return parts[0]
}

func threePartTPDUs(t *testing.T, from, text string, reference int) [][]byte {
	t.Helper()
	parts := deliverTPDUs(t, from, text, reference)
	if len(parts) != 3 {
		t.Fatalf("fixture has %d parts, want 3", len(parts))
	}
	return parts
}

func pduHexOf(t *testing.T, tpdu []byte) string {
	t.Helper()
	pduHex, err := smssim.PDUHex("+7654321", tpdu)
	if err != nil {
		t.Fatalf("smssim.PDUHex() error = %v", err)
	}
	return pduHex
}

// receivedSMS returns the received messages in the history, oldest first.
func receivedSMS(t *testing.T) []db.SMS {
	t.Helper()
	var rows []db.SMS
	if err := db.DB.Where("type = ?", 1).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("reading the history: %v", err)
	}
	return rows
}

func TestCellularDeliverIsStoredAndNotifiedOnce(t *testing.T) {
	openIncomingSMSTestDB(t)
	w, notifier := newIncomingSMSTestWorker(incomingSMSTestIMSI)
	tpdu := deliverTPDU(t, "+12025550123", "your code is 482913")

	// The second delivery stands for a read that is repeated because the modem
	// refused to delete the message, the third for a modem that pads its slots.
	for i, delivery := range [][]byte{tpdu, tpdu, smssim.PadSlot(tpdu, 164)} {
		if err := w.storeCellularDeliver(delivery); err != nil {
			t.Fatalf("delivery %d: storeCellularDeliver() error = %v", i+1, err)
		}
	}

	rows := receivedSMS(t)
	if len(rows) != 1 {
		t.Fatalf("history has %d received messages, want 1", len(rows))
	}
	got := rows[0]
	if got.IMSI != incomingSMSTestIMSI || got.Sender != "+12025550123" || got.Peer != "+12025550123" ||
		got.Content != "your code is 482913" || got.Status != 0 || !got.Timestamp.Equal(incomingSMSTestTime) {
		t.Fatalf("history entry = %+v", got)
	}
	if !strings.HasPrefix(got.MessageID, db.IncomingSMSMessageIDPrefixCellular) {
		t.Fatalf("message ID = %q, want the prefix %q", got.MessageID, db.IncomingSMSMessageIDPrefixCellular)
	}
	want := []incomingSMSNotice{{DeviceID: "dev1", Sender: "+12025550123", Content: "your code is 482913", Source: "蜂窝"}}
	if notices := notifier.seen(); !reflect.DeepEqual(notices, want) {
		t.Fatalf("notices = %+v, want %+v", notices, want)
	}
}

func TestLongCellularMessageSurvivesARestartBetweenItsParts(t *testing.T) {
	openIncomingSMSTestDB(t)
	text := strings.Repeat("a long message that is split into parts ", 9)
	parts := threePartTPDUs(t, "10086", text, 0x42)

	before, notifierBefore := newIncomingSMSTestWorker(incomingSMSTestIMSI)
	for _, part := range [][]byte{parts[2], parts[0]} {
		if err := before.storeCellularDeliver(part); err != nil {
			t.Fatalf("storeCellularDeliver() error = %v", err)
		}
	}
	if rows := receivedSMS(t); len(rows) != 0 {
		t.Fatalf("history has %d messages before the last part arrived", len(rows))
	}

	// The program restarts. Nothing is left in memory, only the database.
	after, notifierAfter := newIncomingSMSTestWorker(incomingSMSTestIMSI)
	if err := after.storeCellularDeliver(parts[1]); err != nil {
		t.Fatalf("storeCellularDeliver() error = %v", err)
	}
	// A part that is read again later does not make a second message.
	if err := after.storeCellularDeliver(parts[0]); err != nil {
		t.Fatalf("storeCellularDeliver() of a repeated part error = %v", err)
	}

	rows := receivedSMS(t)
	if len(rows) != 1 || rows[0].Sender != "10086" || rows[0].Content != text {
		t.Fatalf("history = %+v, want the complete text once", rows)
	}
	if notices := notifierBefore.seen(); len(notices) != 0 {
		t.Fatalf("notices before the message was complete = %+v", notices)
	}
	want := []incomingSMSNotice{{DeviceID: "dev1", Sender: "10086", Content: text, Source: "蜂窝"}}
	if notices := notifierAfter.seen(); !reflect.DeepEqual(notices, want) {
		t.Fatalf("notices = %+v, want the complete text once", notices)
	}

	// The parts no longer hold a second copy of the text.
	var journal []db.SMSIncomingPartJournal
	if err := db.DB.Find(&journal).Error; err != nil {
		t.Fatal(err)
	}
	if len(journal) != 3 {
		t.Fatalf("journal has %d rows, want 3", len(journal))
	}
	for _, row := range journal {
		if row.MessageID != rows[0].MessageID || row.Content != "" {
			t.Fatalf("journal row = %+v, want it linked to the message and without text", row)
		}
	}
}

func TestCellularDeliverIsKeptWhileTheDatabaseFails(t *testing.T) {
	path := openIncomingSMSTestDB(t)
	w, notifier := newIncomingSMSTestWorker(incomingSMSTestIMSI)
	tpdu := deliverTPDU(t, "10086", "arrived while the database was down")

	closeIncomingSMSTestDB(t)
	for i := 0; i < 2; i++ {
		err := w.storeCellularDeliver(tpdu)
		if err == nil || errors.Is(err, modem.ErrIncomingSMSNotTaken) {
			t.Fatalf("attempt %d: storeCellularDeliver() error = %v, want a failure that keeps the modem's copy", i+1, err)
		}
	}
	if notices := notifier.seen(); len(notices) != 0 {
		t.Fatalf("notices for a message that was not stored = %+v", notices)
	}

	if err := db.Init(path); err != nil {
		t.Fatalf("db.Init() error = %v", err)
	}
	if err := w.storeCellularDeliver(tpdu); err != nil {
		t.Fatalf("storeCellularDeliver() after the database came back error = %v", err)
	}
	if rows := receivedSMS(t); len(rows) != 1 || rows[0].Content != "arrived while the database was down" {
		t.Fatalf("history = %+v, want the message once", rows)
	}
	if notices := notifier.seen(); len(notices) != 1 || notices[0].Source != "蜂窝" {
		t.Fatalf("notices = %+v, want one from the pipeline", notices)
	}
	if len(w.smsRetries.pending) != 0 {
		t.Fatalf("%d messages are still marked as waiting", len(w.smsRetries.pending))
	}
}

func TestCellularDeliverIsHandedBackWhenTheDatabaseKeepsFailing(t *testing.T) {
	openIncomingSMSTestDB(t)
	w, _ := newIncomingSMSTestWorker(incomingSMSTestIMSI)
	tpdu := deliverTPDU(t, "10086", "the database never came back")

	closeIncomingSMSTestDB(t)
	if err := w.storeCellularDeliver(tpdu); err == nil || errors.Is(err, modem.ErrIncomingSMSNotTaken) {
		t.Fatalf("storeCellularDeliver() error = %v, want a failure that keeps the modem's copy", err)
	}

	expireIncomingSMSRetries(w)
	if err := w.storeCellularDeliver(tpdu); !errors.Is(err, modem.ErrIncomingSMSNotTaken) {
		t.Fatalf("storeCellularDeliver() after the grace error = %v, want modem.ErrIncomingSMSNotTaken", err)
	}
	if len(w.smsRetries.pending) != 0 {
		t.Fatalf("%d messages are still marked as waiting", len(w.smsRetries.pending))
	}
}

func TestCellularSMSRetriesAreBounded(t *testing.T) {
	var retries cellularSMSRetries
	start := time.Now()
	key := func(i int) [sha256.Size]byte { return sha256.Sum256([]byte{byte(i), byte(i >> 8)}) }

	for i := 0; i < cellularSMSRetryLimit; i++ {
		if !retries.keep(key(i), start) {
			t.Fatalf("message %d was not kept", i)
		}
	}
	if retries.keep(key(cellularSMSRetryLimit), start) {
		t.Fatal("a message was kept although the limit was reached")
	}
	if !retries.keep(key(0), start.Add(cellularSMSRetryGrace-time.Second)) {
		t.Fatal("a message was given up within the grace")
	}
	if retries.keep(key(0), start.Add(cellularSMSRetryGrace)) {
		t.Fatal("a message was kept beyond the grace")
	}

	// Two entries are gone now: the one given up and the one forgotten here.
	retries.forget(key(1))
	for i := 0; i < 2; i++ {
		if !retries.keep(key(cellularSMSRetryLimit+i), start) {
			t.Fatal("a message was not kept although there was room again")
		}
	}

	// The limit is reached again. Entries that were never resolved make room
	// once they are clearly stale.
	if !retries.keep(key(cellularSMSRetryLimit+2), start.Add(2*cellularSMSRetryGrace)) {
		t.Fatal("stale entries were not dropped")
	}
	if len(retries.pending) != 1 {
		t.Fatalf("%d entries are left, want 1", len(retries.pending))
	}
}

func TestCellularDeliverWaitsForTheSIMIdentity(t *testing.T) {
	openIncomingSMSTestDB(t)
	w, notifier := newIncomingSMSTestWorker("")
	tpdu := deliverTPDU(t, "10086", "arrived before the SIM was read")

	for i := 0; i < 2; i++ {
		if err := w.storeCellularDeliver(tpdu); !errors.Is(err, errCellularSMSIdentityUnknown) {
			t.Fatalf("attempt %d: storeCellularDeliver() error = %v, want errCellularSMSIdentityUnknown", i+1, err)
		}
	}
	if rows := receivedSMS(t); len(rows) != 0 {
		t.Fatalf("history = %+v, want nothing while the SIM is unknown", rows)
	}

	setIncomingSMSTestIMSI(w, incomingSMSTestIMSI)
	if err := w.storeCellularDeliver(tpdu); err != nil {
		t.Fatalf("storeCellularDeliver() error = %v", err)
	}
	if rows := receivedSMS(t); len(rows) != 1 || rows[0].IMSI != incomingSMSTestIMSI {
		t.Fatalf("history = %+v, want the message under the SIM", rows)
	}
	if notices := notifier.seen(); len(notices) != 1 || notices[0].Source != "蜂窝" {
		t.Fatalf("notices = %+v, want one from the pipeline", notices)
	}
	if w.smsIdentityUnknownSince.Load() != 0 {
		t.Fatal("the SIM identity is still marked as unknown")
	}
}

func TestCellularDeliverIsHandedBackWhenTheSIMIdentityStaysUnknown(t *testing.T) {
	openIncomingSMSTestDB(t)
	w, _ := newIncomingSMSTestWorker("")
	tpdu := deliverTPDU(t, "10086", "the SIM was never read")

	if err := w.storeCellularDeliver(tpdu); !errors.Is(err, errCellularSMSIdentityUnknown) {
		t.Fatalf("storeCellularDeliver() error = %v, want errCellularSMSIdentityUnknown", err)
	}
	w.smsIdentityUnknownSince.Store(time.Now().Add(-cellularSMSRetryGrace - time.Second).UnixNano())

	// Every message is handed back from now on, also one that has not waited.
	for _, delivery := range [][]byte{tpdu, deliverTPDU(t, "10086", "a later message")} {
		if err := w.storeCellularDeliver(delivery); !errors.Is(err, modem.ErrIncomingSMSNotTaken) {
			t.Fatalf("storeCellularDeliver() after the grace error = %v, want modem.ErrIncomingSMSNotTaken", err)
		}
	}
}

func TestCellularDeliverLeavesWhatItCannotStoreToTheInMemoryPath(t *testing.T) {
	withoutIncomingSMSTestDB(t)
	w, _ := newIncomingSMSTestWorker(incomingSMSTestIMSI)
	tpdu := deliverTPDU(t, "10086", "plain message")

	// Without a database nothing can be stored.
	if err := w.storeCellularDeliver(tpdu); !errors.Is(err, modem.ErrIncomingSMSNotTaken) {
		t.Fatalf("storeCellularDeliver() without a database error = %v, want modem.ErrIncomingSMSNotTaken", err)
	}

	openIncomingSMSTestDB(t)
	statusReport := append([]byte(nil), tpdu...)
	statusReport[0] = statusReport[0]&^0x03 | 0x02
	for name, unusable := range map[string][]byte{
		"nothing":         nil,
		"a status report": statusReport,
		"a truncated PDU": tpdu[:6],
	} {
		if err := w.storeCellularDeliver(unusable); !errors.Is(err, modem.ErrIncomingSMSNotTaken) {
			t.Fatalf("%s: storeCellularDeliver() error = %v, want modem.ErrIncomingSMSNotTaken", name, err)
		}
	}
	for _, pduHex := range []string{"not hexadecimal", "0791"} {
		if err := w.storeCellularDeliverPDU(pduHex); !errors.Is(err, modem.ErrIncomingSMSNotTaken) {
			t.Fatalf("storeCellularDeliverPDU(%q) error = %v, want modem.ErrIncomingSMSNotTaken", pduHex, err)
		}
	}
	if rows := receivedSMS(t); len(rows) != 0 {
		t.Fatalf("history = %+v, want nothing", rows)
	}
	if len(w.smsRetries.pending) != 0 {
		t.Fatalf("%d messages are marked as waiting", len(w.smsRetries.pending))
	}
}

// Text that the decoder marks as a carrier provisioning payload is dropped on
// every channel: it is neither stored nor announced, and the modem's copy may go.
func TestCellularDeliverDropsCarrierProvisioningPayloads(t *testing.T) {
	openIncomingSMSTestDB(t)
	w, notifier := newIncomingSMSTestWorker(incomingSMSTestIMSI)

	if err := w.storeCellularDeliver(deliverTPDU(t, "10086", "[SIM OTA 23.048] 027000")); err != nil {
		t.Fatalf("storeCellularDeliver() error = %v", err)
	}
	if rows := receivedSMS(t); len(rows) != 0 {
		t.Fatalf("history = %+v, want nothing", rows)
	}
	if notices := notifier.seen(); len(notices) != 0 {
		t.Fatalf("notices = %+v, want none", notices)
	}
}

func TestMessageDeliveredOverIMSAndReadFromTheModemIsStoredOnce(t *testing.T) {
	openIncomingSMSTestDB(t)
	w, notifier := newIncomingSMSTestWorker(incomingSMSTestIMSI)
	tpdu := deliverTPDU(t, "+12025550123", "delivered on both channels")
	store := vowifiDeliveryStore{pool: w.Pool}

	if err := store.StoreIncomingSMS(incomingSMSTestIMSI, w.ID, tpdu, time.Now()); err != nil {
		t.Fatalf("StoreIncomingSMS() error = %v", err)
	}
	if err := w.storeCellularDeliver(tpdu); err != nil {
		t.Fatalf("storeCellularDeliver() error = %v", err)
	}

	rows := receivedSMS(t)
	if len(rows) != 1 || !strings.HasPrefix(rows[0].MessageID, db.IncomingSMSMessageIDPrefixIMS) {
		t.Fatalf("history = %+v, want the message once, as received over IMS", rows)
	}
	want := []incomingSMSNotice{{DeviceID: "dev1", Sender: "+12025550123", Content: "delivered on both channels", Source: "VoWiFi"}}
	if notices := notifier.seen(); !reflect.DeepEqual(notices, want) {
		t.Fatalf("notices = %+v, want %+v", notices, want)
	}

	// What the IMS side is told about a message it cannot use has not changed.
	statusReport := append([]byte(nil), tpdu...)
	statusReport[0] = statusReport[0]&^0x03 | 0x02
	if err := store.StoreIncomingSMS("", w.ID, tpdu, time.Now()); !errors.Is(err, messaging.ErrInvalidIncomingSMS) {
		t.Fatalf("StoreIncomingSMS() without a SIM identity error = %v, want messaging.ErrInvalidIncomingSMS", err)
	}
	if err := store.StoreIncomingSMS(incomingSMSTestIMSI, w.ID, statusReport, time.Now()); !errors.Is(err, messaging.ErrInvalidIncomingSMS) {
		t.Fatalf("StoreIncomingSMS() of a status report error = %v, want messaging.ErrInvalidIncomingSMS", err)
	}
}

// incomingSMSMBIMInbox is the message storage of an MBIM modem: messages stay
// until they are deleted.
type incomingSMSMBIMInbox struct {
	mbimInboxBackendStub

	mu       sync.Mutex
	imsi     string
	messages map[int]string
	lists    int
}

func newIncomingSMSMBIMInbox(imsi string) *incomingSMSMBIMInbox {
	return &incomingSMSMBIMInbox{imsi: imsi, messages: map[int]string{}}
}

func (s *incomingSMSMBIMInbox) GetIMSI(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.imsi, nil
}

func (s *incomingSMSMBIMInbox) ListSMS(context.Context) ([]backend.SMSSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists++
	out := make([]backend.SMSSummary, 0, len(s.messages))
	for index := range s.messages {
		out = append(out, backend.SMSSummary{Index: index, Tag: 1})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

func (s *incomingSMSMBIMInbox) ReadSMS(_ context.Context, index int) (*backend.SMS, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pduHex, ok := s.messages[index]
	if !ok {
		return nil, errors.New("no message at this index")
	}
	return &backend.SMS{Index: index, Content: pduHex}, nil
}

func (s *incomingSMSMBIMInbox) DeleteSMS(_ context.Context, index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.messages, index)
	return nil
}

func (s *incomingSMSMBIMInbox) put(index int, pduHex string) {
	s.mu.Lock()
	s.messages[index] = pduHex
	s.mu.Unlock()
}

func (s *incomingSMSMBIMInbox) indexes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, 0, len(s.messages))
	for index := range s.messages {
		out = append(out, index)
	}
	sort.Ints(out)
	return out
}

func (s *incomingSMSMBIMInbox) listCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lists
}

func TestDrainMBIMInboxStoresMessagesBeforeDeletingThem(t *testing.T) {
	openIncomingSMSTestDB(t)
	inbox := newIncomingSMSMBIMInbox(incomingSMSTestIMSI)
	w, notifier := newIncomingSMSTestWorker("") // the identity is read from the modem
	w.Backend = inbox

	text := strings.Repeat("a long message read over MBIM ", 12)
	parts := threePartTPDUs(t, "10086", text, 9)
	inbox.put(1, pduHexOf(t, deliverTPDU(t, "+12025550123", "single message")))
	inbox.put(2, pduHexOf(t, parts[1]))
	inbox.put(3, pduHexOf(t, parts[0]))

	w.drainMBIMInbox(context.Background(), "test")
	if left := inbox.indexes(); len(left) != 0 {
		t.Fatalf("indexes left in the modem = %v, want none", left)
	}
	if rows := receivedSMS(t); len(rows) != 1 || rows[0].Content != "single message" {
		t.Fatalf("history = %+v, want the single message only", rows)
	}

	// The last part arrives later, after the first two have left the modem.
	inbox.put(4, pduHexOf(t, parts[2]))
	w.drainMBIMInbox(context.Background(), "test")
	if left := inbox.indexes(); len(left) != 0 {
		t.Fatalf("indexes left in the modem = %v, want none", left)
	}
	rows := receivedSMS(t)
	if len(rows) != 2 || rows[1].Sender != "10086" || rows[1].Content != text {
		t.Fatalf("history = %+v, want the long message as the second entry", rows)
	}
	want := []incomingSMSNotice{
		{DeviceID: "dev1", Sender: "+12025550123", Content: "single message", Source: "蜂窝"},
		{DeviceID: "dev1", Sender: "10086", Content: text, Source: "蜂窝"},
	}
	if notices := notifier.seen(); !reflect.DeepEqual(notices, want) {
		t.Fatalf("notices = %+v, want %+v", notices, want)
	}
}

func TestDrainMBIMInboxKeepsMessagesWhileTheDatabaseFails(t *testing.T) {
	path := openIncomingSMSTestDB(t)
	inbox := newIncomingSMSMBIMInbox(incomingSMSTestIMSI)
	w, notifier := newIncomingSMSTestWorker("")
	w.Backend = inbox
	inbox.put(1, pduHexOf(t, deliverTPDU(t, "10086", "read while the database was down")))

	closeIncomingSMSTestDB(t)
	w.drainMBIMInbox(context.Background(), "test")
	if left := inbox.indexes(); !reflect.DeepEqual(left, []int{1}) {
		t.Fatalf("indexes left in the modem = %v, want [1]", left)
	}
	if notices := notifier.seen(); len(notices) != 0 {
		t.Fatalf("notices = %+v, want none", notices)
	}

	if err := db.Init(path); err != nil {
		t.Fatalf("db.Init() error = %v", err)
	}
	w.drainMBIMInbox(context.Background(), "test")
	if left := inbox.indexes(); len(left) != 0 {
		t.Fatalf("indexes left in the modem = %v, want none", left)
	}
	if rows := receivedSMS(t); len(rows) != 1 {
		t.Fatalf("history = %+v, want the message once", rows)
	}
	if notices := notifier.seen(); len(notices) != 1 || notices[0].Source != "蜂窝" {
		t.Fatalf("notices = %+v, want one from the pipeline", notices)
	}
}

func TestDrainMBIMInboxPresentsMessagesWhenTheSIMIdentityStaysUnknown(t *testing.T) {
	openIncomingSMSTestDB(t)
	inbox := newIncomingSMSMBIMInbox("")
	w, notifier := newIncomingSMSTestWorker("")
	w.Backend = inbox
	inbox.put(1, pduHexOf(t, deliverTPDU(t, "10086", "the SIM cannot be read")))

	w.drainMBIMInbox(context.Background(), "test")
	if left := inbox.indexes(); !reflect.DeepEqual(left, []int{1}) {
		t.Fatalf("indexes left in the modem = %v, want [1]", left)
	}
	if notices := notifier.seen(); len(notices) != 0 {
		t.Fatalf("notices = %+v, want none within the grace", notices)
	}

	w.smsIdentityUnknownSince.Store(time.Now().Add(-cellularSMSRetryGrace - time.Second).UnixNano())
	w.drainMBIMInbox(context.Background(), "test")
	if left := inbox.indexes(); len(left) != 0 {
		t.Fatalf("indexes left in the modem = %v, want none", left)
	}
	// Presented as before the pipeline existed: announced, but not in the history.
	want := []incomingSMSNotice{{DeviceID: "dev1", Sender: "10086", Content: "the SIM cannot be read"}}
	if notices := notifier.seen(); !reflect.DeepEqual(notices, want) {
		t.Fatalf("notices = %+v, want %+v", notices, want)
	}
	if rows := receivedSMS(t); len(rows) != 0 {
		t.Fatalf("history = %+v, want nothing", rows)
	}
}

func TestPollStoredSMSReadsOverTheChannelInUse(t *testing.T) {
	inbox := newIncomingSMSMBIMInbox(incomingSMSTestIMSI)
	w, _ := newIncomingSMSTestWorker("")
	w.Backend = inbox

	// IMS has taken over, the worker has no AT port, and no QMI client.
	for _, mode := range []smsMode{smsModeVoWiFi, smsModeAT, smsModeQMI} {
		w.smsMode = mode
		w.pollStoredSMS("test")
		if lists := inbox.listCount(); lists != 0 {
			t.Fatalf("mode %s: the MBIM storage was listed %d times, want 0", mode, lists)
		}
	}

	w.smsMode = smsModeMBIM
	w.pollStoredSMS("test")
	if lists := inbox.listCount(); lists != 1 {
		t.Fatalf("the MBIM storage was listed %d times, want 1", lists)
	}
}

func TestSMSPollReadsAfterTheStartupDelayAndThenPeriodically(t *testing.T) {
	pool := NewPool(nil)
	inbox := newIncomingSMSMBIMInbox(incomingSMSTestIMSI)
	w := &Worker{
		ID: "dev1", Pool: pool, Backend: inbox, reassembler: smscodec.NewReassembler(),
		stop: make(chan struct{}), smsMode: smsModeMBIM,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		pool.runSMSPollEvery(w, 10*time.Millisecond, 20*time.Millisecond)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for inbox.listCount() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("the storage was read %d times, want at least 3", inbox.listCount())
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(w.stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the poll did not end with the worker")
	}
	lists := inbox.listCount()
	time.Sleep(60 * time.Millisecond)
	if again := inbox.listCount(); again != lists {
		t.Fatalf("the storage was read %d more times after the worker stopped", again-lists)
	}
}

func journalFingerprints(t *testing.T) []string {
	t.Helper()
	var rows []db.SMSIncomingPartJournal
	if err := db.DB.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Fingerprint)
	}
	sort.Strings(out)
	return out
}

func TestIncomingSMSJournalIsPurgedAtMostOncePerInterval(t *testing.T) {
	openIncomingSMSTestDB(t)
	incomingSMSJournalPurgedAt.Store(0)
	t.Cleanup(func() { incomingSMSJournalPurgedAt.Store(0) })

	now := time.Now()
	old := now.Add(-incomingSMSJournalRetention - time.Hour)
	rows := []db.SMSIncomingPartJournal{
		{Fingerprint: "old-completed", AssemblyKey: "a", MessageID: "cell-in-old", Sequence: 1, Timestamp: old, CreatedAt: old},
		{Fingerprint: "old-incomplete", AssemblyKey: "b", Sequence: 1, Content: "never completed", Timestamp: old, CreatedAt: old},
		{Fingerprint: "recent-completed", AssemblyKey: "c", MessageID: "cell-in-recent", Sequence: 1, Timestamp: now, CreatedAt: now},
		{Fingerprint: "recent-incomplete", AssemblyKey: "d", Sequence: 1, Content: "still waiting", Timestamp: now, CreatedAt: now},
	}
	if err := db.DB.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	recent := []string{"recent-completed", "recent-incomplete"}

	purgeIncomingSMSJournalIfDue(now)
	if got := journalFingerprints(t); !reflect.DeepEqual(got, recent) {
		t.Fatalf("journal after the purge = %v, want %v", got, recent)
	}

	// Within the interval nothing is removed, however old a row is.
	late := db.SMSIncomingPartJournal{Fingerprint: "old-found-later", AssemblyKey: "e", Sequence: 1, Timestamp: old, CreatedAt: old}
	if err := db.DB.Create(&late).Error; err != nil {
		t.Fatal(err)
	}
	purgeIncomingSMSJournalIfDue(now.Add(incomingSMSJournalPurgeInterval - time.Minute))
	if got := journalFingerprints(t); len(got) != 3 {
		t.Fatalf("journal within the interval = %v, want the old row still there", got)
	}

	purgeIncomingSMSJournalIfDue(now.Add(incomingSMSJournalPurgeInterval + time.Minute))
	if got := journalFingerprints(t); !reflect.DeepEqual(got, recent) {
		t.Fatalf("journal after the next purge = %v, want %v", got, recent)
	}
}
