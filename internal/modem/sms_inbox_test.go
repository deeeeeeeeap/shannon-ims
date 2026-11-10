package modem

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/simulation/smssim"
	"github.com/1239t/vohive/pkg/smscodec"
)

// fakeSMSStorage answers the AT commands the manager sends to the message
// storage, the way a modem with several memories does. It stands in for the
// serial port: the manager's command queue is served directly.
type fakeSMSStorage struct {
	mu         sync.Mutex
	memories   [3]string
	slots      map[string]map[int]fakeStoredSMS
	commands   []string
	deleteErr  map[int]error
	refuseList int

	stop chan struct{}
	done chan struct{}
}

type fakeStoredSMS struct {
	status int
	pduHex string
}

func newFakeSMSStorage(mem1, mem2, mem3 string) *fakeSMSStorage {
	return &fakeSMSStorage{
		memories:  [3]string{mem1, mem2, mem3},
		slots:     map[string]map[int]fakeStoredSMS{},
		deleteErr: map[int]error{},
	}
}

func (s *fakeSMSStorage) put(storage string, index, status int, pduHex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.slots[storage] == nil {
		s.slots[storage] = map[int]fakeStoredSMS{}
	}
	s.slots[storage][index] = fakeStoredSMS{status: status, pduHex: pduHex}
}

func (s *fakeSMSStorage) failDelete(index int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.deleteErr, index)
		return
	}
	s.deleteErr[index] = err
}

func (s *fakeSMSStorage) indexes(storage string) []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, 0, len(s.slots[storage]))
	for index := range s.slots[storage] {
		out = append(out, index)
	}
	sort.Ints(out)
	return out
}

func (s *fakeSMSStorage) commandLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

func (s *fakeSMSStorage) currentMemories() [3]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memories
}

// serve answers the manager's commands until the test ends.
func (s *fakeSMSStorage) serve(t *testing.T, m *Manager) {
	t.Helper()
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		for {
			select {
			case <-s.stop:
				return
			case req := <-m.cmdChan:
				resp, err := s.answer(req.cmd)
				if err != nil {
					req.errChan <- err
				} else {
					req.respChan <- resp
				}
			}
		}
	}()
	t.Cleanup(func() {
		close(s.stop)
		<-s.done
	})
}

func (s *fakeSMSStorage) answer(cmd string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, cmd)

	switch {
	case cmd == "AT+CPMS?":
		fields := make([]string, 0, 9)
		for _, memory := range s.memories {
			fields = append(fields, strconv.Quote(memory), strconv.Itoa(len(s.slots[memory])), "255")
		}
		return "\r\n+CPMS: " + strings.Join(fields, ",") + "\r\n\r\nOK\r\n", nil

	case strings.HasPrefix(cmd, "AT+CPMS="):
		names := strings.Split(strings.TrimPrefix(cmd, "AT+CPMS="), ",")
		for i := 0; i < len(names) && i < 3; i++ {
			s.memories[i] = strings.Trim(names[i], `"`)
		}
		return "OK", nil

	case cmd == "AT+CMGF=0":
		return "OK", nil

	case cmd == "AT+CMGL=4":
		if s.refuseList > 0 {
			s.refuseList--
			return "", errors.New("+CMS ERROR: 302")
		}
		slots := s.slots[s.memories[0]]
		indexes := make([]int, 0, len(slots))
		for index := range slots {
			indexes = append(indexes, index)
		}
		sort.Ints(indexes)
		var resp strings.Builder
		for _, index := range indexes {
			entry := slots[index]
			fmt.Fprintf(&resp, "\r\n+CMGL: %d,%d,,%d\r\n%s", index, entry.status, fakeTPDULength(entry.pduHex), entry.pduHex)
			if entry.status == smsStatusReceivedUnread {
				entry.status = smsStatusReceivedRead
				slots[index] = entry
			}
		}
		resp.WriteString("\r\n\r\nOK\r\n")
		return resp.String(), nil

	case strings.HasPrefix(cmd, "AT+CMGR="):
		index, err := strconv.Atoi(strings.TrimPrefix(cmd, "AT+CMGR="))
		if err != nil {
			return "", errors.New("+CMS ERROR: 321")
		}
		slots := s.slots[s.memories[0]]
		entry, ok := slots[index]
		if !ok {
			return "\r\nOK\r\n", nil
		}
		resp := fmt.Sprintf("\r\n+CMGR: %d,,%d\r\n%s\r\n\r\nOK\r\n", entry.status, fakeTPDULength(entry.pduHex), entry.pduHex)
		if entry.status == smsStatusReceivedUnread {
			entry.status = smsStatusReceivedRead
			slots[index] = entry
		}
		return resp, nil

	case strings.HasPrefix(cmd, "AT+CMGD="):
		index, err := strconv.Atoi(strings.TrimPrefix(cmd, "AT+CMGD="))
		if err != nil {
			return "", errors.New("+CMS ERROR: 321")
		}
		if err := s.deleteErr[index]; err != nil {
			return "", err
		}
		delete(s.slots[s.memories[0]], index)
		return "OK", nil
	}
	return "", fmt.Errorf("unexpected command %q", cmd)
}

// fakeTPDULength is the <length> a modem prints for a stored PDU: the number
// of TPDU octets, without the service centre address.
func fakeTPDULength(pduHex string) int {
	raw, err := hex.DecodeString(pduHex)
	if err != nil || len(raw) == 0 {
		return 0
	}
	return len(raw) - 1 - int(raw[0])
}

var inboxTestTime = time.Date(2026, 3, 9, 8, 30, 15, 0, time.UTC)

// deliverPDUs returns the PDU-mode hex strings of one message as a service
// centre delivers it, one for each part.
func deliverPDUs(t *testing.T, from, text string, reference int) []string {
	t.Helper()
	parts, err := smssim.Deliver(smssim.Message{From: from, Text: text, Time: inboxTestTime, Reference: reference})
	if err != nil {
		t.Fatalf("smssim.Deliver() error = %v", err)
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		pduHex, err := smssim.PDUHex("+7654321", part)
		if err != nil {
			t.Fatalf("smssim.PDUHex() error = %v", err)
		}
		out = append(out, pduHex)
	}
	return out
}

func deliverPDU(t *testing.T, from, text string) string {
	t.Helper()
	parts := deliverPDUs(t, from, text, 1)
	if len(parts) != 1 {
		t.Fatalf("%q needs %d parts, want 1", text, len(parts))
	}
	return parts[0]
}

func tpduOf(t *testing.T, pduHex string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(pduHex)
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}
	tpdu, err := smscodec.TPDUFromPDU(raw)
	if err != nil {
		t.Fatalf("TPDUFromPDU() error = %v", err)
	}
	return tpdu
}

// recordingSink is an IncomingSMSSink that decodes what it is given.
type recordingSink struct {
	mu     sync.Mutex
	texts  []string
	reject func(text string) error
}

func (s *recordingSink) take(tpdu []byte) error {
	_, text, _, _, err := smscodec.DecodeDeliverTPDU(tpdu)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reject != nil {
		if err := s.reject(text); err != nil {
			return err
		}
	}
	s.texts = append(s.texts, text)
	return nil
}

func (s *recordingSink) taken() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]string(nil), s.texts...)
	sort.Strings(out)
	return out
}

func (s *recordingSink) rejectWith(reject func(text string) error) {
	s.mu.Lock()
	s.reject = reject
	s.mu.Unlock()
}

// recordingCallback collects what the manager reports through SetSMSCallback.
type recordingCallback struct {
	mu       sync.Mutex
	messages []string
}

func (c *recordingCallback) report(sender, content string, _ time.Time) {
	c.mu.Lock()
	c.messages = append(c.messages, sender+": "+content)
	c.mu.Unlock()
}

func (c *recordingCallback) reported() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.messages...)
}

func drain(t *testing.T, m *Manager) int {
	t.Helper()
	type result struct {
		handled int
		err     error
	}
	done := make(chan result, 1)
	go func() {
		handled, err := m.DrainStoredSMS()
		done <- result{handled, err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("DrainStoredSMS() error = %v", got.err)
		}
		return got.handled
	case <-time.After(5 * time.Second):
		t.Fatal("DrainStoredSMS() did not return")
		return 0
	}
}

func TestParseCMGLEntriesReadsIndexStatusAndPDU(t *testing.T) {
	first := deliverPDU(t, "10086", "first")
	second := deliverPDU(t, "+12025550123", "second")
	sent := deliverPDU(t, "10086", "kept draft")

	paddedRaw, err := hex.DecodeString(second)
	if err != nil {
		t.Fatal(err)
	}
	padded := strings.ToUpper(hex.EncodeToString(smssim.PadSlot(paddedRaw, 176)))

	resp := "\r\n" +
		fmt.Sprintf("+CMGL: 3,0,,%d\r\n%s\r\n", fakeTPDULength(first), first) +
		fmt.Sprintf("+CMGL: 7,1,\"Doe, John\",%d\r\n%s\r\n", fakeTPDULength(second), padded) +
		fmt.Sprintf("+CMGL: 12,3,,%d\r\n%s\r\n", fakeTPDULength(sent), sent) +
		fmt.Sprintf("+CMGL: x,1,,%d\r\n%s\r\n", fakeTPDULength(first), first) +
		"+CMGL: 14,1,,20\r\n" +
		"\r\nOK\r\n"

	got := parseCMGLEntries(resp)
	want := []StoredSMS{
		{Index: 3, Status: 0, PDUHex: first},
		{Index: 7, Status: 1, PDUHex: second},
		{Index: 12, Status: 3, PDUHex: sent},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCMGLEntries() = %#v\nwant %#v", got, want)
	}
	if !got[0].Received() || !got[1].Received() || got[2].Received() {
		t.Fatalf("Received() = %v, %v, %v, want true, true, false", got[0].Received(), got[1].Received(), got[2].Received())
	}
	if entries := parseCMGLEntries("\r\nOK\r\n"); len(entries) != 0 {
		t.Fatalf("empty storage parsed as %#v", entries)
	}
}

func TestParseCPMSUsage(t *testing.T) {
	got := parseCPMSUsage("\r\n+CPMS: \"SM\",2,10,\"SM\",2,10,\"ME\",5,255\r\n\r\nOK\r\n")
	want := []smsStorageUsage{
		{name: "SM", used: 2, usedKnown: true},
		{name: "SM", used: 2, usedKnown: true},
		{name: "ME", used: 5, usedKnown: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCPMSUsage() = %#v, want %#v", got, want)
	}

	got = parseCPMSUsage("+CPMS: \"SM\",?,10,\"SM\",2,10,\"ME\",5,255")
	if len(got) != 3 || got[0].usedKnown || !got[2].usedKnown {
		t.Fatalf("unreadable counter parsed as %#v", got)
	}

	for _, resp := range []string{
		"OK",
		"+CPMS: \"SM\",2,10",
		"+CPMS: \"SM\",2,10,\"SM\",2,10",
		"+CPMS: \"S M\",2,10,\"SM\",2,10,\"ME\",5,255",
	} {
		if got := parseCPMSUsage(resp); got != nil {
			t.Fatalf("parseCPMSUsage(%q) = %#v, want nil", resp, got)
		}
	}
}

func TestDrainStoredSMSHandsReceivedMessagesToTheSinkAndDeletesThemByIndex(t *testing.T) {
	m := newRunningTestManager(t)
	storage := newFakeSMSStorage("ME", "ME", "ME")
	unread := deliverPDU(t, "10086", "unread message")
	read := deliverPDU(t, "+12025550123", "message that was read before")
	storage.put("ME", 3, smsStatusReceivedUnread, unread)
	storage.put("ME", 7, smsStatusReceivedRead, read)
	storage.put("ME", 12, 3, deliverPDU(t, "10086", "a sent message kept by the user"))
	storage.serve(t, m)

	var tpdus [][]byte
	sink := &recordingSink{}
	m.SetIncomingSMSSink(func(tpdu []byte) error {
		tpdus = append(tpdus, append([]byte(nil), tpdu...))
		return sink.take(tpdu)
	})

	if handled := drain(t, m); handled != 2 {
		t.Fatalf("handled = %d, want 2", handled)
	}
	if got, want := sink.taken(), []string{"message that was read before", "unread message"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sink received %q, want %q", got, want)
	}
	if len(tpdus) != 2 || !reflect.DeepEqual(tpdus[0], tpduOf(t, unread)) || !reflect.DeepEqual(tpdus[1], tpduOf(t, read)) {
		t.Fatal("sink did not receive the TPDUs without the service centre address")
	}
	if got, want := storage.indexes("ME"), []int{12}; !reflect.DeepEqual(got, want) {
		t.Fatalf("indexes left in the storage = %v, want %v", got, want)
	}
	wantCommands := []string{"AT+CPMS?", "AT+CMGL=4", "AT+CMGD=3", "AT+CMGD=7"}
	if got := storage.commandLog(); !reflect.DeepEqual(got, wantCommands) {
		t.Fatalf("commands = %q, want %q", got, wantCommands)
	}
}

func TestDrainStoredSMSKeepsWhatTheSinkCouldNotStore(t *testing.T) {
	m := newRunningTestManager(t)
	storage := newFakeSMSStorage("ME", "ME", "ME")
	storage.put("ME", 1, smsStatusReceivedUnread, deliverPDU(t, "10086", "stored at once"))
	storage.put("ME", 2, smsStatusReceivedUnread, deliverPDU(t, "10086", "database is down"))
	storage.serve(t, m)

	sink := &recordingSink{}
	sink.rejectWith(func(text string) error {
		if text == "database is down" {
			return errors.New("storage failure")
		}
		return nil
	})
	callback := &recordingCallback{}
	m.SetIncomingSMSSink(sink.take)
	m.SetSMSCallback(callback.report)

	if handled := drain(t, m); handled != 1 {
		t.Fatalf("handled = %d, want 1", handled)
	}
	if got, want := storage.indexes("ME"), []int{2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("indexes left after a failed store = %v, want %v", got, want)
	}

	// The next drain offers the message again; this time it can be stored.
	sink.rejectWith(nil)
	if handled := drain(t, m); handled != 1 {
		t.Fatalf("handled by the second drain = %d, want 1", handled)
	}
	if got := storage.indexes("ME"); len(got) != 0 {
		t.Fatalf("indexes left after the retry = %v, want none", got)
	}
	if got, want := sink.taken(), []string{"database is down", "stored at once"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sink received %q, want %q", got, want)
	}
	if got := callback.reported(); len(got) != 0 {
		t.Fatalf("callback reported %q although the sink handled every message", got)
	}
}

func TestDrainStoredSMSReadsTheReceiveStorageWhenItIsNotTheCurrentOne(t *testing.T) {
	m := newRunningTestManager(t)
	storage := newFakeSMSStorage("SM", "SM", "ME")
	storage.put("ME", 5, smsStatusReceivedUnread, deliverPDU(t, "10086", "waiting in the receive storage"))
	storage.serve(t, m)

	sink := &recordingSink{}
	m.SetIncomingSMSSink(sink.take)

	if handled := drain(t, m); handled != 1 {
		t.Fatalf("handled = %d, want 1", handled)
	}
	wantCommands := []string{
		"AT+CPMS?",
		`AT+CPMS="ME","ME","ME"`,
		"AT+CMGL=4",
		"AT+CMGD=5",
		`AT+CPMS="SM","SM","ME"`,
	}
	if got := storage.commandLog(); !reflect.DeepEqual(got, wantCommands) {
		t.Fatalf("commands = %q, want %q", got, wantCommands)
	}
	if got, want := storage.currentMemories(), [3]string{"SM", "SM", "ME"}; got != want {
		t.Fatalf("memories after the drain = %v, want %v", got, want)
	}
}

func TestDrainStoredSMSLeavesAnEmptyStorageAlone(t *testing.T) {
	m := newRunningTestManager(t)
	storage := newFakeSMSStorage("SM", "SM", "ME")
	storage.serve(t, m)
	m.SetIncomingSMSSink((&recordingSink{}).take)

	if handled := drain(t, m); handled != 0 {
		t.Fatalf("handled = %d, want 0", handled)
	}
	if got, want := storage.commandLog(), []string{"AT+CPMS?"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %q, want %q", got, want)
	}
}

func TestDrainStoredSMSWaitsWhileTheModemIsBusy(t *testing.T) {
	m := newRunningTestManager(t)
	storage := newFakeSMSStorage("ME", "ME", "ME")
	storage.put("ME", 1, smsStatusReceivedUnread, deliverPDU(t, "10086", "arrived during a send"))
	storage.serve(t, m)
	m.SetIncomingSMSSink((&recordingSink{}).take)

	m.SetBusy(true)
	if handled := drain(t, m); handled != 0 {
		t.Fatalf("handled while busy = %d, want 0", handled)
	}
	if got := storage.commandLog(); len(got) != 0 {
		t.Fatalf("commands while busy = %q, want none", got)
	}

	m.SetBusy(false)
	if handled := drain(t, m); handled != 1 {
		t.Fatalf("handled after the modem became free = %d, want 1", handled)
	}
}

func TestDrainStoredSMSFallsBackToTheCallbackOnce(t *testing.T) {
	m := newRunningTestManager(t)
	storage := newFakeSMSStorage("ME", "ME", "ME")
	storage.put("ME", 4, smsStatusReceivedUnread, deliverPDU(t, "10086", "not taken by the sink"))
	storage.failDelete(4, errors.New("+CMS ERROR: 500"))
	storage.serve(t, m)

	callback := &recordingCallback{}
	var sinkMu sync.Mutex
	offered, sinkTakes := 0, false
	m.SetIncomingSMSSink(func([]byte) error {
		sinkMu.Lock()
		defer sinkMu.Unlock()
		offered++
		if sinkTakes {
			return nil
		}
		return ErrIncomingSMSNotTaken
	})
	m.SetSMSCallback(callback.report)

	if handled := drain(t, m); handled != 0 {
		t.Fatalf("handled although the delete failed = %d, want 0", handled)
	}
	want := []string{"10086: not taken by the sink"}
	if got := callback.reported(); !reflect.DeepEqual(got, want) {
		t.Fatalf("callback reported %q, want %q", got, want)
	}

	// The message is still in the storage. It must not be reported again, and
	// it must not be offered to a sink that would now store and announce it;
	// only the delete is repeated.
	sinkMu.Lock()
	sinkTakes = true
	sinkMu.Unlock()
	storage.failDelete(4, nil)
	if handled := drain(t, m); handled != 1 {
		t.Fatalf("handled by the second drain = %d, want 1", handled)
	}
	if got := callback.reported(); !reflect.DeepEqual(got, want) {
		t.Fatalf("callback reported %q after the retry, want %q", got, want)
	}
	sinkMu.Lock()
	offeredTotal := offered
	sinkMu.Unlock()
	if offeredTotal != 1 {
		t.Fatalf("the sink was offered the message %d times, want 1", offeredTotal)
	}
	if got := storage.indexes("ME"); len(got) != 0 {
		t.Fatalf("indexes left = %v, want none", got)
	}
}

func TestDrainStoredSMSReassemblesLongMessagesInMemoryWithoutASink(t *testing.T) {
	m := newRunningTestManager(t)
	storage := newFakeSMSStorage("ME", "ME", "ME")
	text := strings.Repeat("long message without a database ", 12)
	parts := deliverPDUs(t, "10086", text, 0x21)
	if len(parts) != 3 {
		t.Fatalf("fixture has %d parts, want 3", len(parts))
	}
	// Stored out of order, as parts arrive.
	storage.put("ME", 1, smsStatusReceivedUnread, parts[2])
	storage.put("ME", 2, smsStatusReceivedUnread, parts[0])
	storage.put("ME", 3, smsStatusReceivedUnread, parts[1])
	storage.serve(t, m)

	callback := &recordingCallback{}
	m.SetSMSCallback(callback.report)

	if handled := drain(t, m); handled != 3 {
		t.Fatalf("handled = %d, want 3", handled)
	}
	if got, want := callback.reported(), []string{"10086: " + text}; !reflect.DeepEqual(got, want) {
		t.Fatalf("callback reported %q, want the complete text once", got)
	}
	if got := storage.indexes("ME"); len(got) != 0 {
		t.Fatalf("indexes left = %v, want none", got)
	}
}

func TestListStoredSMSSelectsPDUModeWhenListingIsRefused(t *testing.T) {
	m := newRunningTestManager(t)
	storage := newFakeSMSStorage("ME", "ME", "ME")
	pdu := deliverPDU(t, "10086", "listed after selecting PDU mode")
	storage.put("ME", 9, smsStatusReceivedRead, pdu)
	storage.refuseList = 1
	storage.serve(t, m)

	entries, err := m.ListStoredSMS()
	if err != nil {
		t.Fatalf("ListStoredSMS() error = %v", err)
	}
	if want := []StoredSMS{{Index: 9, Status: smsStatusReceivedRead, PDUHex: pdu}}; !reflect.DeepEqual(entries, want) {
		t.Fatalf("ListStoredSMS() = %#v, want %#v", entries, want)
	}
	if got, want := storage.commandLog(), []string{"AT+CMGL=4", "AT+CMGF=0", "AT+CMGL=4"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %q, want %q", got, want)
	}

	storage.refuseList = 2
	if _, err := m.ListStoredSMS(); err == nil {
		t.Fatal("ListStoredSMS() succeeded although the modem refused twice")
	}
}

func TestNewMessageIndicationKeepsTheMessageUntilItIsStored(t *testing.T) {
	m := newRunningTestManager(t)
	storage := newFakeSMSStorage("ME", "ME", "ME")
	storage.put("ME", 7, smsStatusReceivedUnread, deliverPDU(t, "10086", "arrived while the database was locked"))
	storage.serve(t, m)

	offered := make(chan struct{}, 4)
	sink := &recordingSink{}
	sink.rejectWith(func(string) error { return errors.New("database is locked") })
	m.SetIncomingSMSSink(func(tpdu []byte) error {
		err := sink.take(tpdu)
		offered <- struct{}{}
		return err
	})

	m.handleURC(`+CMTI: "ME",7`)
	select {
	case <-offered:
	case <-time.After(5 * time.Second):
		t.Fatal("the indicated message was not offered to the sink")
	}
	// The read holds the inbox lock until it has finished.
	m.smsInboxMu.Lock()
	m.smsInboxMu.Unlock()

	if got, want := storage.commandLog(), []string{"AT+CPMS?", "AT+CMGR=7"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %q, want %q (no delete)", got, want)
	}
	if got, want := storage.indexes("ME"), []int{7}; !reflect.DeepEqual(got, want) {
		t.Fatalf("indexes left = %v, want %v", got, want)
	}

	sink.rejectWith(nil)
	if handled := drain(t, m); handled != 1 {
		t.Fatalf("handled by the drain = %d, want 1", handled)
	}
	if got, want := sink.taken(), []string{"arrived while the database was locked"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sink received %q, want %q", got, want)
	}
	if got := storage.indexes("ME"); len(got) != 0 {
		t.Fatalf("indexes left after the drain = %v, want none", got)
	}
}

// A burst of new-message indications races with the periodic drain. Every
// message has to reach the sink exactly once, and the storage selection has to
// be what it was before.
func TestIndicatedReadsAndDrainsDoNotInterleave(t *testing.T) {
	m := newRunningTestManager(t)
	storage := newFakeSMSStorage("SM", "SM", "ME")
	const messages = 40
	want := make([]string, 0, messages)
	for i := 1; i <= messages; i++ {
		text := fmt.Sprintf("burst message %02d", i)
		want = append(want, text)
		storage.put("ME", i, smsStatusReceivedUnread, deliverPDU(t, "10086", text))
	}
	storage.serve(t, m)

	sink := &recordingSink{}
	m.SetIncomingSMSSink(sink.take)

	var wg sync.WaitGroup
	for i := 1; i <= messages; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			m.ReadAndProcessSMSFromStorage("ME", strconv.Itoa(index))
		}(i)
		if i%10 == 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := m.DrainStoredSMS(); err != nil {
					t.Errorf("DrainStoredSMS() error = %v", err)
				}
			}()
		}
	}
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(20 * time.Second):
		t.Fatal("reads and drains did not finish")
	}

	sort.Strings(want)
	if got := sink.taken(); !reflect.DeepEqual(got, want) {
		t.Fatalf("sink received %d messages %q, want each of the %d exactly once", len(got), got, messages)
	}
	if got := storage.indexes("ME"); len(got) != 0 {
		t.Fatalf("indexes left = %v, want none", got)
	}
	if got, wantMemories := storage.currentMemories(), [3]string{"SM", "SM", "ME"}; got != wantMemories {
		t.Fatalf("memories afterwards = %v, want %v", got, wantMemories)
	}
}
