package modem

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/simulation/atsim"
	"github.com/1239t/vohive/internal/simulation/smssim"
	"github.com/1239t/vohive/pkg/smscodec"
)

// These tests run the real manager against a simulated modem: every byte goes
// through the serial read loop, the command queue and the answer parser, as it
// does with hardware.

// startManagerOnSimulatedModem starts a manager on the simulated modem and
// waits until it has set the modem up and collected its identity.
func startManagerOnSimulatedModem(t *testing.T, sim *atsim.Modem) *Manager {
	t.Helper()
	name := virtualPortTestName()
	t.Cleanup(RegisterVirtualSerialPort(name, sim.Open))

	m, err := New(config.DeviceConfig{ID: "dev-atsim", DeviceBackend: "at", ATPort: name})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { m.StopAndWait(2 * time.Second) })
	if !m.WaitReady(5 * time.Second) {
		t.Fatal("the manager did not finish its setup commands")
	}
	// The identity is collected after the setup commands, in one pass that
	// stores everything at its end.
	waitForSimulation(t, "the identity of the modem to be collected", func() bool { return m.GetAPN() != "" })
	return m
}

func waitForSimulation(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("gave up waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// simStateLog collects the SIM state changes a manager reports.
type simStateLog struct {
	mu     sync.Mutex
	states []string
}

func (l *simStateLog) add(_ *bool, state string) {
	l.mu.Lock()
	l.states = append(l.states, state)
	l.mu.Unlock()
}

func (l *simStateLog) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.states...)
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// settle gives handlers that run on their own goroutines time to be called.
func settle() { time.Sleep(100 * time.Millisecond) }

func TestManagerSetsUpASimulatedModemAndReadsItsIdentity(t *testing.T) {
	profile := atsim.DefaultProfile()
	sim := atsim.New(profile)
	m := startManagerOnSimulatedModem(t, sim)

	for _, command := range []string{"ATE0", "AT+CMGF=0", "AT+CNMI=2,1,0,0,0", "AT+CLIP=1", "AT+QPCMV=1,2"} {
		if sim.Count(command) == 0 {
			t.Errorf("the setup command %s was not sent", command)
		}
	}
	settings := sim.Settings()
	if settings.Echo || !settings.PDUMode || settings.NewMessageIndication != "2,1,0,0,0" || !settings.CallerID {
		t.Fatalf("the modem was left with the settings %+v", settings)
	}

	if got := m.GetIMEI(); got != profile.IMEI {
		t.Errorf("GetIMEI() = %q, want %q", got, profile.IMEI)
	}
	if got := m.GetFirmware(); got != profile.Firmware {
		t.Errorf("GetFirmware() = %q, want %q", got, profile.Firmware)
	}
	if got := m.GetIMSI(); got != profile.IMSI {
		t.Errorf("GetIMSI() = %q, want %q", got, profile.IMSI)
	}
	if got := m.GetICCID(); got != profile.ICCID {
		t.Errorf("GetICCID() = %q, want %q", got, profile.ICCID)
	}
	if !m.IsSimInserted() {
		t.Error("IsSimInserted() = false with a SIM in the modem")
	}
	if got := m.GetOperator(); got != profile.PLMN {
		t.Errorf("GetOperator() = %q, want %q", got, profile.PLMN)
	}
	if status, _ := m.GetRegStatus(); status != atsim.RegisteredHome {
		t.Errorf("GetRegStatus() = %d, want %d", status, atsim.RegisteredHome)
	}
	if got := m.GetSignalDBM(); got != -73 {
		t.Errorf("GetSignalDBM() = %d, want -73 for a signal quality of 20", got)
	}
	if rsrp, rsrq := m.GetSignalLTE(); rsrp != -80 || rsrq != -10 {
		t.Errorf("GetSignalLTE() = %d, %d, want -80, -10", rsrp, rsrq)
	}
	if got := m.GetAPN(); got != profile.APN {
		t.Errorf("GetAPN() = %q, want %q", got, profile.APN)
	}
	if got := m.GetIMSStatus(); got != 1 {
		t.Errorf("GetIMSStatus() = %d, want 1", got)
	}
	if got, err := m.QuerySMSC(); err != nil || got != profile.ServiceCentre {
		t.Errorf("QuerySMSC() = %q, %v, want %q", got, err, profile.ServiceCentre)
	}
}

func TestAnAnswerToAStatusQueryIsNotAnEvent(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)

	// Collecting the identity already found the SIM ready.
	var states simStateLog
	m.SetSIMStatusHandler(states.add)
	ready := m.SubscribeRDY()

	for i := 0; i < 5; i++ {
		inserted, err := m.QuerySIMInserted()
		if err != nil || !inserted {
			t.Fatalf("QuerySIMInserted() = %v, %v, want true", inserted, err)
		}
	}
	settle()

	if isClosed(ready) {
		t.Error("finding the SIM ready, as it was before, was reported as the modem having started")
	}
	if got := states.seen(); len(got) != 0 {
		t.Errorf("the answers were reported as SIM state changes: %q", got)
	}
	if got := sim.Count("AT+QSIMSTAT"); got != 0 {
		t.Errorf("the tray detection was queried %d times, its answer is not used", got)
	}
}

func TestASIMStateThatChangesBetweenAnswersIsReportedOnce(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)
	var states simStateLog
	m.SetSIMStatusHandler(states.add)

	// The SIM goes away and the modem announces nothing: only the answers
	// to the query tell.
	remove := sim.AddRule(atsim.Rule{Prefix: "AT+CPIN?", Result: "OK", URC: "+CPIN: NOT INSERTED"})
	for i := 0; i < 3; i++ {
		inserted, err := m.QuerySIMInserted()
		if err != nil || inserted {
			t.Fatalf("QuerySIMInserted() = %v, %v, want false", inserted, err)
		}
	}
	settle()
	if got := states.seen(); len(got) != 1 || got[0] != "NOT INSERTED" {
		t.Fatalf("SIM state changes = %q, want the removal reported once", got)
	}

	// It comes back, again without an announcement.
	remove()
	ready := m.SubscribeRDY()
	if inserted, err := m.QuerySIMInserted(); err != nil || !inserted {
		t.Fatalf("QuerySIMInserted() = %v, %v, want true", inserted, err)
	}
	waitForSimulation(t, "the SIM becoming ready to be reported", func() bool { return isClosed(ready) })

	again := m.SubscribeRDY()
	for i := 0; i < 3; i++ {
		if inserted, err := m.QuerySIMInserted(); err != nil || !inserted {
			t.Fatalf("QuerySIMInserted() = %v, %v, want true", inserted, err)
		}
	}
	settle()
	if isClosed(again) {
		t.Error("the SIM being ready was reported a second time")
	}
	if got := states.seen(); len(got) != 2 || got[1] != "READY" {
		t.Errorf("SIM state changes = %q, want the removal and the return", got)
	}
}

func TestARefusedSIMQueryIsNotAnEventButTheNextReadyAnswerIs(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)
	var states simStateLog
	m.SetSIMStatusHandler(states.add)

	remove := sim.AddRule(atsim.Rule{Prefix: "AT+CPIN?", Result: "+CME ERROR: 10"})
	for i := 0; i < 3; i++ {
		if inserted, err := m.QuerySIMInserted(); err == nil || inserted {
			t.Fatalf("QuerySIMInserted() = %v, %v, want the refusal", inserted, err)
		}
	}
	settle()
	if got := states.seen(); len(got) != 0 {
		t.Fatalf("a refused query was reported as SIM state changes: %q", got)
	}

	remove()
	ready := m.SubscribeRDY()
	if inserted, err := m.QuerySIMInserted(); err != nil || !inserted {
		t.Fatalf("QuerySIMInserted() = %v, %v, want true", inserted, err)
	}
	waitForSimulation(t, "the SIM becoming ready to be reported", func() bool { return isClosed(ready) })
}

func TestWhatTheModemAnnouncesAboutTheSIMIsReportedEveryTime(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)
	var states simStateLog
	m.SetSIMStatusHandler(states.add)

	sim.RemoveSIM()
	waitForSimulation(t, "the removal to be reported", func() bool { return len(states.seen()) == 1 })
	if got := states.seen(); got[0] != "NOT INSERTED" {
		t.Fatalf("SIM state changes = %q", got)
	}
	if inserted, err := m.QuerySIMInserted(); err == nil || inserted {
		t.Fatalf("QuerySIMInserted() = %v, %v, want the modem to refuse without a SIM", inserted, err)
	}

	ready := m.SubscribeRDY()
	sim.InsertSIM()
	waitForSimulation(t, "the SIM becoming ready to be reported", func() bool { return isClosed(ready) })
	waitForSimulation(t, "the insertion to be reported", func() bool { return len(states.seen()) == 2 })

	// The modem saying so again is an announcement again.
	again := m.SubscribeRDY()
	sim.URC("+CPIN: READY")
	waitForSimulation(t, "the second announcement to be reported", func() bool { return isClosed(again) })
}

func TestAnswersQueryCommandTellsAnswersFromAnnouncements(t *testing.T) {
	cases := []struct {
		command string
		line    string
		want    bool
	}{
		{"AT+CPIN?", "+CPIN: READY", true},
		{"at+cpin?", "+CPIN: READY", true},
		{"AT+QSIMSTAT?", "+QSIMSTAT: 0,1", true},
		{"AT+QPCMV?", "+QPCMV: 1,2", true},
		{"AT+CUSD=?", "+CUSD: (0-2)", true},
		{"AT+CPIN?", `+CMTI: "ME",3`, false},
		{"AT+CPIN?", "RING", false},
		// What follows a command that sets or does something is an announcement.
		{`AT+CUSD=1,"*100#",15`, `+CUSD: 2,"Balance",15`, false},
		{"AT+QPCMV=1,2", "+QPCMV: 1", false},
		{"AT+CSQ", "+CSQ: 20,99", false},
		// A query that names a setting is left to the old rules.
		{`AT+QCFG="USBCFG"?`, `+QCFG: "usbcfg",0x2C7C`, false},
		{"AT?", "+CPIN: READY", false},
		{"", "+CPIN: READY", false},
	}
	for _, tc := range cases {
		if got := answersQueryCommand(tc.command, tc.line); got != tc.want {
			t.Errorf("answersQueryCommand(%q, %q) = %v, want %v", tc.command, tc.line, got, tc.want)
		}
	}
}

func TestAnAnnouncementInsideAnAnswerIsDispatchedAndKeptOutOfTheAnswer(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)
	indexes := make(chan string, 1)
	m.SetNewSMSHandler(func(index string) { indexes <- index })

	sim.AddRule(atsim.Rule{Prefix: "AT+CSQ", Times: 1, URC: `+CMTI: "ME",7`})
	answer, err := m.ExecuteAT("AT+CSQ", 2*time.Second)
	if err != nil {
		t.Fatalf("ExecuteAT() error = %v", err)
	}
	if answer != "+CSQ: 20,99" {
		t.Errorf("ExecuteAT() = %q, want only the answer to the command", answer)
	}
	select {
	case got := <-indexes:
		if got != "7" {
			t.Errorf("the new message was announced at index %q, want 7", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the new message announced in the middle of the answer was lost")
	}
}

// receivedMessages collects what the manager hands to its message callback.
type receivedMessages struct {
	mu   sync.Mutex
	list []string
}

func (r *receivedMessages) add(sender, content string, _ time.Time) {
	r.mu.Lock()
	r.list = append(r.list, sender+"|"+content)
	r.mu.Unlock()
}

func (r *receivedMessages) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.list...)
}

func deliverToSimulatedModem(t *testing.T, sim *atsim.Modem, msg smssim.Message) {
	t.Helper()
	tpdus, err := smssim.Deliver(msg)
	if err != nil {
		t.Fatalf("smssim.Deliver() error = %v", err)
	}
	for _, tpdu := range tpdus {
		if _, err := sim.DeliverSMS(tpdu); err != nil {
			t.Fatalf("DeliverSMS() error = %v", err)
		}
	}
}

func TestManagerReadsAMessageTheModemAnnouncesAndDeletesIt(t *testing.T) {
	for _, first := range []int{0, 1} {
		profile := atsim.DefaultProfile()
		profile.FirstSMSIndex = first
		sim := atsim.New(profile)
		m := startManagerOnSimulatedModem(t, sim)
		var received receivedMessages
		m.SetSMSCallback(received.add)

		deliverToSimulatedModem(t, sim, smssim.Message{
			From: "+15555550142",
			Text: "Your code is 482913",
			Time: time.Date(2026, 3, 9, 8, 30, 15, 0, time.UTC),
		})

		waitForSimulation(t, "the message to be handed over", func() bool { return len(received.seen()) == 1 })
		if got := received.seen()[0]; got != "+15555550142|Your code is 482913" {
			t.Errorf("received %q", got)
		}
		waitForSimulation(t, "the message to be deleted from the modem", func() bool { return len(sim.StoredSMS("ME")) == 0 })
	}
}

func TestManagerPutsTogetherALongMessageTheModemAnnouncesInParts(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)
	var received receivedMessages
	m.SetSMSCallback(received.add)

	text := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 8)
	deliverToSimulatedModem(t, sim, smssim.Message{
		From:      "+15555550142",
		Text:      text,
		Time:      time.Date(2026, 3, 9, 8, 30, 15, 0, time.UTC),
		Reference: 77,
	})

	waitForSimulation(t, "the message to be handed over", func() bool { return len(received.seen()) >= 1 })
	waitForSimulation(t, "the parts to be deleted from the modem", func() bool { return len(sim.StoredSMS("ME")) == 0 })
	settle()
	got := received.seen()
	if len(got) != 1 || got[0] != "+15555550142|"+text {
		t.Fatalf("received %d messages: %q", len(got), got)
	}
	if reads := sim.Count("AT+CMGR="); reads < 3 {
		t.Errorf("%d parts were read, want a message of at least three parts", reads)
	}
}

func TestManagerCollectsTheMessagesThatWereStoredWhileNobodyListened(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	for _, text := range []string{"first", "second", "third"} {
		tpdus, err := smssim.Deliver(smssim.Message{From: "+15555550142", Text: text, Time: time.Date(2026, 3, 9, 8, 30, 15, 0, time.UTC)})
		if err != nil {
			t.Fatalf("smssim.Deliver() error = %v", err)
		}
		if _, err := sim.StoreSMS("ME", atsim.ReceivedUnread, tpdus[0]); err != nil {
			t.Fatalf("StoreSMS() error = %v", err)
		}
	}
	m := startManagerOnSimulatedModem(t, sim)
	var received receivedMessages
	m.SetSMSCallback(received.add)

	handled, err := m.DrainStoredSMS()
	if err != nil || handled != 3 {
		t.Fatalf("DrainStoredSMS() = %d, %v, want 3", handled, err)
	}
	if got := strings.Join(received.seen(), ";"); got != "+15555550142|first;+15555550142|second;+15555550142|third" {
		t.Errorf("received %q", got)
	}
	if left := sim.StoredSMS("ME"); len(left) != 0 {
		t.Errorf("%d messages were left in the modem", len(left))
	}
}

func TestManagerSendsAMessageThroughTheSimulatedModem(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)

	submission, err := smscodec.PrepareSubmission("+15555550142", "hello", smscodec.SubmitOptions{})
	if err != nil {
		t.Fatalf("PrepareSubmission() error = %v", err)
	}
	if err := m.SendPreparedSMS(submission); err != nil {
		t.Fatalf("SendPreparedSMS() error = %v", err)
	}
	sent := sim.SentSMS()
	if len(sent) != 1 || string(sent[0].TPDU) != string(submission.TPDU(0)) {
		t.Fatalf("the modem sent %d messages, want the one that was submitted", len(sent))
	}

	// A long text goes out as several parts, each with its own prompt.
	long, err := smscodec.PrepareSubmission("+15555550142", strings.Repeat("0123456789", 40), smscodec.SubmitOptions{})
	if err != nil {
		t.Fatalf("PrepareSubmission() error = %v", err)
	}
	if long.PartCount() < 3 {
		t.Fatalf("PartCount() = %d, want a message of at least three parts", long.PartCount())
	}
	if err := m.SendPreparedSMS(long); err != nil {
		t.Fatalf("SendPreparedSMS() error = %v", err)
	}
	sent = sim.SentSMS()
	if len(sent) != 1+long.PartCount() {
		t.Fatalf("the modem sent %d messages, want %d", len(sent), 1+long.PartCount())
	}
	for i := 0; i < long.PartCount(); i++ {
		if string(sent[1+i].TPDU) != string(long.TPDU(i)) {
			t.Errorf("part %d was not sent as it was submitted", i+1)
		}
	}
}

func TestManagerReportsAMessageTheNetworkRefusesAndCarriesOn(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)
	submission, err := smscodec.PrepareSubmission("+15555550142", "hello", smscodec.SubmitOptions{})
	if err != nil {
		t.Fatalf("PrepareSubmission() error = %v", err)
	}

	sim.AddRule(atsim.Rule{Prefix: "AT+CMGS", Times: 1, Result: "+CMS ERROR: 38"})
	if err := m.SendPreparedSMS(submission); err == nil || !strings.Contains(err.Error(), "+CMS ERROR: 38") {
		t.Fatalf("SendPreparedSMS() error = %v, want the refusal of the network", err)
	}
	if got := len(sim.SentSMS()); got != 0 {
		t.Fatalf("%d messages were sent although the network refused", got)
	}

	if !m.IsHealthy() {
		t.Fatal("a refused message left the manager unhealthy")
	}
	if err := m.SendPreparedSMS(submission); err != nil {
		t.Fatalf("SendPreparedSMS() after the refusal error = %v", err)
	}
	if got := len(sim.SentSMS()); got != 1 {
		t.Fatalf("%d messages were sent, want 1", got)
	}
}

func TestManagerGivesUpOnAMessageTheNetworkNeverConfirms(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)
	submission, err := smscodec.PrepareSubmission("+15555550142", "hello", smscodec.SubmitOptions{})
	if err != nil {
		t.Fatalf("PrepareSubmission() error = %v", err)
	}
	tpduLen, pduHex := submission.ATPDU(0)
	if tpduLen != len(submission.TPDU(0)) {
		t.Fatalf("ATPDU() length = %d, want %d", tpduLen, len(submission.TPDU(0)))
	}

	// The same request SendPreparedSMS makes, with a wait short enough for a test.
	sim.AddRule(atsim.Rule{Prefix: "AT+CMGS", Times: 1, SilentAfterPrompt: true})
	req := commandRequest{
		requestID:      m.requestSeq.Add(1),
		cmd:            fmt.Sprintf("AT+CMGS=%d", tpduLen),
		respChan:       make(chan string, 1),
		errChan:        make(chan error, 1),
		timeout:        400 * time.Millisecond,
		highPriority:   true,
		interactive:    true,
		waitPrompt:     true,
		followUp:       pduHex + "\x1A",
		cancelSequence: []byte{0x1B},
	}
	m.cmdChanHigh <- req
	select {
	case answer := <-req.respChan:
		t.Fatalf("the request answered %q, want it to time out", answer)
	case err := <-req.errChan:
		if err == nil || !strings.Contains(err.Error(), "超时") {
			t.Fatalf("the request failed with %v, want a timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request neither answered nor failed")
	}

	// The answer may still arrive and would then be taken for the answer to
	// the next command, so the manager stops using the port until it is reopened.
	if m.IsHealthy() {
		t.Error("the manager still counts as healthy after a command without an answer")
	}
	if _, err := m.ExecuteAT("AT+CSQ", time.Second); err == nil {
		t.Error("a command was accepted on a port whose answers can no longer be trusted")
	}
}

func TestManagerRunsAUSSDRequestOnTheSimulatedModem(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)

	sim.SetUSSD(func(code string) (int, string) { return 2, "Balance for " + code + " is 12.50" })
	result, err := m.ExecuteUSSD("*100#", 3*time.Second)
	if err != nil {
		t.Fatalf("ExecuteUSSD() error = %v", err)
	}
	if result.Status != 2 || result.Text != "Balance for *100# is 12.50" || result.DCS != 15 {
		t.Fatalf("ExecuteUSSD() = %+v", *result)
	}

	// A network that never answers: the session is cancelled.
	sim.SetUSSD(nil)
	if _, err := m.ExecuteUSSD("*100#", 300*time.Millisecond); err == nil {
		t.Fatal("ExecuteUSSD() succeeded without an answer from the network")
	}
	if got := sim.Count("AT+CUSD=2"); got != 1 {
		t.Errorf("the session was cancelled %d times, want once", got)
	}
}

func TestManagerFollowsACallOnTheSimulatedModem(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)
	rings := make(chan struct{}, 4)
	numbers := make(chan string, 4)
	hangups := make(chan struct{}, 4)
	m.SetRingCallback(func() { rings <- struct{}{} })
	m.SetClipCallback(func(number string) { numbers <- number })
	m.SetHangupCallback(func() { hangups <- struct{}{} })

	sim.IncomingCall("+15555550142")
	select {
	case <-rings:
	case <-time.After(2 * time.Second):
		t.Fatal("the call did not ring")
	}
	select {
	case got := <-numbers:
		if got != "+15555550142" {
			t.Errorf("the caller was reported as %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the number of the caller was not reported")
	}
	if err := m.AnswerCall(); err != nil {
		t.Fatalf("AnswerCall() error = %v", err)
	}
	sim.EndCall()
	select {
	case <-hangups:
	case <-time.After(2 * time.Second):
		t.Fatal("the end of the call was not reported")
	}

	if err := m.DialCall("5550100"); err != nil {
		t.Fatalf("DialCall() error = %v", err)
	}
	if dialled := sim.Dialled(); len(dialled) != 1 || dialled[0] != "5550100" {
		t.Errorf("the modem dialled %q", dialled)
	}
	if err := m.HangupCall(); err != nil {
		t.Fatalf("HangupCall() error = %v", err)
	}
}

func TestManagerReportsAModemThatIsUnpluggedAndANewOneTakesOverWhenItIsBack(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)
	reasons := make(chan string, 4)
	m.SetOnDisconnectWithReason(func(reason string) { reasons <- reason })

	sim.Unplug()
	select {
	case reason := <-reasons:
		if reason != "serial_read_error" {
			t.Errorf("the disconnect was reported as %q", reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the unplugged modem was not reported")
	}
	if _, err := m.ExecuteAT("AT+CSQ", time.Second); err == nil {
		t.Error("a command succeeded on an unplugged modem")
	}
	m.StopAndWait(2 * time.Second)

	// While it is away the port cannot be opened.
	gone, err := New(config.DeviceConfig{ID: "dev-atsim", DeviceBackend: "at", ATPort: m.ATPort()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := gone.Start(); err == nil {
		gone.StopAndWait(2 * time.Second)
		t.Fatal("Start() succeeded on a port whose device is unplugged")
	}

	sim.Replug()
	back, err := New(config.DeviceConfig{ID: "dev-atsim", DeviceBackend: "at", ATPort: m.ATPort()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	started := back.SubscribeRDY()
	if err := back.Start(); err != nil {
		t.Fatalf("Start() after the modem came back error = %v", err)
	}
	t.Cleanup(func() { back.StopAndWait(2 * time.Second) })
	waitForSimulation(t, "the modem to announce that it has started", func() bool { return isClosed(started) })
	waitForSimulation(t, "the identity of the modem to be collected", func() bool { return back.GetIMEI() != "" })
	if !back.IsHealthy() {
		t.Error("the manager of the modem that came back is not healthy")
	}
}

func TestManagerStopsTrustingAModemThatHangs(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)

	sim.SetSilent(true)
	start := time.Now()
	if _, err := m.ExecuteAT("AT+CSQ", 300*time.Millisecond); err == nil {
		t.Fatal("ExecuteAT() succeeded on a modem that does not answer")
	}
	if waited := time.Since(start); waited < 250*time.Millisecond || waited > 3*time.Second {
		t.Errorf("ExecuteAT() gave up after %v, want its timeout of 300ms", waited)
	}
	if m.IsHealthy() {
		t.Error("the manager still counts as healthy after a command without an answer")
	}

	// Even when the modem wakes up, the port is not used again before it is reopened.
	sim.SetSilent(false)
	before := sim.Count("AT+CSQ")
	if _, err := m.ExecuteAT("AT+CSQ", time.Second); err == nil {
		t.Error("a command was accepted on a port whose answers can no longer be trusted")
	}
	if got := sim.Count("AT+CSQ"); got != before {
		t.Errorf("%d more commands reached the modem", got-before)
	}
}

func TestManagerKeepsAnswersApartWhenTheModemIsSlow(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	m := startManagerOnSimulatedModem(t, sim)
	sim.SetDelay(30 * time.Millisecond)

	var wg sync.WaitGroup
	failures := make(chan string, 64)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				if answer, err := m.ExecuteAT("AT+CSQ", 5*time.Second); err != nil || answer != "+CSQ: 20,99" {
					failures <- "AT+CSQ: " + answer
				}
				if answer, err := m.ExecuteAT("AT+CGSN", 5*time.Second); err != nil || answer != sim.Profile().IMEI {
					failures <- "AT+CGSN: " + answer
				}
			}
		}()
	}
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Errorf("a command got the answer of another one: %s", failure)
	}
}
