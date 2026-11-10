package atsim

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"go.bug.st/serial"
)

// An SMS-DELIVER and an SMS-SUBMIT. The modem does not look inside a TPDU, so
// their content does not matter here.
var (
	testDeliver = []byte{0x04, 0x04, 0x81, 0x21, 0x43, 0x00, 0x00, 0x62, 0x30, 0x90, 0x80, 0x03, 0x51, 0x00, 0x02, 0xC8, 0x34}
	testSubmit  = []byte{0x01, 0x00, 0x04, 0x81, 0x21, 0x43, 0x00, 0x00, 0x02, 0xC8, 0x34}
)

func openPort(t *testing.T, m *Modem) serial.Port {
	t.Helper()
	p, err := m.Open("sim", &serial.Mode{BaudRate: 115200})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := p.SetReadTimeout(20 * time.Millisecond); err != nil {
		t.Fatalf("SetReadTimeout() error = %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// quietModem returns a modem with the echo off and its port open.
func quietModem(t *testing.T, profile Profile) (*Modem, serial.Port) {
	t.Helper()
	m := New(profile)
	p := openPort(t, m)
	if got := exchange(t, p, "ATE0"); !strings.HasSuffix(got, "\r\nOK\r\n") {
		t.Fatalf("ATE0 answered %q", got)
	}
	return m, p
}

// readUntil reads until done accepts what has been read.
func readUntil(t *testing.T, p serial.Port, done func(string) bool) string {
	t.Helper()
	var got strings.Builder
	buf := make([]byte, 512)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, err := p.Read(buf)
		if err != nil {
			t.Fatalf("Read() error = %v after %q", err, got.String())
		}
		got.Write(buf[:n])
		if done(got.String()) {
			return got.String()
		}
	}
	t.Fatalf("gave up after three seconds, read %q", got.String())
	return ""
}

// finished reports whether the text ends with a final result.
func finished(text string) bool {
	if !strings.HasSuffix(text, "\r\n") {
		return false
	}
	lines := strings.Split(strings.TrimRight(text, "\r\n"), "\r\n")
	last := lines[len(lines)-1]
	return last == "OK" || last == "ERROR" || last == "NO CARRIER" ||
		strings.HasPrefix(last, "+CME ERROR:") || strings.HasPrefix(last, "+CMS ERROR:")
}

// exchange sends a command and returns its answer up to the final result.
func exchange(t *testing.T, p serial.Port, command string) string {
	t.Helper()
	if _, err := p.Write([]byte(command + "\r\n")); err != nil {
		t.Fatalf("Write(%q) error = %v", command, err)
	}
	return readUntil(t, p, finished)
}

// lines returns the non-empty lines of an answer.
func lines(answer string) []string {
	var out []string
	for _, line := range strings.Split(answer, "\r\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func wantLines(t *testing.T, command, answer string, want ...string) {
	t.Helper()
	got := lines(answer)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("%s answered %q, want %q", command, got, want)
	}
}

func TestReadReturnsNothingWhenTheTimeoutPasses(t *testing.T) {
	p := openPort(t, New(DefaultProfile()))
	start := time.Now()
	n, err := p.Read(make([]byte, 16))
	if n != 0 || err != nil {
		t.Fatalf("Read() = %d, %v, want 0, nil", n, err)
	}
	if waited := time.Since(start); waited < 15*time.Millisecond {
		t.Fatalf("Read() returned after %v, before the timeout of 20ms", waited)
	}
}

func TestCloseEndsAReadThatIsWaiting(t *testing.T) {
	m := New(DefaultProfile())
	p, err := m.Open("sim", nil)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := p.Read(make([]byte, 16))
		result <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := p.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-result:
		if err == nil || err.Error() != "Port has been closed" {
			t.Fatalf("Read() error = %v, want the port to be reported closed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the read kept waiting after Close")
	}
	if m.IsOpen() {
		t.Fatal("the modem still has a host after Close")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestThePortCanBeOpenedOnlyOnceAtATime(t *testing.T) {
	m := New(DefaultProfile())
	first, err := m.Open("sim", &serial.Mode{BaudRate: 9600, DataBits: 7})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := m.Open("sim", nil); err == nil || err.Error() != "Serial port busy" {
		t.Fatalf("second Open() error = %v, want the port to be busy", err)
	}
	if mode := m.Mode(); mode.BaudRate != 9600 || mode.DataBits != 7 {
		t.Fatalf("Mode() = %+v, want the mode of the open", mode)
	}
	_ = first.Close()
	second, err := m.Open("sim", nil)
	if err != nil {
		t.Fatalf("Open() after Close() error = %v", err)
	}
	_ = second.Close()
	if got := m.Opens(); got != 2 {
		t.Fatalf("Opens() = %d, want 2", got)
	}
}

func TestUnpluggingFailsTheOpenPortUntilTheDeviceIsBack(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	m.Unplug()

	if _, err := p.Read(make([]byte, 16)); err == nil || err.Error() != "Port has been closed" {
		t.Fatalf("Read() error = %v, want the port to be reported closed", err)
	}
	if _, err := p.Write([]byte("AT\r\n")); err == nil || !strings.Contains(err.Error(), "input/output error") {
		t.Fatalf("Write() error = %v, want an input/output error", err)
	}
	if _, err := m.Open("sim", nil); err == nil || err.Error() != "Serial port not found" {
		t.Fatalf("Open() error = %v, want the port to be missing", err)
	}
	if _, err := m.DeliverSMS(testDeliver); !errors.Is(err, ErrPoweredOff) {
		t.Fatalf("DeliverSMS() error = %v, want ErrPoweredOff", err)
	}

	m.Replug()
	again := openPort(t, m)
	greeting := readUntil(t, again, func(s string) bool { return strings.Contains(s, "+CPIN: READY\r\n") })
	wantLines(t, "power-on", greeting, "RDY", "+CPIN: READY")
	if !m.Settings().Echo {
		t.Fatal("the echo stayed off across a power cycle")
	}
}

func TestEchoIsOnUntilTheHostTurnsItOff(t *testing.T) {
	p := openPort(t, New(DefaultProfile()))
	if got := exchange(t, p, "AT"); got != "AT\r\r\nOK\r\n" {
		t.Fatalf("AT answered %q with the echo on", got)
	}
	if got := exchange(t, p, "ATE0"); got != "ATE0\r\r\nOK\r\n" {
		t.Fatalf("ATE0 answered %q", got)
	}
	if got := exchange(t, p, "AT"); got != "\r\nOK\r\n" {
		t.Fatalf("AT answered %q with the echo off", got)
	}
}

func TestTheModemAnswersTheQueriesOfTheHost(t *testing.T) {
	profile := DefaultProfile()
	_, p := quietModem(t, profile)
	cases := []struct {
		command string
		want    []string
	}{
		{"AT+CGSN", []string{profile.IMEI, "OK"}},
		{"AT+CGMR", []string{profile.Firmware, "OK"}},
		{"AT+CIMI", []string{profile.IMSI, "OK"}},
		{"AT+QCCID", []string{"+QCCID: " + profile.ICCID, "OK"}},
		{"AT+CNUM", []string{`+CNUM: ,"+15555550123",145`, "OK"}},
		{"AT+CPIN?", []string{"+CPIN: READY", "OK"}},
		{"AT+QSIMSTAT?", []string{"+QSIMSTAT: 0,1", "OK"}},
		{"AT+CSQ", []string{"+CSQ: 20,99", "OK"}},
		{"AT+CREG?", []string{"+CREG: 0,1", "OK"}},
		{"AT+CREG=2", []string{"OK"}},
		{"AT+CREG?", []string{`+CREG: 2,1,"1A2B","1A2B3C4",7`, "OK"}},
		{"AT+COPS?", []string{`+COPS: 0,0,"Test Network",7`, "OK"}},
		{"AT+COPS=3,2", []string{"OK"}},
		{"AT+COPS?", []string{`+COPS: 0,2,"00101",7`, "OK"}},
		{"AT+COPS=?", []string{`+COPS: (2,"Test Network","Test Network","00101",7),,(0-4),(0-2)`, "OK"}},
		{"AT+QNWINFO", []string{`+QNWINFO: "FDD LTE","00101","LTE BAND 3",1300`, "OK"}},
		{`AT+QENG="servingcell"`, []string{`+QENG: "servingcell","NOCONN","LTE","FDD",001,01,1A2B3C4,123,1300,3,5,5,1A2B,-80,-10,-65,15,40`, "OK"}},
		{"AT+QIMS?", []string{"+QIMS: 1,1", "OK"}},
		{"AT+CGDCONT?", []string{`+CGDCONT: 1,"IPV4V6","internet","0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",0,0,0,0`, "OK"}},
		{"AT+CFUN?", []string{"+CFUN: 1", "OK"}},
		{`AT+QCFG="usbnet"`, []string{`+QCFG: "usbnet",0`, "OK"}},
		{`AT+QCFG="usbnet",1`, []string{"OK"}},
		{`AT+QCFG="usbnet"?`, []string{`+QCFG: "usbnet",1`, "OK"}},
		{"AT+CSCA?", []string{`+CSCA: "+15555550199",145`, "OK"}},
		{"AT+CMGF=0", []string{"OK"}},
		{"AT+CNMI=2,1,0,0,0", []string{"OK"}},
		{"AT+CNMI?", []string{"+CNMI: 2,1,0,0,0", "OK"}},
		{"AT+CLIP=1", []string{"OK"}},
		{"AT+QPCMV=1,2", []string{"OK"}},
		{"AT+QPCMV?", []string{"+QPCMV: 1,2", "OK"}},
		{"AT+CPMS?", []string{`+CPMS: "ME",0,255,"ME",0,255,"ME",0,255`, "OK"}},
		{`AT+CCHO="A0000000871002"`, []string{"ERROR"}},
		{"AT+NOSUCHCOMMAND", []string{"ERROR"}},
	}
	for _, tc := range cases {
		wantLines(t, tc.command, exchange(t, p, tc.command), tc.want...)
	}
}

func TestAModemWithoutServiceSaysSo(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	m.SetRegistration(Searching)
	wantLines(t, "AT+CREG?", exchange(t, p, "AT+CREG?"), "+CREG: 0,2", "OK")
	wantLines(t, "AT+COPS?", exchange(t, p, "AT+COPS?"), "+COPS: 0", "OK")
	wantLines(t, "AT+CSQ", exchange(t, p, "AT+CSQ"), "+CSQ: 99,99", "OK")
	wantLines(t, "AT+QNWINFO", exchange(t, p, "AT+QNWINFO"), "+QNWINFO: No Service", "OK")
	wantLines(t, "ATD", exchange(t, p, "ATD5550100;"), "NO CARRIER")
}

func TestSIMRemovalIsReportedAndRefusesSIMCommands(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	wantLines(t, "AT+QSIMSTAT=1", exchange(t, p, "AT+QSIMSTAT=1"), "OK")

	m.RemoveSIM()
	gone := readUntil(t, p, func(s string) bool { return strings.Contains(s, "+CPIN: NOT INSERTED\r\n") })
	wantLines(t, "removal", gone, "+QSIMSTAT: 1,0", "+CPIN: NOT INSERTED")
	wantLines(t, "AT+CPIN?", exchange(t, p, "AT+CPIN?"), "+CME ERROR: 10")
	wantLines(t, "AT+CIMI", exchange(t, p, "AT+CIMI"), "+CME ERROR: 10")
	wantLines(t, "AT+CREG?", exchange(t, p, "AT+CREG?"), "+CREG: 0,0", "OK")
	wantLines(t, "AT+CMEE=0", exchange(t, p, "AT+CMEE=0"), "OK")
	wantLines(t, "AT+CIMI", exchange(t, p, "AT+CIMI"), "ERROR")

	m.InsertSIM()
	back := readUntil(t, p, func(s string) bool { return strings.Contains(s, "+CPIN: READY\r\n") })
	wantLines(t, "insertion", back, "+QSIMSTAT: 1,1", "+CPIN: READY")
}

func TestAReceivedMessageIsAnnouncedReadAndDeleted(t *testing.T) {
	for _, first := range []int{0, 1} {
		profile := DefaultProfile()
		profile.FirstSMSIndex = first
		m, p := quietModem(t, profile)

		index, err := m.DeliverSMS(testDeliver)
		if err != nil || index != first {
			t.Fatalf("DeliverSMS() = %d, %v, want index %d", index, err, first)
		}
		announced := readUntil(t, p, func(s string) bool { return strings.HasSuffix(s, "\r\n") && strings.Contains(s, "+CMTI") })
		indexText := string(rune('0' + first))
		wantLines(t, "delivery", announced, `+CMTI: "ME",`+indexText)

		// 07 91 and the swapped digits of +15555550199, then the TPDU.
		pdu := "07915155550591F9" + strings.ToUpper(hex.EncodeToString(testDeliver))
		wantLines(t, "AT+CMGR", exchange(t, p, "AT+CMGR="+indexText), "+CMGR: 0,,17", pdu, "OK")
		wantLines(t, "AT+CMGR again", exchange(t, p, "AT+CMGR="+indexText), "+CMGR: 1,,17", pdu, "OK")
		wantLines(t, "AT+CMGL", exchange(t, p, "AT+CMGL=4"), "+CMGL: "+indexText+",1,,17", pdu, "OK")
		wantLines(t, "AT+CMGL unread", exchange(t, p, "AT+CMGL=0"), "OK")

		wantLines(t, "AT+CMGD", exchange(t, p, "AT+CMGD="+indexText), "OK")
		wantLines(t, "AT+CMGR of an empty slot", exchange(t, p, "AT+CMGR="+indexText), "OK")
		wantLines(t, "AT+CMGR outside the storage", exchange(t, p, "AT+CMGR=900"), "+CMS ERROR: 321")
		wantLines(t, "AT+CMGD outside the storage", exchange(t, p, "AT+CMGD=900"), "+CMS ERROR: 321")
		if left := m.StoredSMS("ME"); len(left) != 0 {
			t.Fatalf("%d messages left after the delete", len(left))
		}
	}
}

func TestAMessageIsNotAnnouncedWhenTheHostDidNotAskForIt(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	wantLines(t, "AT+CNMI", exchange(t, p, "AT+CNMI=2,0,0,0,0"), "OK")
	if _, err := m.DeliverSMS(testDeliver); err != nil {
		t.Fatalf("DeliverSMS() error = %v", err)
	}
	if n, err := p.Read(make([]byte, 64)); n != 0 || err != nil {
		t.Fatalf("Read() = %d, %v, want nothing to be announced", n, err)
	}
	if stored := m.StoredSMS("ME"); len(stored) != 1 || stored[0].Status != ReceivedUnread {
		t.Fatalf("StoredSMS() = %+v, want the message stored unread", stored)
	}
}

func TestMessagesAreReadFromTheSelectedStorage(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	if _, err := m.StoreSMS("SM", ReceivedRead, testDeliver); err != nil {
		t.Fatalf("StoreSMS() error = %v", err)
	}
	wantLines(t, "AT+CMGL in ME", exchange(t, p, "AT+CMGL=4"), "OK")
	wantLines(t, "AT+CPMS", exchange(t, p, `AT+CPMS="SM"`), "+CPMS: 1,50,0,255,0,255", "OK")
	wantLines(t, "AT+CPMS?", exchange(t, p, "AT+CPMS?"), `+CPMS: "SM",1,50,"ME",0,255,"ME",0,255`, "OK")
	if got := lines(exchange(t, p, "AT+CMGL=4")); len(got) != 3 || got[0] != "+CMGL: 0,1,,17" {
		t.Fatalf("AT+CMGL in SM answered %q", got)
	}
	wantLines(t, "unknown storage", exchange(t, p, `AT+CPMS="XX"`), "+CMS ERROR: 302")
	wantLines(t, "AT+CMGD all", exchange(t, p, "AT+CMGD=0,4"), "OK")
	if left := m.StoredSMS("SM"); len(left) != 0 {
		t.Fatalf("%d messages left after deleting all", len(left))
	}
}

func TestAFullStorageTakesNoMoreMessages(t *testing.T) {
	profile := DefaultProfile()
	profile.ModemSlots = 2
	m := New(profile)
	for i := 0; i < 2; i++ {
		if _, err := m.DeliverSMS(testDeliver); err != nil {
			t.Fatalf("DeliverSMS() #%d error = %v", i+1, err)
		}
	}
	if _, err := m.DeliverSMS(testDeliver); !errors.Is(err, ErrStorageFull) {
		t.Fatalf("DeliverSMS() into a full storage error = %v, want ErrStorageFull", err)
	}
	if stored := m.StoredSMS("ME"); len(stored) != 2 || stored[0].Index != 0 || stored[1].Index != 1 {
		t.Fatalf("StoredSMS() = %+v", stored)
	}
}

// submit sends AT+CMGS and, after the prompt, the PDU and the end character.
func submit(t *testing.T, p serial.Port, length string, pduHex string, end byte) string {
	t.Helper()
	if _, err := p.Write([]byte("AT+CMGS=" + length + "\r\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if got := readUntil(t, p, func(s string) bool { return strings.HasSuffix(s, "> ") }); got != "\r\n> " {
		t.Fatalf("AT+CMGS answered %q, want the prompt", got)
	}
	if _, err := p.Write(append([]byte(pduHex), end)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	return readUntil(t, p, finished)
}

func TestTheHostSendsAMessage(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	pduHex := "00" + strings.ToUpper(hex.EncodeToString(testSubmit))

	wantLines(t, "AT+CMGS", submit(t, p, "11", pduHex, ctrlZ), "+CMGS: 0", "OK")
	wantLines(t, "AT+CMGS", submit(t, p, "11", pduHex, ctrlZ), "+CMGS: 1", "OK")
	sent := m.SentSMS()
	if len(sent) != 2 || sent[1].Reference != 1 || string(sent[1].TPDU) != string(testSubmit) || len(sent[1].PDU) != len(testSubmit)+1 {
		t.Fatalf("SentSMS() = %+v", sent)
	}

	wantLines(t, "escape", submit(t, p, "11", pduHex, escape), "OK")
	wantLines(t, "wrong length", submit(t, p, "12", pduHex, ctrlZ), "+CMS ERROR: 304")
	wantLines(t, "not hexadecimal", submit(t, p, "11", "XYZ", ctrlZ), "+CMS ERROR: 304")
	m.SetRegistration(Searching)
	wantLines(t, "no service", submit(t, p, "11", pduHex, ctrlZ), "+CMS ERROR: 331")
	if got := len(m.SentSMS()); got != 2 {
		t.Fatalf("%d messages sent, want the two that were accepted", got)
	}

	wantLines(t, "text mode", exchange(t, p, "AT+CMGF=1"), "OK")
	wantLines(t, "AT+CMGS in text mode", exchange(t, p, "AT+CMGS=11"), "+CMS ERROR: 302")
}

func TestARuleLeavesACommandUnanswered(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	m.AddRule(Rule{Prefix: "at+csq", Times: 1, Silent: true})

	if _, err := p.Write([]byte("AT+CSQ\r\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n, err := p.Read(make([]byte, 64)); n != 0 || err != nil {
		t.Fatalf("Read() = %d, %v, want no answer", n, err)
	}
	wantLines(t, "AT+CSQ after the rule ran out", exchange(t, p, "AT+CSQ"), "+CSQ: 20,99", "OK")
	if got := m.Count("AT+CSQ"); got != 2 {
		t.Fatalf("Count() = %d, want 2", got)
	}
}

func TestARuleReplacesTheResultUntilItIsRemoved(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	if _, err := m.DeliverSMS(testDeliver); err != nil {
		t.Fatalf("DeliverSMS() error = %v", err)
	}
	readUntil(t, p, func(s string) bool { return strings.Contains(s, "+CMTI") && strings.HasSuffix(s, "\r\n") })

	remove := m.AddRule(Rule{Prefix: "AT+CMGD", Result: "+CMS ERROR: 500"})
	wantLines(t, "AT+CMGD", exchange(t, p, "AT+CMGD=0"), "+CMS ERROR: 500")
	wantLines(t, "AT+CMGD", exchange(t, p, "AT+CMGD=0"), "+CMS ERROR: 500")
	if stored := m.StoredSMS("ME"); len(stored) != 1 {
		t.Fatalf("a refused delete removed the message: %+v", stored)
	}
	remove()
	wantLines(t, "AT+CMGD", exchange(t, p, "AT+CMGD=0"), "OK")

	m.AddRule(Rule{Prefix: "AT+CMGS", Times: 1, Result: "+CMS ERROR: 38"})
	pduHex := "00" + hex.EncodeToString(testSubmit)
	wantLines(t, "AT+CMGS", submit(t, p, "11", pduHex, ctrlZ), "+CMS ERROR: 38")
	if got := len(m.SentSMS()); got != 0 {
		t.Fatalf("%d messages sent although the network refused", got)
	}
}

func TestARuleDelaysTheAnswerAndAnUnsolicitedLineOvertakesIt(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	m.AddRule(Rule{Prefix: "AT+CSQ", Times: 1, Delay: 150 * time.Millisecond})

	start := time.Now()
	if _, err := p.Write([]byte("AT+CSQ\r\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	m.URC("RING")
	got := readUntil(t, p, finished)
	if waited := time.Since(start); waited < 140*time.Millisecond {
		t.Fatalf("the answer arrived after %v, want it delayed", waited)
	}
	wantLines(t, "AT+CSQ", got, "RING", "+CSQ: 20,99", "OK")
}

func TestARulePutsAnUnsolicitedLineBeforeTheResult(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	m.AddRule(Rule{Prefix: "AT+CSQ", Times: 1, URC: `+CMTI: "ME",7`})
	wantLines(t, "AT+CSQ", exchange(t, p, "AT+CSQ"), "+CSQ: 20,99", `+CMTI: "ME",7`, "OK")
}

func TestTheNetworkNeverConfirmsAMessage(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	m.AddRule(Rule{Prefix: "AT+CMGS", Times: 1, SilentAfterPrompt: true})

	if _, err := p.Write([]byte("AT+CMGS=11\r\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	readUntil(t, p, func(s string) bool { return strings.HasSuffix(s, "> ") })
	if _, err := p.Write(append([]byte("00"+hex.EncodeToString(testSubmit)), ctrlZ)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n, err := p.Read(make([]byte, 64)); n != 0 || err != nil {
		t.Fatalf("Read() = %d, %v, want no result", n, err)
	}
	wantLines(t, "AT", exchange(t, p, "AT"), "OK")
}

func TestASilentModemAnswersNothing(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	m.SetSilent(true)
	if _, err := p.Write([]byte("AT\r\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n, err := p.Read(make([]byte, 64)); n != 0 || err != nil {
		t.Fatalf("Read() = %d, %v, want no answer", n, err)
	}
	m.SetSilent(false)
	wantLines(t, "AT", exchange(t, p, "AT"), "OK")
}

func TestARestartTakesThePortAwayForTheBootTime(t *testing.T) {
	profile := DefaultProfile()
	profile.BootTime = 120 * time.Millisecond
	m, p := quietModem(t, profile)
	if _, err := m.DeliverSMS(testDeliver); err != nil {
		t.Fatalf("DeliverSMS() error = %v", err)
	}
	readUntil(t, p, func(s string) bool { return strings.Contains(s, "+CMTI") && strings.HasSuffix(s, "\r\n") })

	wantLines(t, "AT+CFUN=1,1", exchange(t, p, "AT+CFUN=1,1"), "OK")
	deadline := time.Now().Add(2 * time.Second)
	var readErr error
	for readErr == nil && time.Now().Before(deadline) {
		_, readErr = p.Read(make([]byte, 16))
	}
	if readErr == nil || readErr.Error() != "Port has been closed" {
		t.Fatalf("Read() error = %v, want the port to go away after the restart command", readErr)
	}
	if _, err := m.Open("sim", nil); err == nil {
		t.Fatal("the port could be opened while the module was starting")
	}

	time.Sleep(profile.BootTime + 20*time.Millisecond)
	again := openPort(t, m)
	greeting := readUntil(t, again, func(s string) bool { return strings.Contains(s, "+CPIN: READY\r\n") })
	wantLines(t, "start", greeting, "RDY", "+CPIN: READY")
	if stored := m.StoredSMS("ME"); len(stored) != 1 {
		t.Fatalf("the stored message did not survive the restart: %+v", stored)
	}
	if got := exchange(t, again, "AT"); got != "AT\r\r\nOK\r\n" {
		t.Fatalf("AT answered %q, want the echo back on after a restart", got)
	}
}

func TestTheSIMFilesCarryTheIdentityOfTheProfile(t *testing.T) {
	_, p := quietModem(t, DefaultProfile())
	// 08 for eight octets, then 9 and the fifteen digits with the nibbles of
	// each octet swapped.
	wantLines(t, "IMSI", exchange(t, p, "AT+CRSM=176,28423,0,0,9"), `+CRSM: 144,0,"080910101032547698"`, "OK")
	wantLines(t, "administrative data", exchange(t, p, "AT+CRSM=176,28589,0,0,4"), `+CRSM: 144,0,"00000002"`, "OK")
	wantLines(t, "provider name", exchange(t, p, "AT+CRSM=176,28486,0,0,17"),
		`+CRSM: 144,0,"01`+strings.ToUpper(hex.EncodeToString([]byte("Test SIM")))+`FFFFFFFFFFFFFFFF"`, "OK")
	wantLines(t, "a file the SIM does not have", exchange(t, p, "AT+CRSM=176,28478,0,0,32"), `+CRSM: 106,130,""`, "OK")
	wantLines(t, "more than the file holds", exchange(t, p, "AT+CRSM=176,28589,0,0,32"), `+CRSM: 103,0,""`, "OK")
	wantLines(t, "a record", exchange(t, p, "AT+CRSM=178,28613,1,4,32"), `+CRSM: 106,130,""`, "OK")
}

func TestTheNetworkAnswersAUSSDRequest(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	m.SetUSSD(func(code string) (int, string) { return 2, "Balance of " + code })
	if _, err := p.Write([]byte(`AT+CUSD=1,"*100#",15` + "\r\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got := readUntil(t, p, func(s string) bool { return strings.Contains(s, "+CUSD") && strings.HasSuffix(s, "\r\n") })
	wantLines(t, "AT+CUSD", got, "OK", `+CUSD: 2,"Balance of *100#",15`)

	m.SetUSSD(nil)
	wantLines(t, "AT+CUSD without an answer", exchange(t, p, `AT+CUSD=1,"*100#",15`), "OK")
	if n, err := p.Read(make([]byte, 64)); n != 0 || err != nil {
		t.Fatalf("Read() = %d, %v, want no answer from the network", n, err)
	}
	wantLines(t, "AT+CUSD=2", exchange(t, p, "AT+CUSD=2"), "OK")
}

func TestAnIncomingCallRingsAndCanBeAnswered(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	wantLines(t, "ATA without a call", exchange(t, p, "ATA"), "NO CARRIER")
	wantLines(t, "AT+CLIP=1", exchange(t, p, "AT+CLIP=1"), "OK")

	m.IncomingCall("+15555550142")
	ringing := readUntil(t, p, func(s string) bool { return strings.Contains(s, "+CLIP") && strings.HasSuffix(s, "\r\n") })
	wantLines(t, "call", ringing, "RING", `+CLIP: "+15555550142",145,"",,"",0`)
	wantLines(t, "ATA", exchange(t, p, "ATA"), "OK")
	m.EndCall()
	wantLines(t, "hang-up", readUntil(t, p, func(s string) bool { return strings.HasSuffix(s, "NO CARRIER\r\n") }), "NO CARRIER")

	wantLines(t, "ATD", exchange(t, p, "ATD5550100;"), "OK")
	if dialled := m.Dialled(); len(dialled) != 1 || dialled[0] != "5550100" {
		t.Fatalf("Dialled() = %q", dialled)
	}
	wantLines(t, "ATH", exchange(t, p, "ATH"), "OK")
}

func TestInjectedBytesReachTheHostUnchanged(t *testing.T) {
	m, p := quietModem(t, DefaultProfile())
	m.Inject([]byte("\x00garbage\r\n"))
	got := readUntil(t, p, func(s string) bool { return strings.HasSuffix(s, "\r\n") })
	if got != "\x00garbage\r\n" {
		t.Fatalf("read %q", got)
	}
	if !m.WaitCommands("ATE0", 1, time.Second) || m.WaitCommands("AT+NEVER", 1, 20*time.Millisecond) {
		t.Fatal("WaitCommands() does not follow the commands received")
	}
}
