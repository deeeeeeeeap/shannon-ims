// Package atsim is a software cellular module for tests.
//
// A Modem answers the AT commands this project sends to a Quectel-style
// module. The host reaches it through a serial port that behaves like the one
// the serial library returns: a read that times out returns no bytes and no
// error, a port whose device has gone reports that it has been closed, and a
// device can be opened only once at a time. A test registers Modem.Open as
// the opener of a port name and runs the real AT manager against it.
//
// Besides answering, the modem can be told to misbehave: stay silent, answer
// late, refuse a command, send an unsolicited line in the middle of an answer,
// restart, or disappear the way an unplugged USB device does.
package atsim

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.bug.st/serial"
)

// Registration states, as AT+CREG reports them.
const (
	NotRegistered      = 0
	RegisteredHome     = 1
	Searching          = 2
	RegistrationDenied = 3
	RegisteredRoaming  = 5
)

// States of a stored message, as AT+CMGL and AT+CMGR report them.
const (
	ReceivedUnread = 0
	ReceivedRead   = 1
)

// ErrStorageFull is returned when a message does not fit into a storage.
var ErrStorageFull = errors.New("atsim: message storage is full")

// ErrPoweredOff is returned when a message is delivered to a modem that is
// unplugged or restarting.
var ErrPoweredOff = errors.New("atsim: modem is powered off")

// restartLag is the time between the answer to a restart command and the
// moment the port goes away.
const restartLag = 50 * time.Millisecond

// Profile is what a modem and its SIM report about themselves.
type Profile struct {
	IMEI     string
	Firmware string
	IMSI     string
	ICCID    string
	// Number is the subscriber's own number as AT+CNUM reports it. Many SIMs
	// do not carry one; leave it empty for those.
	Number        string
	ServiceCentre string
	// PLMN is the serving network, the MCC followed by the MNC.
	PLMN         string
	OperatorName string
	// ProviderName is the service provider name stored on the SIM.
	ProviderName string
	APN          string
	// FirstSMSIndex is the index of the first slot of a message storage.
	// Quectel modules count from 0, several other vendors from 1.
	FirstSMSIndex int
	// SIMSlots and ModemSlots are the sizes of the "SM" and "ME" storages.
	SIMSlots   int
	ModemSlots int
	// BootTime is how long the port stays away after a restart.
	BootTime time.Duration
}

// DefaultProfile returns a module on the test network 001/01. Every identity
// in it is invented.
func DefaultProfile() Profile {
	return Profile{
		IMEI:          "350000000000006",
		Firmware:      "ATSIM20R01A01",
		IMSI:          "001010123456789",
		ICCID:         "89001012345678901234",
		Number:        "+15555550123",
		ServiceCentre: "+15555550199",
		PLMN:          "00101",
		OperatorName:  "Test Network",
		ProviderName:  "Test SIM",
		APN:           "internet",
		SIMSlots:      50,
		ModemSlots:    255,
		BootTime:      300 * time.Millisecond,
	}
}

// StoredSMS is a message in one of the modem's storages.
type StoredSMS struct {
	Index  int
	Status int
	// PDU is the service centre address followed by the SMS-DELIVER.
	PDU []byte
}

// SentSMS is a message the host gave the modem to send.
type SentSMS struct {
	// Reference is the message reference the modem answered with.
	Reference int
	// PDU is what the host wrote: the service centre address followed by the
	// SMS-SUBMIT. TPDU is the SMS-SUBMIT alone.
	PDU  []byte
	TPDU []byte
}

// Settings are the settings a host changes with AT commands.
type Settings struct {
	Echo    bool
	PDUMode bool
	// NewMessageIndication holds the parameters of AT+CNMI.
	NewMessageIndication string
	// Memories holds the three storages of AT+CPMS.
	Memories      [3]string
	CallerID      bool
	Functionality int
	USBNetMode    int
}

// Rule changes how the modem treats the commands that begin with Prefix.
type Rule struct {
	// Prefix is compared without regard to case; an empty prefix matches
	// every command.
	Prefix string
	// Times is the number of commands the rule applies to. Zero means every
	// command until the rule is removed.
	Times int
	// Delay postpones the answer.
	Delay time.Duration
	// Silent leaves the command without any answer.
	Silent bool
	// Result is sent as the final result instead of carrying the command
	// out, for example "+CMS ERROR: 500". For AT+CMGS the prompt is still
	// given and the result follows the message.
	Result string
	// URC is an unsolicited line sent between the information lines of the
	// answer and its final result.
	URC string
	// SilentAfterPrompt applies to AT+CMGS: the prompt is given and the
	// message is taken, but no result follows.
	SilentAfterPrompt bool
}

type activeRule struct {
	Rule
	id   int
	left int
}

type slot struct {
	status  int
	pdu     []byte
	tpduLen int
}

type storage struct {
	size  int
	slots map[int]*slot
}

// Modem is a simulated cellular module. Its methods may be called from any
// goroutine.
type Modem struct {
	mu      sync.Mutex
	profile Profile

	// Settings a restart resets.
	echo           bool
	errorMode      int
	pduMode        bool
	indication     [5]int
	regReport      int
	operatorFormat int
	callerID       bool
	simReport      int
	pcmVoice       string
	mem            [3]string

	// State a restart keeps.
	functionality int
	usbNetMode    int
	apn           string
	serviceCentre string
	simInserted   bool
	registration  int
	signal        int
	attached      bool
	storages      map[string]*storage
	simFiles      map[int][]byte
	nextReference int
	sent          []SentSMS
	dialled       []string
	commands      []string
	ringing       bool

	// The serial line.
	port      *port
	mode      serial.Mode
	opens     int
	unplugged bool
	removeAt  time.Time
	bootUntil time.Time
	announce  bool
	line      []byte
	prompt    *submitPrompt

	// Misbehaviour.
	silent     bool
	delay      time.Duration
	rules      []*activeRule
	nextRuleID int

	ussd func(code string) (status int, text string)
}

// New returns a modem that is powered, registered on its home network and has
// its SIM inserted.
func New(profile Profile) *Modem {
	if profile.SIMSlots <= 0 {
		profile.SIMSlots = 50
	}
	if profile.ModemSlots <= 0 {
		profile.ModemSlots = 255
	}
	m := &Modem{
		profile:       profile,
		functionality: 1,
		apn:           profile.APN,
		serviceCentre: profile.ServiceCentre,
		simInserted:   true,
		registration:  RegisteredHome,
		signal:        20,
		attached:      true,
		storages: map[string]*storage{
			"SM": {size: profile.SIMSlots, slots: map[int]*slot{}},
			"ME": {size: profile.ModemSlots, slots: map[int]*slot{}},
		},
		simFiles: simFiles(profile),
		ussd: func(code string) (int, string) {
			return 0, "No service for " + code
		},
	}
	m.resetSettings()
	return m
}

// resetSettings puts the settings back to what the module has after power-on.
func (m *Modem) resetSettings() {
	m.echo = true
	m.errorMode = 1
	m.pduMode = true
	m.indication = [5]int{2, 1, 0, 0, 0}
	m.regReport = 0
	m.operatorFormat = 0
	m.callerID = false
	m.simReport = 0
	m.pcmVoice = "0,0"
	m.mem = [3]string{"ME", "ME", "ME"}
	m.line = nil
	m.prompt = nil
	m.ringing = false
}

// Profile returns the profile the modem was made with.
func (m *Modem) Profile() Profile {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.profile
}

// Settings returns the settings as the host has left them.
func (m *Modem) Settings() Settings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Settings{
		Echo:                 m.echo,
		PDUMode:              m.pduMode,
		NewMessageIndication: joinInts(m.indication[:]),
		Memories:             m.mem,
		CallerID:             m.callerID,
		Functionality:        m.functionality,
		USBNetMode:           m.usbNetMode,
	}
}

// Mode returns the serial mode the port was last opened with.
func (m *Modem) Mode() serial.Mode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// Opens returns how many times the port has been opened.
func (m *Modem) Opens() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.opens
}

// IsOpen reports whether a host has the port open.
func (m *Modem) IsOpen() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expire(time.Now())
	return m.port != nil
}

// Commands returns the command lines received so far, oldest first.
func (m *Modem) Commands() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.commands...)
}

// Count returns how many of the received command lines begin with prefix,
// compared without regard to case.
func (m *Modem) Count(prefix string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.count(prefix)
}

func (m *Modem) count(prefix string) int {
	prefix = strings.ToUpper(prefix)
	n := 0
	for _, command := range m.commands {
		if strings.HasPrefix(strings.ToUpper(command), prefix) {
			n++
		}
	}
	return n
}

// WaitCommands waits until at least n command lines that begin with prefix
// have been received and reports whether that happened within the timeout.
func (m *Modem) WaitCommands(prefix string, n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if m.Count(prefix) >= n {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// DeliverSMS hands the modem a message from the network, an SMS-DELIVER. The
// modem stores it in the storage for received messages and, when the host has
// asked for it, announces it with +CMTI. It returns the index of the message.
func (m *Modem) DeliverSMS(tpdu []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.expire(now)
	if m.unplugged || now.Before(m.bootUntil) || m.functionality != 1 {
		return 0, ErrPoweredOff
	}
	name := m.mem[2]
	index, err := m.store(name, ReceivedUnread, tpdu)
	if err != nil {
		return 0, err
	}
	if m.indication[1] == 1 {
		m.sendLine(now, fmt.Sprintf("+CMTI: %q,%d", name, index))
	}
	return index, nil
}

// StoreSMS puts a message into a storage without announcing it, the state of
// a message that arrived while no host was listening.
func (m *Modem) StoreSMS(storageName string, status int, tpdu []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store(storageName, status, tpdu)
}

func (m *Modem) store(name string, status int, tpdu []byte) (int, error) {
	s := m.storages[strings.ToUpper(name)]
	if s == nil {
		return 0, fmt.Errorf("atsim: no storage %q", name)
	}
	for position := 0; position < s.size; position++ {
		if s.slots[position] != nil {
			continue
		}
		pdu := append(encodeServiceCentre(m.serviceCentre), tpdu...)
		s.slots[position] = &slot{status: status, pdu: pdu, tpduLen: len(tpdu)}
		return position + m.profile.FirstSMSIndex, nil
	}
	return 0, ErrStorageFull
}

// StoredSMS returns the messages in a storage in index order.
func (m *Modem) StoredSMS(storageName string) []StoredSMS {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.storages[strings.ToUpper(storageName)]
	if s == nil {
		return nil
	}
	out := make([]StoredSMS, 0, len(s.slots))
	for _, position := range s.positions() {
		entry := s.slots[position]
		out = append(out, StoredSMS{
			Index:  position + m.profile.FirstSMSIndex,
			Status: entry.status,
			PDU:    append([]byte(nil), entry.pdu...),
		})
	}
	return out
}

func (s *storage) positions() []int {
	positions := make([]int, 0, len(s.slots))
	for position := range s.slots {
		positions = append(positions, position)
	}
	sort.Ints(positions)
	return positions
}

// SentSMS returns the messages the host has sent, oldest first.
func (m *Modem) SentSMS() []SentSMS {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]SentSMS(nil), m.sent...)
}

// Dialled returns the numbers the host has dialled, oldest first.
func (m *Modem) Dialled() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.dialled...)
}

// SetRegistration changes the network registration state.
func (m *Modem) SetRegistration(state int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registration = state
}

// SetSignal changes the received signal strength, 0 to 31, or 99 for unknown.
func (m *Modem) SetSignal(rssi int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signal = rssi
}

// RemoveSIM takes the SIM out. The modem loses its registration and reports
// the removal when the host has asked for SIM status reports.
func (m *Modem) RemoveSIM() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.simInserted {
		return
	}
	m.simInserted = false
	now := time.Now()
	if m.simReport == 1 {
		m.sendLine(now, "+QSIMSTAT: 1,0")
	}
	m.sendLine(now, "+CPIN: NOT INSERTED")
}

// InsertSIM puts the SIM back.
func (m *Modem) InsertSIM() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.simInserted {
		return
	}
	m.simInserted = true
	now := time.Now()
	if m.simReport == 1 {
		m.sendLine(now, "+QSIMSTAT: 1,1")
	}
	m.sendLine(now, "+CPIN: READY")
}

// IncomingCall makes the modem ring.
func (m *Modem) IncomingCall(number string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ringing = true
	now := time.Now()
	m.sendLine(now, "RING")
	if m.callerID {
		kind := 129
		if strings.HasPrefix(number, "+") {
			kind = 145
		}
		m.sendLine(now, fmt.Sprintf("+CLIP: %q,%d,\"\",,\"\",0", number, kind))
	}
}

// EndCall ends a call from the far side.
func (m *Modem) EndCall() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ringing = false
	m.sendLine(time.Now(), "NO CARRIER")
}

// SetUSSD sets what the network answers to a USSD request: the status and the
// text of the +CUSD line. With a nil function the network does not answer.
// The function is called with the modem locked and must not call the modem.
func (m *Modem) SetUSSD(answer func(code string) (status int, text string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ussd = answer
}

// URC sends an unsolicited line to the host.
func (m *Modem) URC(line string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendLine(time.Now(), line)
}

// Inject sends bytes to the host exactly as given.
func (m *Modem) Inject(raw []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.send(time.Now(), append([]byte(nil), raw...))
}

// Unplug removes the device. An open port fails from now on and the port
// cannot be opened until Replug.
func (m *Modem) Unplug() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unplugged = true
	m.removeAt = time.Time{}
	m.dropPort()
}

// Replug puts the device back. The module starts as after power-on: its
// settings are reset, its stored messages are kept.
func (m *Modem) Replug() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.unplugged {
		return
	}
	m.unplugged = false
	m.bootUntil = time.Time{}
	m.resetSettings()
	m.announce = true
}

// Restart restarts the module on its own, as a firmware fault does: the port
// goes away at once and returns after the boot time.
func (m *Modem) Restart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeAt = time.Now()
	m.expire(m.removeAt)
}

// expire carries out a restart that has become due.
func (m *Modem) expire(now time.Time) {
	if m.removeAt.IsZero() || now.Before(m.removeAt) {
		return
	}
	m.bootUntil = m.removeAt.Add(m.profile.BootTime)
	m.removeAt = time.Time{}
	m.dropPort()
	m.resetSettings()
	m.announce = true
}

// dropPort takes the device away from under an open port.
func (m *Modem) dropPort() {
	if m.port == nil {
		return
	}
	m.port.gone = true
	m.port.out = nil
	m.port.signal()
	m.port = nil
	m.line = nil
	m.prompt = nil
}

// SetSilent makes the modem stop reacting to anything the host writes, the
// way a module with hung firmware does.
func (m *Modem) SetSilent(silent bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.silent = silent
	if silent {
		m.line = nil
		m.prompt = nil
	}
}

// SetDelay postpones every answer.
func (m *Modem) SetDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delay = delay
}

// AddRule adds a rule. When several rules match a command the oldest one is
// used. The returned function removes the rule.
func (m *Modem) AddRule(rule Rule) (remove func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextRuleID++
	id := m.nextRuleID
	rule.Prefix = strings.ToUpper(strings.TrimSpace(rule.Prefix))
	m.rules = append(m.rules, &activeRule{Rule: rule, id: id, left: rule.Times})
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.removeRule(id)
	}
}

func (m *Modem) removeRule(id int) {
	for i, rule := range m.rules {
		if rule.id == id {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			return
		}
	}
}

// useRule returns the rule for a command and counts the use.
func (m *Modem) useRule(upper string) *Rule {
	for _, rule := range m.rules {
		if !strings.HasPrefix(upper, rule.Prefix) {
			continue
		}
		used := rule.Rule
		if rule.Times > 0 {
			rule.left--
			if rule.left == 0 {
				m.removeRule(rule.id)
			}
		}
		return &used
	}
	return nil
}

// registered reports whether the module has network service.
func (m *Modem) registered() bool {
	if m.functionality != 1 || !m.simInserted {
		return false
	}
	return m.registration == RegisteredHome || m.registration == RegisteredRoaming
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprint(value)
	}
	return strings.Join(parts, ",")
}
