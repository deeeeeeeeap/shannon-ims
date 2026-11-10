package atsim

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	resultOK    = "OK"
	resultError = "ERROR"

	ctrlZ  = 0x1A
	escape = 0x1B
)

// submitPrompt is the state between the prompt of AT+CMGS and the end of the
// message the host types after it.
type submitPrompt struct {
	length int
	input  []byte
	rule   *Rule
}

// receive takes what the host wrote to the port.
func (m *Modem) receive(data []byte) {
	if m.silent {
		return
	}
	for _, b := range data {
		if m.prompt != nil {
			m.promptByte(b)
			continue
		}
		switch b {
		case '\r':
			line := string(m.line)
			m.line = m.line[:0]
			m.execute(line)
		case '\n':
			// The host ends its lines with CR LF; the module acts on the CR.
		default:
			// Outside the message prompt a module discards control characters,
			// such as an ESC or a Ctrl-Z that arrives after the prompt is gone.
			if b >= 0x20 && b != 0x7F {
				m.line = append(m.line, b)
			}
		}
	}
}

// execute carries out one command line and queues its answer.
func (m *Modem) execute(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	m.commands = append(m.commands, line)
	upper := strings.ToUpper(line)
	if !strings.HasPrefix(upper, "AT") {
		// A module looks for the AT prefix and ignores everything else.
		return
	}

	at := time.Now().Add(m.delay)
	rule := m.useRule(upper)
	if rule != nil {
		if rule.Silent {
			return
		}
		at = at.Add(rule.Delay)
	}
	if m.echo {
		m.send(at, []byte(line+"\r"))
	}

	if strings.HasPrefix(upper, "AT+CMGS=") {
		m.beginSubmit(at, line[len("AT+CMGS="):], rule)
		return
	}
	if rule != nil && rule.Result != "" {
		m.answer(at, nil, rule.Result, rule.URC)
		return
	}
	info, result := m.run(line, upper)
	urc := ""
	if rule != nil {
		urc = rule.URC
	}
	m.answer(at, info, result, urc)
}

// answer queues the information lines, an unsolicited line if one is to be
// slipped in, and the final result.
func (m *Modem) answer(at time.Time, info []string, result, urc string) {
	var out strings.Builder
	if len(info) > 0 {
		out.WriteString("\r\n")
		out.WriteString(strings.Join(info, "\r\n"))
		out.WriteString("\r\n")
	}
	if urc != "" {
		out.WriteString("\r\n" + urc + "\r\n")
	}
	out.WriteString("\r\n" + result + "\r\n")
	m.send(at, []byte(out.String()))
}

func (m *Modem) cme(code int) string {
	if m.errorMode == 0 {
		return resultError
	}
	return fmt.Sprintf("+CME ERROR: %d", code)
}

func cms(code int) string {
	return fmt.Sprintf("+CMS ERROR: %d", code)
}

// run carries out a command and returns its information lines and result.
func (m *Modem) run(line, upper string) ([]string, string) {
	switch {
	case upper == "AT":
		return nil, resultOK
	case upper == "ATE0":
		m.echo = false
		return nil, resultOK
	case upper == "ATE1" || upper == "ATE":
		m.echo = true
		return nil, resultOK
	case upper == "ATI":
		return []string{"Quectel", "EC20F", "Revision: " + m.profile.Firmware}, resultOK
	case upper == "ATZ" || upper == "AT&F" || upper == "AT&W":
		return nil, resultOK
	case upper == "ATA":
		if !m.ringing {
			return nil, "NO CARRIER"
		}
		m.ringing = false
		return nil, resultOK
	case upper == "ATH" || upper == "ATH0":
		m.ringing = false
		return nil, resultOK
	case strings.HasPrefix(upper, "ATD"):
		if !m.registered() {
			return nil, "NO CARRIER"
		}
		m.dialled = append(m.dialled, strings.TrimSuffix(line[3:], ";"))
		return nil, resultOK
	}
	if !strings.HasPrefix(upper, "AT+") {
		return nil, resultError
	}

	body := line[2:]
	name, args := body, ""
	read, test, set := false, false, false
	if i := strings.IndexAny(body, "=?"); i >= 0 {
		name = body[:i]
		switch rest := body[i:]; {
		case rest == "?":
			read = true
		case rest == "=?":
			test = true
		case strings.HasPrefix(rest, "="):
			set = true
			args = rest[1:]
		default:
			return nil, resultError
		}
	}
	name = strings.ToUpper(name)
	fields := splitArgs(args)

	switch name {
	case "+CGSN", "+GSN":
		return []string{m.profile.IMEI}, resultOK
	case "+CGMR", "+GMR":
		return []string{m.profile.Firmware}, resultOK
	case "+CGMI", "+GMI":
		return []string{"Quectel"}, resultOK
	case "+CGMM", "+GMM":
		return []string{"EC20F"}, resultOK

	case "+CIMI":
		if !m.simInserted {
			return nil, m.cme(10)
		}
		return []string{m.profile.IMSI}, resultOK
	case "+QCCID", "+CCID", "+ICCID":
		if !m.simInserted {
			return nil, m.cme(10)
		}
		return []string{name + ": " + m.profile.ICCID}, resultOK
	case "+CNUM":
		if !m.simInserted {
			return nil, m.cme(10)
		}
		if m.profile.Number == "" {
			return nil, resultOK
		}
		return []string{fmt.Sprintf("+CNUM: ,%q,%d", m.profile.Number, numberType(m.profile.Number))}, resultOK
	case "+CPIN":
		if !read {
			return nil, resultError
		}
		if !m.simInserted {
			return nil, m.cme(10)
		}
		return []string{"+CPIN: READY"}, resultOK
	case "+QSIMSTAT":
		if set {
			m.simReport = intArg(fields, 0, m.simReport)
			return nil, resultOK
		}
		return []string{fmt.Sprintf("+QSIMSTAT: %d,%d", m.simReport, boolInt(m.simInserted))}, resultOK

	case "+CSQ":
		if !m.registered() {
			return []string{"+CSQ: 99,99"}, resultOK
		}
		return []string{fmt.Sprintf("+CSQ: %d,99", m.signal)}, resultOK
	case "+CREG", "+CGREG", "+CEREG":
		if set {
			m.regReport = intArg(fields, 0, m.regReport)
			return nil, resultOK
		}
		state := m.registration
		if m.functionality != 1 || !m.simInserted {
			state = NotRegistered
		}
		if m.regReport == 2 && m.registered() {
			return []string{fmt.Sprintf("%s: 2,%d,\"1A2B\",\"1A2B3C4\",7", name, state)}, resultOK
		}
		return []string{fmt.Sprintf("%s: %d,%d", name, m.regReport, state)}, resultOK
	case "+COPS":
		return m.operatorCommand(read, test, set, fields)
	case "+QNWINFO":
		if !m.registered() {
			return []string{"+QNWINFO: No Service"}, resultOK
		}
		return []string{fmt.Sprintf("+QNWINFO: \"FDD LTE\",%q,\"LTE BAND 3\",1300", m.profile.PLMN)}, resultOK
	case "+QENG":
		if !m.registered() {
			return []string{"+QENG: \"servingcell\",\"SEARCH\""}, resultOK
		}
		mcc, mnc := splitPLMN(m.profile.PLMN)
		rsrp := -140 + m.signal*3
		if rsrp > -44 {
			rsrp = -44
		}
		return []string{fmt.Sprintf("+QENG: \"servingcell\",\"NOCONN\",\"LTE\",\"FDD\",%s,%s,1A2B3C4,123,1300,3,5,5,1A2B,%d,-10,-65,15,40", mcc, mnc, rsrp)}, resultOK
	case "+QIMS":
		return []string{"+QIMS: 1,1"}, resultOK
	case "+CGDCONT":
		if set {
			if len(fields) >= 3 {
				m.apn = fields[2]
			}
			return nil, resultOK
		}
		return []string{fmt.Sprintf("+CGDCONT: 1,\"IPV4V6\",%q,\"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0\",0,0,0,0", m.apn)}, resultOK
	case "+CGATT":
		if set {
			m.attached = intArg(fields, 0, 1) == 1
			return nil, resultOK
		}
		return []string{fmt.Sprintf("+CGATT: %d", boolInt(m.attached && m.registered()))}, resultOK
	case "+CFUN":
		if set {
			m.functionality = intArg(fields, 0, m.functionality)
			if intArg(fields, 1, 0) == 1 {
				m.functionality = 1
				m.removeAt = time.Now().Add(m.delay + restartLag)
			}
			return nil, resultOK
		}
		return []string{fmt.Sprintf("+CFUN: %d", m.functionality)}, resultOK
	case "+QCFG":
		if !set || len(fields) == 0 {
			return nil, resultError
		}
		// A setting is read by naming it without a value. The host also asks
		// with a question mark after the name, which is accepted here.
		if !strings.EqualFold(strings.TrimSuffix(fields[0], "?"), "usbnet") {
			return nil, resultOK
		}
		if len(fields) >= 2 {
			m.usbNetMode = intArg(fields, 1, m.usbNetMode)
			return nil, resultOK
		}
		return []string{fmt.Sprintf("+QCFG: \"usbnet\",%d", m.usbNetMode)}, resultOK

	case "+CMEE":
		if set {
			m.errorMode = intArg(fields, 0, m.errorMode)
			return nil, resultOK
		}
		return []string{fmt.Sprintf("+CMEE: %d", m.errorMode)}, resultOK
	case "+CSCS":
		if set {
			return nil, resultOK
		}
		return []string{"+CSCS: \"GSM\""}, resultOK
	case "+CLIP":
		if set {
			m.callerID = intArg(fields, 0, 0) == 1
			return nil, resultOK
		}
		return []string{fmt.Sprintf("+CLIP: %d,1", boolInt(m.callerID))}, resultOK
	case "+QPCMV":
		if set {
			m.pcmVoice = strings.Join(fields, ",")
			return nil, resultOK
		}
		return []string{"+QPCMV: " + m.pcmVoice}, resultOK

	case "+CSCA":
		if set {
			if len(fields) == 0 {
				return nil, resultError
			}
			m.serviceCentre = fields[0]
			return nil, resultOK
		}
		if !m.simInserted {
			return nil, m.cme(10)
		}
		return []string{fmt.Sprintf("+CSCA: %q,%d", m.serviceCentre, numberType(m.serviceCentre))}, resultOK
	case "+CMGF":
		if set {
			m.pduMode = intArg(fields, 0, 0) == 0
			return nil, resultOK
		}
		return []string{fmt.Sprintf("+CMGF: %d", boolInt(!m.pduMode))}, resultOK
	case "+CNMI":
		if set {
			for i := range m.indication {
				m.indication[i] = intArg(fields, i, m.indication[i])
			}
			return nil, resultOK
		}
		return []string{"+CNMI: " + joinInts(m.indication[:])}, resultOK
	case "+CPMS":
		return m.storageCommand(read, test, set, fields)
	case "+CMGL":
		return m.listMessages(set, fields)
	case "+CMGR":
		return m.readMessage(set, fields)
	case "+CMGD":
		return m.deleteMessages(set, fields)

	case "+CUSD":
		return m.ussdCommand(set, fields)
	case "+CRSM":
		return m.simFileCommand(set, fields)
	case "+CSIM", "+CGLA", "+CCHO", "+CCHC":
		// The simulated SIM has no applications to select or talk to.
		if !m.simInserted {
			return nil, m.cme(10)
		}
		return nil, resultError
	}
	return nil, resultError
}

func (m *Modem) operatorCommand(read, test, set bool, fields []string) ([]string, string) {
	switch {
	case test:
		return []string{fmt.Sprintf("+COPS: (2,%q,%q,%q,7),,(0-4),(0-2)", m.profile.OperatorName, m.profile.OperatorName, m.profile.PLMN)}, resultOK
	case set:
		switch intArg(fields, 0, 0) {
		case 0, 1, 4:
			if m.simInserted {
				m.registration = RegisteredHome
			}
		case 2:
			m.registration = NotRegistered
		case 3:
			m.operatorFormat = intArg(fields, 1, m.operatorFormat)
		}
		return nil, resultOK
	case read:
		if !m.registered() {
			return []string{"+COPS: 0"}, resultOK
		}
		operator := m.profile.OperatorName
		if m.operatorFormat == 2 {
			operator = m.profile.PLMN
		}
		return []string{fmt.Sprintf("+COPS: 0,%d,%q,7", m.operatorFormat, operator)}, resultOK
	}
	return nil, resultError
}

func (m *Modem) storageCommand(read, test, set bool, fields []string) ([]string, string) {
	switch {
	case test:
		return []string{`+CPMS: ("SM","ME"),("SM","ME"),("SM","ME")`}, resultOK
	case read:
		parts := make([]string, 0, 3)
		for _, name := range m.mem {
			s := m.storages[name]
			parts = append(parts, fmt.Sprintf("%q,%d,%d", name, len(s.slots), s.size))
		}
		return []string{"+CPMS: " + strings.Join(parts, ",")}, resultOK
	case set:
		if len(fields) == 0 || len(fields) > 3 {
			return nil, cms(302)
		}
		chosen := m.mem
		for i, field := range fields {
			name := strings.ToUpper(field)
			if m.storages[name] == nil {
				return nil, cms(302)
			}
			chosen[i] = name
		}
		m.mem = chosen
		parts := make([]string, 0, 3)
		for _, name := range m.mem {
			s := m.storages[name]
			parts = append(parts, fmt.Sprintf("%d,%d", len(s.slots), s.size))
		}
		return []string{"+CPMS: " + strings.Join(parts, ",")}, resultOK
	}
	return nil, resultError
}

// position turns the index a host names into a position of the storage that
// AT+CMGR and AT+CMGD work on.
func (m *Modem) position(field string) (*storage, int, bool) {
	s := m.storages[m.mem[0]]
	index, err := strconv.Atoi(strings.TrimSpace(field))
	if err != nil {
		return s, 0, false
	}
	position := index - m.profile.FirstSMSIndex
	if position < 0 || position >= s.size {
		return s, 0, false
	}
	return s, position, true
}

func (m *Modem) listMessages(set bool, fields []string) ([]string, string) {
	if !m.pduMode {
		return nil, cms(302)
	}
	wanted := ReceivedUnread
	if set {
		wanted = intArg(fields, 0, -1)
		if wanted < 0 || wanted > 4 {
			return nil, cms(302)
		}
	}
	s := m.storages[m.mem[0]]
	var info []string
	for _, position := range s.positions() {
		entry := s.slots[position]
		if wanted != 4 && entry.status != wanted {
			continue
		}
		info = append(info,
			fmt.Sprintf("+CMGL: %d,%d,,%d", position+m.profile.FirstSMSIndex, entry.status, entry.tpduLen),
			strings.ToUpper(hex.EncodeToString(entry.pdu)))
		if entry.status == ReceivedUnread {
			entry.status = ReceivedRead
		}
	}
	return info, resultOK
}

func (m *Modem) readMessage(set bool, fields []string) ([]string, string) {
	if !m.pduMode {
		return nil, cms(302)
	}
	if !set || len(fields) == 0 {
		return nil, cms(302)
	}
	s, position, ok := m.position(fields[0])
	if !ok {
		return nil, cms(321)
	}
	entry := s.slots[position]
	if entry == nil {
		// An empty slot is not an error: the answer just carries no message.
		return nil, resultOK
	}
	info := []string{
		fmt.Sprintf("+CMGR: %d,,%d", entry.status, entry.tpduLen),
		strings.ToUpper(hex.EncodeToString(entry.pdu)),
	}
	if entry.status == ReceivedUnread {
		entry.status = ReceivedRead
	}
	return info, resultOK
}

func (m *Modem) deleteMessages(set bool, fields []string) ([]string, string) {
	if !set || len(fields) == 0 {
		return nil, cms(302)
	}
	s, position, ok := m.position(fields[0])
	switch flag := intArg(fields, 1, 0); flag {
	case 0:
		if !ok {
			return nil, cms(321)
		}
		delete(s.slots, position)
	case 1, 2, 3:
		for position, entry := range s.slots {
			if entry.status == ReceivedRead {
				delete(s.slots, position)
			}
		}
	case 4:
		s.slots = map[int]*slot{}
	default:
		return nil, cms(302)
	}
	return nil, resultOK
}

// beginSubmit answers AT+CMGS=<length> with the prompt and waits for the
// message.
func (m *Modem) beginSubmit(at time.Time, arg string, rule *Rule) {
	length, err := strconv.Atoi(strings.TrimSpace(arg))
	if !m.pduMode || err != nil || length <= 0 {
		m.answer(at, nil, cms(302), "")
		return
	}
	m.prompt = &submitPrompt{length: length, rule: rule}
	m.send(at, []byte("\r\n> "))
}

// promptByte takes one byte of the message typed after the prompt.
func (m *Modem) promptByte(b byte) {
	switch b {
	case escape:
		m.prompt = nil
		m.answer(time.Now().Add(m.delay), nil, resultOK, "")
	case ctrlZ:
		prompt := m.prompt
		m.prompt = nil
		m.submit(prompt)
	case '\r', '\n':
	default:
		m.prompt.input = append(m.prompt.input, b)
	}
}

// submit sends the message the host typed, or refuses it.
func (m *Modem) submit(prompt *submitPrompt) {
	at := time.Now().Add(m.delay)
	urc := ""
	if rule := prompt.rule; rule != nil {
		if rule.SilentAfterPrompt {
			return
		}
		at = at.Add(rule.Delay)
		urc = rule.URC
		if rule.Result != "" {
			m.answer(at, nil, rule.Result, urc)
			return
		}
	}
	if m.echo {
		m.send(at, append(append([]byte(nil), prompt.input...), '\r', '\n'))
	}
	pdu, err := hex.DecodeString(strings.TrimSpace(string(prompt.input)))
	if err != nil || len(pdu) == 0 || 1+int(pdu[0]) > len(pdu) {
		m.answer(at, nil, cms(304), urc)
		return
	}
	tpdu := pdu[1+int(pdu[0]):]
	if len(tpdu) != prompt.length {
		m.answer(at, nil, cms(304), urc)
		return
	}
	if !m.simInserted {
		m.answer(at, nil, cms(310), urc)
		return
	}
	if !m.registered() {
		m.answer(at, nil, cms(331), urc)
		return
	}
	reference := m.nextReference
	m.nextReference = (m.nextReference + 1) % 256
	m.sent = append(m.sent, SentSMS{Reference: reference, PDU: pdu, TPDU: tpdu})
	m.answer(at, []string{fmt.Sprintf("+CMGS: %d", reference)}, resultOK, urc)
}

func (m *Modem) ussdCommand(set bool, fields []string) ([]string, string) {
	if !set || len(fields) == 0 {
		return nil, resultError
	}
	if intArg(fields, 0, 0) == 2 || len(fields) < 2 {
		return nil, resultOK
	}
	if !m.registered() {
		return nil, m.cme(30)
	}
	if m.ussd != nil {
		status, text := m.ussd(fields[1])
		// The network's answer arrives after the command has been confirmed.
		m.sendLine(time.Now().Add(m.delay+10*time.Millisecond), fmt.Sprintf("+CUSD: %d,%q,15", status, text))
	}
	return nil, resultOK
}

// simFileCommand answers AT+CRSM for the files of the simulated SIM.
func (m *Modem) simFileCommand(set bool, fields []string) ([]string, string) {
	if !set || len(fields) < 2 {
		return nil, resultError
	}
	if !m.simInserted {
		return nil, m.cme(10)
	}
	const readBinary = 176
	content, found := m.simFiles[intArg(fields, 1, -1)]
	if intArg(fields, 0, -1) != readBinary || !found {
		return []string{`+CRSM: 106,130,""`}, resultOK
	}
	if length := intArg(fields, 4, 0); length > 0 {
		if length > len(content) {
			return []string{`+CRSM: 103,0,""`}, resultOK
		}
		content = content[:length]
	}
	return []string{fmt.Sprintf("+CRSM: 144,0,%q", strings.ToUpper(hex.EncodeToString(content)))}, resultOK
}

// simFiles builds the elementary files a host reads from the SIM: the ICCID,
// the IMSI, the administrative data with the length of the MNC, and the
// service provider name.
func simFiles(profile Profile) map[int][]byte {
	const (
		fileICCID = 0x2FE2
		fileIMSI  = 0x6F07
		fileAD    = 0x6FAD
		fileSPN   = 0x6F46
	)
	files := map[int][]byte{}
	if profile.ICCID != "" {
		files[fileICCID] = swappedBCD(profile.ICCID)
	}
	if profile.IMSI != "" {
		// The first nibble tells that an IMSI follows and whether it has an
		// odd number of digits.
		lead := "1"
		if len(profile.IMSI)%2 == 1 {
			lead = "9"
		}
		digits := swappedBCD(lead + profile.IMSI)
		files[fileIMSI] = append([]byte{byte(len(digits))}, digits...)
	}
	if len(profile.PLMN) >= 5 {
		files[fileAD] = []byte{0x00, 0x00, 0x00, byte(len(profile.PLMN) - 3)}
	}
	if profile.ProviderName != "" {
		name := make([]byte, 17)
		for i := range name {
			name[i] = 0xFF
		}
		name[0] = 0x01
		copy(name[1:], profile.ProviderName)
		files[fileSPN] = name
	}
	return files
}

// swappedBCD packs decimal digits two to an octet, the first digit in the low
// nibble, and fills an incomplete last octet with F.
func swappedBCD(digits string) []byte {
	out := make([]byte, 0, (len(digits)+1)/2)
	for i := 0; i < len(digits); i += 2 {
		low := digits[i] - '0'
		high := byte(0x0F)
		if i+1 < len(digits) {
			high = digits[i+1] - '0'
		}
		out = append(out, high<<4|low)
	}
	return out
}

// encodeServiceCentre builds the service centre address field that precedes
// the TPDU in a PDU: its length, the type of number and the digits.
func encodeServiceCentre(number string) []byte {
	kind := byte(0x81)
	if strings.HasPrefix(number, "+") {
		kind = 0x91
		number = number[1:]
	}
	if number == "" {
		return []byte{0x00}
	}
	digits := swappedBCD(number)
	return append([]byte{byte(1 + len(digits)), kind}, digits...)
}

func numberType(number string) int {
	if strings.HasPrefix(number, "+") {
		return 145
	}
	return 129
}

func splitPLMN(plmn string) (mcc, mnc string) {
	if len(plmn) < 5 {
		return plmn, ""
	}
	return plmn[:3], plmn[3:]
}

// splitArgs splits the parameters of a command at the commas outside quotes
// and takes the quotes off.
func splitArgs(args string) []string {
	if strings.TrimSpace(args) == "" {
		return nil
	}
	var fields []string
	var field strings.Builder
	quoted := false
	for _, r := range args {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ',' && !quoted:
			fields = append(fields, strings.TrimSpace(field.String()))
			field.Reset()
		default:
			field.WriteRune(r)
		}
	}
	return append(fields, strings.TrimSpace(field.String()))
}

// intArg returns the i-th parameter as a number, or fallback when it is
// missing, empty or not a number.
func intArg(fields []string, i, fallback int) int {
	if i >= len(fields) {
		return fallback
	}
	value, err := strconv.Atoi(fields[i])
	if err != nil {
		return fallback
	}
	return value
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
