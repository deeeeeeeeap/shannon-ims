package atsim

import (
	"errors"
	"time"

	"go.bug.st/serial"
)

// The texts are the ones the serial library and the operating system give for
// the same conditions; code that tells them apart by text sees no difference.
var (
	errPortClosed  = errors.New("Port has been closed")
	errPortBusy    = errors.New("Serial port busy")
	errPortMissing = errors.New("Serial port not found")
	errDeviceGone  = errors.New("input/output error")
)

// chunk is output of the modem that becomes readable at a given time.
type chunk struct {
	at   time.Time
	data []byte
}

// port is the host's end of the serial line. Its fields are guarded by the
// modem's mutex.
type port struct {
	modem *Modem
	// wake receives when output arrives or the state of the port changes.
	wake    chan struct{}
	timeout time.Duration
	closed  bool
	// gone is set when the device goes away while the port is open.
	gone bool
	out  []chunk
}

// Open opens the modem's AT port. It has the signature of the AT manager's
// port opener; the name is not looked at.
func (m *Modem) Open(_ string, mode *serial.Mode) (serial.Port, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.expire(now)
	if m.unplugged || now.Before(m.bootUntil) {
		return nil, errPortMissing
	}
	if m.port != nil {
		return nil, errPortBusy
	}
	p := &port{modem: m, wake: make(chan struct{}, 1), timeout: serial.NoTimeout}
	m.port = p
	m.opens++
	if mode != nil {
		m.mode = *mode
	}
	if m.announce {
		m.announce = false
		m.sendLine(now, "RDY")
		if m.simInserted {
			m.sendLine(now, "+CPIN: READY")
		}
	}
	return p, nil
}

func (p *port) signal() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Read returns what the modem has sent. Like the serial library it returns no
// bytes and no error when the read timeout passes, and fails once the port
// has been closed or its device has gone.
func (p *port) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	m := p.modem
	var deadline time.Time
	m.mu.Lock()
	if p.timeout >= 0 {
		deadline = time.Now().Add(p.timeout)
	}
	m.mu.Unlock()

	for {
		now := time.Now()
		m.mu.Lock()
		m.expire(now)
		if p.closed || p.gone {
			m.mu.Unlock()
			return 0, errPortClosed
		}
		n, next := p.take(dst, now)
		if !m.removeAt.IsZero() && (next.IsZero() || m.removeAt.Before(next)) {
			next = m.removeAt
		}
		m.mu.Unlock()
		if n > 0 {
			return n, nil
		}

		wait := time.Duration(-1)
		if !deadline.IsZero() {
			wait = deadline.Sub(now)
			if wait <= 0 {
				return 0, nil
			}
		}
		if !next.IsZero() {
			if until := next.Sub(now); wait < 0 || until < wait {
				wait = until
			}
		}
		if wait < 0 {
			<-p.wake
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-p.wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// take moves the output that is due into dst. When nothing is due it returns
// the time the next output becomes due, if there is any.
func (p *port) take(dst []byte, now time.Time) (int, time.Time) {
	n := 0
	for len(p.out) > 0 && n < len(dst) {
		head := &p.out[0]
		if head.at.After(now) {
			if n == 0 {
				return 0, head.at
			}
			break
		}
		copied := copy(dst[n:], head.data)
		n += copied
		head.data = head.data[copied:]
		if len(head.data) == 0 {
			p.out = p.out[1:]
		}
	}
	return n, time.Time{}
}

// Write gives the modem what the host wrote.
func (p *port) Write(src []byte) (int, error) {
	m := p.modem
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expire(time.Now())
	if p.closed {
		return 0, errPortClosed
	}
	if p.gone {
		return 0, errDeviceGone
	}
	m.receive(src)
	return len(src), nil
}

// Close closes the port. A read that is waiting returns with an error.
func (p *port) Close() error {
	m := p.modem
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	p.out = nil
	if m.port == p {
		m.port = nil
		m.line = nil
		m.prompt = nil
	}
	p.signal()
	return nil
}

// SetReadTimeout sets how long a read waits for data; serial.NoTimeout makes
// it wait without limit.
func (p *port) SetReadTimeout(timeout time.Duration) error {
	if timeout < 0 && timeout != serial.NoTimeout {
		return errors.New("invalid read timeout")
	}
	p.modem.mu.Lock()
	defer p.modem.mu.Unlock()
	if p.closed {
		return errPortClosed
	}
	p.timeout = timeout
	return nil
}

// SetMode records the mode; a simulated line has no bit rate to honour.
func (p *port) SetMode(mode *serial.Mode) error {
	p.modem.mu.Lock()
	defer p.modem.mu.Unlock()
	if p.closed {
		return errPortClosed
	}
	if mode != nil {
		p.modem.mode = *mode
	}
	return nil
}

// ResetInputBuffer discards what the modem has sent and the host has not read.
func (p *port) ResetInputBuffer() error {
	p.modem.mu.Lock()
	defer p.modem.mu.Unlock()
	if p.closed {
		return errPortClosed
	}
	p.out = nil
	return nil
}

func (p *port) ResetOutputBuffer() error  { return nil }
func (p *port) Drain() error              { return nil }
func (p *port) SetDTR(bool) error         { return nil }
func (p *port) SetRTS(bool) error         { return nil }
func (p *port) Break(time.Duration) error { return nil }

func (p *port) GetModemStatusBits() (*serial.ModemStatusBits, error) {
	return &serial.ModemStatusBits{CTS: true, DSR: true, DCD: true}, nil
}

// send queues bytes for the host. They become readable at the given time and
// never before bytes that were queued for an earlier time.
func (m *Modem) send(at time.Time, data []byte) {
	p := m.port
	if p == nil || len(data) == 0 {
		return
	}
	i := len(p.out)
	for i > 0 && p.out[i-1].at.After(at) {
		i--
	}
	p.out = append(p.out, chunk{})
	copy(p.out[i+1:], p.out[i:])
	p.out[i] = chunk{at: at, data: data}
	p.signal()
}

// sendLine queues one line the way a module frames it.
func (m *Modem) sendLine(at time.Time, line string) {
	m.send(at, []byte("\r\n"+line+"\r\n"))
}
