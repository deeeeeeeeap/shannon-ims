package modem

import (
	"strings"
	"sync"

	"github.com/1239t/vohive/internal/config"

	"go.bug.st/serial"
)

// SerialPortOpener opens the serial device behind an AT port name.
type SerialPortOpener func(name string, mode *serial.Mode) (serial.Port, error)

type virtualSerialPort struct {
	open SerialPortOpener
	id   uint64
}

var virtualSerialPorts struct {
	mu     sync.RWMutex
	nextID uint64
	byName map[string]virtualSerialPort
}

// RegisterVirtualSerialPort makes every later open of the AT port called name
// go to open instead of the operating system, until the returned function is
// called. It lets a software modem stand in for hardware; nothing in the
// product registers one, so a port that is not registered is always a real
// device. Registering a name again replaces the earlier opener, and the
// function returned for the earlier registration then does nothing.
func RegisterVirtualSerialPort(name string, open SerialPortOpener) (unregister func()) {
	name = strings.TrimSpace(name)
	if name == "" || open == nil {
		return func() {}
	}
	virtualSerialPorts.mu.Lock()
	virtualSerialPorts.nextID++
	id := virtualSerialPorts.nextID
	if virtualSerialPorts.byName == nil {
		virtualSerialPorts.byName = make(map[string]virtualSerialPort)
	}
	virtualSerialPorts.byName[name] = virtualSerialPort{open: open, id: id}
	virtualSerialPorts.mu.Unlock()

	return func() {
		virtualSerialPorts.mu.Lock()
		if current, ok := virtualSerialPorts.byName[name]; ok && current.id == id {
			delete(virtualSerialPorts.byName, name)
		}
		virtualSerialPorts.mu.Unlock()
	}
}

// openSerialPort is the one place this package opens an AT port.
func openSerialPort(name string, mode *serial.Mode) (serial.Port, error) {
	virtualSerialPorts.mu.RLock()
	virtual, ok := virtualSerialPorts.byName[strings.TrimSpace(name)]
	virtualSerialPorts.mu.RUnlock()
	if ok {
		return virtual.open(name, mode)
	}
	return serial.Open(name, mode)
}

// serialMode translates resolved serial settings into the mode the serial
// library takes. SerialSettings only ever holds supported values.
func serialMode(settings config.SerialSettings) *serial.Mode {
	mode := &serial.Mode{
		BaudRate: settings.BaudRate,
		DataBits: settings.DataBits,
		StopBits: serial.OneStopBit,
		Parity:   serial.NoParity,
	}
	if settings.StopBits == 2 {
		mode.StopBits = serial.TwoStopBits
	}
	switch settings.Parity {
	case "O":
		mode.Parity = serial.OddParity
	case "E":
		mode.Parity = serial.EvenParity
	}
	return mode
}

// defaultSerialMode is the line configuration used where no device entry is
// known yet, such as probing a port during discovery.
func defaultSerialMode() *serial.Mode {
	return serialMode(config.DeviceConfig{}.SerialSettings())
}
