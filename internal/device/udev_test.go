package device

import "testing"

func TestUdevWatcherTreatsWWANPortEventsAsModemEvents(t *testing.T) {
	w := NewUdevWatcher(nil)
	event := []byte("add@/devices/platform/soc@0/4080000.remoteproc/wwan/wwan0/wwan0qmi0\x00ACTION=add\x00SUBSYSTEM=wwan\x00DEVTYPE=wwan_port\x00DEVNAME=/dev/wwan0qmi0\x00")

	if !w.isModemEvent(event) {
		t.Fatal("isModemEvent() = false, want true for SUBSYSTEM=wwan QMI port")
	}
}

func TestUdevWatcherKeepsIgnoringNonWWANNetEvents(t *testing.T) {
	w := NewUdevWatcher(nil)
	event := []byte("add@/devices/virtual/net/eth0\x00ACTION=add\x00SUBSYSTEM=net\x00INTERFACE=eth0\x00")

	if w.isModemEvent(event) {
		t.Fatal("isModemEvent() = true, want false for eth0 net event")
	}
}
