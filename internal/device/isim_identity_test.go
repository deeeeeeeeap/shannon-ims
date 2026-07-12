package device

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

type fakeISIMIdentityAPDU struct {
	commands  []string
	responses []string
	closed    bool
}

func (f *fakeISIMIdentityAPDU) ResolveLogicalChannelAID(app, fallbackAID string) (string, string, error) {
	if app != "isim" {
		return "", "", fmt.Errorf("unexpected app %q", app)
	}
	return "A0000000871004FF01", "test", nil
}

func (f *fakeISIMIdentityAPDU) OpenLogicalChannel(aid string) (int, error) {
	if aid != "A0000000871004FF01" {
		return 0, fmt.Errorf("unexpected AID %q", aid)
	}
	return 3, nil
}

func (f *fakeISIMIdentityAPDU) CloseLogicalChannel(channel int) error {
	if channel != 3 {
		return fmt.Errorf("unexpected channel %d", channel)
	}
	f.closed = true
	return nil
}

func (f *fakeISIMIdentityAPDU) TransmitAPDU(channel int, command string) (string, error) {
	if channel != 3 {
		return "", fmt.Errorf("unexpected channel %d", channel)
	}
	f.commands = append(f.commands, command)
	if len(f.responses) == 0 {
		return "", fmt.Errorf("no response for %s", command)
	}
	response := f.responses[0]
	f.responses = f.responses[1:]
	return response, nil
}

func isimTLV80Response(value string) string {
	payload := append([]byte{0x80, byte(len(value))}, []byte(value)...)
	return hex.EncodeToString(append(payload, 0x90, 0x00))
}

func TestDecodeISIMIdentityTLV80(t *testing.T) {
	want := "234150000000000@ims.mnc015.mcc234.3gppnetwork.org"
	raw := append([]byte{0x80, byte(len(want))}, []byte(want)...)
	raw = append(raw, 0xff, 0xff)

	got, err := decodeISIMIdentityTLV80(raw)
	if err != nil {
		t.Fatalf("decodeISIMIdentityTLV80: %v", err)
	}
	if got != want {
		t.Fatalf("identity = %q, want %q", got, want)
	}
}

func TestReadISIMIdentityUsesReadOnlyEFCommands(t *testing.T) {
	fake := &fakeISIMIdentityAPDU{responses: []string{
		"9000",
		isimTLV80Response("234150000000000@ims.mnc015.mcc234.3gppnetwork.org"),
		"9000",
		isimTLV80Response("ims.mnc015.mcc234.3gppnetwork.org"),
		"9000",
		isimTLV80Response("sip:+447700900123@ims.mnc015.mcc234.3gppnetwork.org"),
		"6a83",
	}}

	got, err := readISIMIdentity(fake)
	if err != nil {
		t.Fatalf("readISIMIdentity: %v", err)
	}
	if got.IMPI != "234150000000000@ims.mnc015.mcc234.3gppnetwork.org" {
		t.Fatalf("IMPI = %q", got.IMPI)
	}
	if got.Domain != "ims.mnc015.mcc234.3gppnetwork.org" {
		t.Fatalf("Domain = %q", got.Domain)
	}
	if !reflect.DeepEqual(got.IMPU, []string{"sip:+447700900123@ims.mnc015.mcc234.3gppnetwork.org"}) {
		t.Fatalf("IMPU = %#v", got.IMPU)
	}
	if !fake.closed {
		t.Fatal("ISIM logical channel was not closed")
	}
	wantCommands := []string{
		"00A40004026F0200", "00B0000000",
		"00A40004026F0300", "00B0000000",
		"00A40004026F0400", "00B2010400", "00B2020400",
	}
	if !reflect.DeepEqual(fake.commands, wantCommands) {
		t.Fatalf("commands = %#v, want read-only %#v", fake.commands, wantCommands)
	}
}
