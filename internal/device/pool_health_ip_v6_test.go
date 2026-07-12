package device

import "testing"

func TestIPHealthyAcceptsV6Only(t *testing.T) {
	if !ipHealthy("", "2001:db8::1") {
		t.Fatal("v6-only should be considered healthy when v6 is present")
	}
}

func TestIPHealthyRejectsMissingAddresses(t *testing.T) {
	if ipHealthy(" ", "\t") {
		t.Fatal("blank v4/v6 should be considered unhealthy")
	}
}
