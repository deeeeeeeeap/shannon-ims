package device

import (
	"os"
	"strings"
	"testing"
)

func TestVoWiFiRuntimeDispatcherUsesEventhost(t *testing.T) {
	body, err := os.ReadFile("vowifi_dispatcher.go")
	if err != nil {
		t.Fatalf("read vowifi_dispatcher.go: %v", err)
	}
	source := string(body)
	for _, marker := range []string{
		"runtimehost.EventDispatcher",
		"runtimehost.ModuleEvent",
		"runtimehost.EventSMSReceived",
		"runtimehost.EventSMSSent",
		"runtimehost.EventLocalNumberLearned",
		"runtimehost.EventLogNotify",
	} {
		if strings.Contains(source, marker) {
			t.Fatalf("vowifi_dispatcher.go still depends on legacy runtimehost event contract %q", marker)
		}
	}
}
