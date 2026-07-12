package device

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVoWiFiVoiceLifecycleIsNotHostReadyCallbackGlue(t *testing.T) {
	root := filepath.Join("..", "..")
	files := []string{
		filepath.Join(root, "cmd", "vohive", "main.go"),
		filepath.Join("pool.go"),
		filepath.Join("pool_vowifi_runtime.go"),
		filepath.Join("pool_vowifi_wiring.go"),
	}
	forbidden := []string{
		"IMS" + "SessionProvider",
		"SetOn" + "VoWiFiReady",
		"on" + "VoWiFiReady",
		"wait" + "VoWiFiIMSReadyAndNotify",
		"unregister" + "VoiceAgentForVoWiFiTeardown",
	}

	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", file, err)
		}
		for _, token := range forbidden {
			if strings.Contains(string(body), token) {
				t.Fatalf("%s still contains host-owned VoWiFi voice lifecycle glue token %q", file, token)
			}
		}
	}
}
