package logger

import (
	"strings"
	"testing"
)

func TestRedactSIPRaw(t *testing.T) {
	in := "INVITE sip:x SIP/2.0\r\nAuthorization: Digest username=\"123456789012345\"\r\nCall-ID: 1234567890123\r\n\r\n"
	out := RedactSIPRaw(in)
	if strings.Contains(strings.ToLower(out), "digest username") {
		t.Fatalf("authorization should be redacted: %s", out)
	}
	if strings.Contains(out, "1234567890123") {
		t.Fatalf("long digit should be masked: %s", out)
	}
}

func TestRedactSMSContentDefaultHidden(t *testing.T) {
	t.Setenv("VOHIVE_SMS_LOG_CONTENT", "")
	out := RedactSMSContent("hello world")
	if !strings.Contains(out, "[REDACTED") {
		t.Fatalf("sms content should be hidden by default: %s", out)
	}
}

func TestRedactSMSContentEnabled(t *testing.T) {
	t.Setenv("VOHIVE_SMS_LOG_CONTENT", "true")
	in := "hello world"
	out := RedactSMSContent(in)
	if out != in {
		t.Fatalf("sms content should stay plaintext when enabled: got=%s", out)
	}
}
