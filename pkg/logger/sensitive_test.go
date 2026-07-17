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

func TestRedactSMSContentEnvironmentCannotBypass(t *testing.T) {
	t.Setenv("VOHIVE_SMS_LOG_CONTENT", "true")
	in := "hello world"
	out := RedactSMSContent(in)
	if out == in || !strings.Contains(out, "[REDACTED") {
		t.Fatalf("runtime environment must not bypass SMS redaction: got=%s", out)
	}
}

func TestRawSIPLoggingCannotBeEnabledByEnvironment(t *testing.T) {
	t.Setenv("VOHIVE_SIP_LOG_RAW", "true")
	if ShouldLogSIPRaw() {
		t.Fatal("runtime environment must not enable raw SIP logging")
	}
}

func TestRedactTextPreservesLongDiagnosticIdentifiers(t *testing.T) {
	in := "post_switch_sim_auth_not_ready"
	if out := RedactText(in); out != in {
		t.Fatalf("diagnostic identifier changed: got=%q want=%q", out, in)
	}
}

func TestFingerprintIsStableWithinProcessAndDoesNotEchoInput(t *testing.T) {
	in := strings.Repeat("synthetic", 4)
	first := Fingerprint(in)
	second := Fingerprint(in)
	if first != second {
		t.Fatalf("Fingerprint() changed within one process: %q != %q", first, second)
	}
	if first == in || strings.Contains(first, in) {
		t.Fatalf("Fingerprint() echoed input: %q", first)
	}
	if other := Fingerprint(in + "-other"); other == first {
		t.Fatalf("Fingerprint() collision for distinct synthetic inputs: %q", first)
	}
}
