package logger

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	reLongDigits   = regexp.MustCompile(`\d{8,}`)
	reLongHex      = regexp.MustCompile(`(?i)\b[0-9a-f]{24,}\b`)
	reSecretKV     = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|bearer|token|password|secret|rand|autn|auts|res|xres|ck|ik|nonce|pdu|payload|content)\b(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;]+)`)
	fingerprintKey = newFingerprintKey()
)

func newFingerprintKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil
	}
	return key
}

// ShouldLogSIPRaw is retained for compatibility; raw SIP logging is disabled.
func ShouldLogSIPRaw() bool {
	return false
}

// ShouldLogSMSContent is retained for compatibility; SMS plaintext logging is disabled.
func ShouldLogSMSContent() bool {
	return false
}

// RedactSIPRaw 对 SIP 原文做脱敏。
func RedactSIPRaw(raw string) string {
	return RedactText(raw)
}

// RedactSMSContent always emits metadata; runtime flags cannot enable plaintext.
func RedactSMSContent(content string) string {
	return redactionSummary("sms_content", content)
}

// RedactText removes credential assignments, raw auth headers, long identities,
// and opaque blobs from free-form messages and errors.
func RedactText(text string) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "authorization:") || strings.HasPrefix(lower, "proxy-authorization:") {
			name := strings.SplitN(trimmed, ":", 2)[0]
			lines[i] = name + ": [REDACTED]"
			continue
		}
		line = reSecretKV.ReplaceAllString(line, "${1}${2}[REDACTED]")
		line = reLongDigits.ReplaceAllStringFunc(line, func(value string) string {
			return redactionSummary("digits", value)
		})
		line = reLongHex.ReplaceAllStringFunc(line, func(value string) string {
			return redactionSummary("hex", value)
		})
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

// Fingerprint returns a short one-way diagnostic identifier, never raw input.
func Fingerprint(value string) string {
	if value == "" {
		return "missing"
	}
	if len(fingerprintKey) == 0 {
		return "unavailable"
	}
	mac := hmac.New(sha256.New, fingerprintKey)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil)[:8])
}

func redactionSummary(kind, value string) string {
	return fmt.Sprintf("[REDACTED kind=%s len=%d fp=%s]", normalizeLogKey(kind), utf8.RuneCountInString(value), Fingerprint(value))
}
