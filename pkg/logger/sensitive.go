package logger

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

var reLongDigits = regexp.MustCompile(`\d{8,}`)

func envEnabled(name string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// ShouldLogSIPRaw 返回是否允许输出 SIP 原文。
func ShouldLogSIPRaw() bool {
	return envEnabled("VOHIVE_SIP_LOG_RAW")
}

// ShouldLogSMSContent 返回是否允许输出短信明文。
func ShouldLogSMSContent() bool {
	return envEnabled("VOHIVE_SMS_LOG_CONTENT")
}

// RedactSIPRaw 对 SIP 原文做脱敏。
func RedactSIPRaw(raw string) string {
	if raw == "" {
		return raw
	}
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		lower := strings.ToLower(trim)
		if strings.HasPrefix(lower, "authorization:") || strings.HasPrefix(lower, "proxy-authorization:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				lines[i] = parts[0] + ": [REDACTED]\r"
				continue
			}
			lines[i] = "Authorization: [REDACTED]\r"
			continue
		}
		lines[i] = reLongDigits.ReplaceAllStringFunc(line, maskLongDigits)
	}
	return strings.Join(lines, "\n")
}

// RedactSMSContent 统一短信内容脱敏；开启 VOHIVE_SMS_LOG_CONTENT 时返回明文。
func RedactSMSContent(content string) string {
	if ShouldLogSMSContent() {
		return content
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return "[REDACTED len=0]"
	}
	return fmt.Sprintf("[REDACTED len=%d]", utf8.RuneCountInString(content))
}

func maskLongDigits(s string) string {
	if len(s) <= 6 {
		return strings.Repeat("*", len(s))
	}
	prefix := s[:3]
	suffix := s[len(s)-2:]
	return prefix + strings.Repeat("*", len(s)-5) + suffix
}
