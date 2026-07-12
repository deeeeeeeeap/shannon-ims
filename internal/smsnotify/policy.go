package smsnotify

import "strings"

func ShouldSuppressReceivedSMS(content string) bool {
	content = strings.TrimSpace(content)
	if content == "" {
		return false
	}
	if strings.Contains(content, "[SIM OTA 23.048]") {
		return true
	}
	if strings.Contains(content, "[OMA CP 运营商配置短信]") && strings.Contains(content, "wbxml_decode=failed") {
		return true
	}
	if strings.Contains(content, "security=可能加密") {
		return true
	}
	if strings.Contains(content, "decrypt=not_attempted") {
		return true
	}
	if strings.Contains(content, "加密/不可解码") {
		return true
	}
	return false
}

func ShouldSuppressSMSNotification(content string) bool {
	return ShouldSuppressReceivedSMS(content)
}
