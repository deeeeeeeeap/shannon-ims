package smsnotify

import "testing"

func TestShouldSuppressReceivedSMS(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "sim ota encrypted",
			content: "[SIM OTA 23.048]\ndecrypt=not_attempted\nsecurity=可能加密\nraw=0011",
			want:    true,
		},
		{
			name:    "oma cp decode failed",
			content: "[OMA CP 运营商配置短信]\nwbxml_decode=failed (可能加密/非明文)\nraw=0011",
			want:    true,
		},
		{
			name:    "normal text sms",
			content: "hello world",
			want:    false,
		},
		{
			name:    "decoded oma summary",
			content: "[OMA CP 运营商配置短信]\n📋 NAPDEF\nraw=0011",
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShouldSuppressReceivedSMS(tc.content)
			if got != tc.want {
				t.Fatalf("ShouldSuppressReceivedSMS()=%v want=%v content=%q", got, tc.want, tc.content)
			}
		})
	}
}

func TestShouldSuppressSMSNotificationUsesReceivedSMSPolicy(t *testing.T) {
	content := "[SIM OTA 23.048]\ndecrypt=not_attempted\nsecurity=可能加密\nraw=0011"
	if !ShouldSuppressSMSNotification(content) {
		t.Fatal("ShouldSuppressSMSNotification() = false, want true")
	}
}
