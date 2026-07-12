package device

import "testing"

func TestFormatVoWiFiPLMN3(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "trimmed numeric", in: " 24 ", want: "024"},
		{name: "already three digits", in: "530", want: "530"},
		{name: "non numeric", in: "abc", want: "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatVoWiFiPLMN3(tt.in); got != tt.want {
				t.Fatalf("formatVoWiFiPLMN3(%q)=%q want %q", tt.in, got, tt.want)
			}
		})
	}
}
