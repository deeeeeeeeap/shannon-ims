package api

import "testing"

func TestServerListenAddressDefaultsEmptyHostToLoopback(t *testing.T) {
	tests := []struct {
		name string
		port string
		want string
	}{
		{name: "empty value", port: "", want: "127.0.0.1:7575"},
		{name: "plain port", port: "7575", want: "127.0.0.1:7575"},
		{name: "empty host", port: ":7575", want: "127.0.0.1:7575"},
		{name: "explicit LAN", port: "0.0.0.0:7575", want: "0.0.0.0:7575"},
		{name: "explicit loopback", port: "127.0.0.1:7575", want: "127.0.0.1:7575"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serverListenAddress(tt.port); got != tt.want {
				t.Fatalf("serverListenAddress(%q) = %q, want %q", tt.port, got, tt.want)
			}
		})
	}
}

func TestServerListenAddressWarnsOnlyForExplicitNonLoopback(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{addr: "127.0.0.1:7575", want: false},
		{addr: "localhost:7575", want: false},
		{addr: "[::1]:7575", want: false},
		{addr: "0.0.0.0:7575", want: true},
		{addr: "[::]:7575", want: true},
		{addr: "192.0.2.10:7575", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := serverListenAddressNeedsLANWarning(tt.addr); got != tt.want {
				t.Fatalf("serverListenAddressNeedsLANWarning(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestServerListenAddressReportsLoopbackDefaultCompatibilityChange(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{addr: "", want: true},
		{addr: "7575", want: true},
		{addr: ":7575", want: true},
		{addr: "127.0.0.1:7575", want: false},
		{addr: "0.0.0.0:7575", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := serverListenAddressUsesLoopbackDefault(tt.addr); got != tt.want {
				t.Fatalf("serverListenAddressUsesLoopbackDefault(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}
