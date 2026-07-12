package server

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestBoundDialerDialsIPv6Loopback(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer ln.Close()

	d := newBoundDialer("test", "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("tcp6 dial failed: %v", err)
	}
	_ = conn.Close()
}
