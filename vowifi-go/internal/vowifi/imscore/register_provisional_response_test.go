package imscore

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/emiago/sipgo/sip"
)

func TestRegisterTransportsWaitForFinalResponse(t *testing.T) {
	for _, kind := range []string{"stream", "packet"} {
		for _, coalesced := range []bool{false, true} {
			for _, status := range []int{200, 401, 403} {
				t.Run(fmt.Sprintf("%s/coalesced=%t/final=%d", kind, coalesced, status), func(t *testing.T) {
					conn, peer := net.Pipe()
					t.Cleanup(func() { conn.Close(); peer.Close() })
					var reader interface {
						ReadResponse(context.Context) (*sip.Response, error)
					}
					if kind == "stream" {
						transport, err := newStreamRegisterTransport(conn)
						if err != nil {
							t.Fatal(err)
						}
						reader = transport
					} else {
						reader = newConnRegisterTransport(conn, "", "", "udp")
					}
					provisional := "SIP/2.0 100 Trying\r\nContent-Length: 0\r\n\r\n"
					final := fmt.Sprintf("SIP/2.0 %d Synthetic\r\nContent-Length: 0\r\n\r\n", status)
					go func() {
						defer peer.Close()
						if coalesced {
							_, _ = peer.Write([]byte(provisional + final))
							return
						}
						if _, err := peer.Write([]byte(provisional)); err == nil {
							_, _ = peer.Write([]byte(final))
						}
					}()
					response, err := reader.ReadResponse(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != status {
						t.Fatalf("status=%d, want final=%d", response.StatusCode, status)
					}
				})
			}
		}
	}
}
