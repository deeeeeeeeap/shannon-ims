//go:build !linux

package runtimehost

func simAdminIMSTransport(mcc, mnc string) string {
	return "udp"
}
