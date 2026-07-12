//go:build linux

package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	externalsim "github.com/1239t/swu-go/pkg/sim"
	externalswu "github.com/1239t/swu-go/pkg/swu"
	swusim "github.com/1239t/vowifi-go/engine/sim"
)

type externalSIMAdapter struct {
	inner SIMAdapter
}

func (a externalSIMAdapter) GetIMSI() (string, error) {
	if a.inner == nil {
		return "", externalsim.ErrSIMNotPresent
	}
	return a.inner.GetIMSI()
}

func (a externalSIMAdapter) CalculateAKA(randBytes, autnBytes []byte) (res, ck, ik, auts []byte, err error) {
	if a.inner == nil {
		return nil, nil, nil, nil, externalsim.ErrSIMNotPresent
	}
	out, err := a.inner.CalculateAKA(randBytes, autnBytes)
	if err != nil {
		if errors.Is(err, swusim.ErrSyncFailure) {
			return nil, nil, nil, append([]byte(nil), out.AUTS...), externalsim.ErrSyncFailure
		}
		return nil, nil, nil, nil, err
	}
	return append([]byte(nil), out.RES...), append([]byte(nil), out.CK...), append([]byte(nil), out.IK...), nil, nil
}

func (a externalSIMAdapter) Close() error {
	if a.inner == nil {
		return nil
	}
	return a.inner.Close()
}

type swuInnerDataplane interface {
	SendInnerPacket([]byte) error
	InnerPackets() <-chan []byte
}

func (i *Instance) startSWuSession(ctx context.Context, req StartRequest, epdgIP, epdgPort string) (swuSnapshot, net.IP, swuInnerDataplane, func(string, string) error, error) {
	if req.SIM == nil {
		return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu tunnel failed: SIM AKA provider unavailable")
	}

	port, err := strconv.Atoi(strings.TrimSpace(epdgPort))
	if err != nil || port <= 0 || port > 65535 {
		return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu tunnel failed: invalid ePDG port %q", epdgPort)
	}
	remoteIP := net.ParseIP(epdgIP)
	if remoteIP == nil {
		return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu tunnel failed: invalid ePDG IP %q", epdgIP)
	}

	localIPStr := ""
	usingProxy := req.Proxy != nil && req.Proxy.Enabled && strings.TrimSpace(req.Proxy.Addr) != ""
	if !usingProxy {
		if outIP, err := detectOutboundIPv4(remoteIP, port); err == nil && outIP != nil {
			localIPStr = outIP.String()
		}
	}

	mnc := strings.TrimSpace(req.Profile.MNC)
	if len(mnc) < 3 {
		mnc = strings.Repeat("0", 3-len(mnc)) + mnc
	}

	cfg := &externalswu.Config{
		EpDGAddr:      epdgIP,
		EpDGPort:      uint16(port),
		APN:           "ims",
		LocalAddr:     localIPStr,
		SIM:           externalSIMAdapter{inner: req.SIM},
		EnableDriver:  true,
		DataplaneMode: externalDataplaneMode(req.Dataplane.Mode),
		MCC:           strings.TrimSpace(req.Profile.MCC),
		MNC:           mnc,
		LocalPort:     0,
	}
	applySimAdminSWuProfile(cfg, req.Profile.MCC, req.Profile.MNC)
	readyCh := make(chan struct{})
	var readyOnce sync.Once
	cfg.OnReady = func() {
		readyOnce.Do(func() { close(readyCh) })
	}
	if factory := buildSWuTransportFactory(req.Proxy); factory != nil {
		cfg.TransportFactory = factory
	}
	if usingProxy {
		logger.Info("VoWiFi SWu 将通过前置代理建立标准 IKE/UDP 隧道",
			logger.String("trace_id", strings.TrimSpace(req.TraceID)),
			logger.String("proxy_id", strings.TrimSpace(req.Proxy.ID)),
			logger.String("proxy_addr", strings.TrimSpace(req.Proxy.Addr)),
			logger.String("epdg_ip", epdgIP),
			logger.Int("epdg_port", port),
			logger.String("udp_ports", "500->4500"))
	}

	session := externalswu.NewSession(cfg, nil)
	errCh := make(chan error, 1)
	go func() { errCh <- session.Connect(ctx) }()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()

	var lastSnap swuSnapshot
	mobike := func(oldIP, newIP string) error {
		target := epdgIP
		if strings.TrimSpace(oldIP) != "" {
			_ = oldIP
		}
		return session.UpdateAddresses(newIP, target)
	}

	for {
		select {
		case <-ctx.Done():
			return swuSnapshot{}, nil, nil, nil, fmt.Errorf("%w; last_snapshot=%s", ctx.Err(), formatSWuSnapshot(lastSnap))
		case err := <-errCh:
			lastSnap = fromExternalSnapshot(session.Snapshot())
			if err != nil {
				if isDataplanePermissionError(err) {
					return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu userspace dataplane failed: configuring TUN requires root/CAP_NET_ADMIN: %w; last_snapshot=%s", err, formatSWuSnapshot(lastSnap))
				}
				return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu tunnel failed: %w; last_snapshot=%s", err, formatSWuSnapshot(lastSnap))
			}
			if !lastSnap.Established || !snapshotHasLocalIP(lastSnap) {
				return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu tunnel finished without usable Child SA; last_snapshot=%s", formatSWuSnapshot(lastSnap))
			}
			return lastSnap, preferTunnelLocalIP(lastSnap), session, mobike, nil
		case <-readyCh:
			lastSnap = fromExternalSnapshot(session.Snapshot())
			if !lastSnap.Established || !snapshotHasLocalIP(lastSnap) {
				return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu dataplane reported ready without usable tunnel IP; last_snapshot=%s", formatSWuSnapshot(lastSnap))
			}
			return lastSnap, preferTunnelLocalIP(lastSnap), session, mobike, nil
		case <-deadline.C:
			return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu tunnel timed out waiting for Child SA; last_snapshot=%s", formatSWuSnapshot(lastSnap))
		case <-ticker.C:
			lastSnap = fromExternalSnapshot(session.Snapshot())
		}
	}
}

func externalDataplaneMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "xfrmi":
		return "xfrmi"
	case "tun":
		return "tun"
	case "userspace", "user", "libipsec", "netstack", "userspace-netstack":
		return "netstack"
	default:
		return "netstack"
	}
}

func fromExternalSnapshot(s externalswu.SessionSnapshot) swuSnapshot {
	return swuSnapshot{
		Established: s.Established,
		TUNName:     s.TUNName,
		IPv4:        append(net.IP(nil), s.IPv4...),
		IPv6:        append(net.IP(nil), s.IPv6...),
		PCSCFv4:     append([]net.IP(nil), s.PCSCFv4...),
		PCSCFv6:     append([]net.IP(nil), s.PCSCFv6...),
	}
}

func snapshotHasPCSCF(s swuSnapshot) bool {
	return len(s.PCSCFv4) > 0 || len(s.PCSCFv6) > 0
}

func isDataplanePermissionError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") &&
		(strings.Contains(msg, "addr add") ||
			strings.Contains(msg, "route add") ||
			strings.Contains(msg, "link set") ||
			strings.Contains(msg, "dev tun") ||
			strings.Contains(msg, "/dev/net/tun") ||
			strings.Contains(msg, "xfrm"))
}

func snapshotHasLocalIP(s swuSnapshot) bool {
	return s.IPv4 != nil || s.IPv6 != nil
}

func formatSWuSnapshot(s swuSnapshot) string {
	return fmt.Sprintf("established=%t tun=%q ipv4=%s ipv6=%s pcscfv4=%s pcscfv6=%s",
		s.Established,
		s.TUNName,
		ipString(s.IPv4),
		ipString(s.IPv6),
		ipListString(s.PCSCFv4),
		ipListString(s.PCSCFv6),
	)
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func ipListString(ips []net.IP) string {
	if len(ips) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip != nil {
			parts = append(parts, ip.String())
		}
	}
	return strings.Join(parts, ",")
}

func preferTunnelLocalIP(s swuSnapshot) net.IP {
	if s.IPv4 != nil {
		return s.IPv4
	}
	if s.IPv6 != nil {
		return s.IPv6
	}
	return nil
}

func detectOutboundIPv4(remoteIP net.IP, remotePort int) (net.IP, error) {
	r := &net.UDPAddr{IP: remoteIP, Port: remotePort}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "udp", r.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if v4 := ua.IP.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("cannot detect outbound ip")
}