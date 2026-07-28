//go:build linux

package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	externalsim "github.com/1239t/swu-go/pkg/sim"
	externalswu "github.com/1239t/swu-go/pkg/swu"
	swusim "github.com/1239t/vowifi-go/engine/sim"
	"go.uber.org/zap"
)

var errSWuConnectTimeout = errors.New("SWu tunnel timed out waiting for Child SA")

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

func (i *Instance) startSWuSession(ctx context.Context, req StartRequest, epdgIP, epdgPort string) (*swuSessionLease, error) {
	if req.SIM == nil {
		return nil, fmt.Errorf("SWu tunnel failed: SIM AKA provider unavailable")
	}

	port, err := strconv.Atoi(strings.TrimSpace(epdgPort))
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("SWu tunnel failed: invalid ePDG port %q", epdgPort)
	}
	remoteIP := net.ParseIP(epdgIP)
	if remoteIP == nil {
		return nil, fmt.Errorf("SWu tunnel failed: invalid ePDG IP %q", epdgIP)
	}

	localIPStr := ""
	usingProxy := req.Proxy != nil && req.Proxy.Enabled && strings.TrimSpace(req.Proxy.Addr) != ""
	if !usingProxy {
		detectOutbound := req.outboundIPDetector
		if detectOutbound == nil {
			detectOutbound = detectOutboundIPv4
		}
		if outIP, err := detectOutbound(remoteIP, port); err == nil && outIP != nil {
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
	lease := newSWUSessionLease(epdgIP, req.swuCandidate, req.swuConnectJoinDeadline)
	cfg.OnReady = lease.markReady
	cfg.TransportFactory = buildObservedSWuTransportFactory(req.Proxy, req.swuCandidate, logger.Get(), nil)
	if usingProxy {
		logger.Info("VoWiFi SWu 将通过前置代理建立标准 IKE/UDP 隧道",
			logger.String("trace_id", strings.TrimSpace(req.TraceID)),
			logger.String("proxy_id", strings.TrimSpace(req.Proxy.ID)),
			logger.String("proxy_addr", strings.TrimSpace(req.Proxy.Addr)),
			logger.String("epdg_ip", epdgIP),
			logger.Int("epdg_port", port),
			logger.String("udp_ports", "500->4500"))
	}

	sessionFactory := req.swuSessionFactory
	if sessionFactory == nil {
		sessionFactory = func(cfg *externalswu.Config) swuSession {
			return newExternalSWUSession(cfg)
		}
	}
	session := sessionFactory(cfg)
	if err := lease.start(session); err != nil {
		return nil, fmt.Errorf("SWu tunnel failed: %w", err)
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	connectBudget := req.swuConnectBudget
	if connectBudget <= 0 {
		connectBudget = defaultSWUTunnelBudget
	}
	deadlineC := req.swuConnectDeadline
	var deadline *time.Timer
	if deadlineC == nil {
		deadline = time.NewTimer(connectBudget)
		deadlineC = deadline.C
		defer deadline.Stop()
	}

	var lastSnap swuSnapshot

	for {
		select {
		case <-ctx.Done():
			if err := lease.CancelAndJoin(); err != nil {
				return nil, fmt.Errorf("%w; connect_join=%w; last_snapshot=%s", ctx.Err(), err, formatSWuSnapshot(lastSnap))
			}
			return nil, fmt.Errorf("%w; last_snapshot=%s", ctx.Err(), formatSWuSnapshot(lastSnap))
		case <-lease.connectDone:
			err := lease.connectResult()
			lastSnap = fromExternalSnapshot(session.Snapshot())
			if joinErr := lease.CancelAndJoin(); joinErr != nil {
				if err != nil {
					return nil, fmt.Errorf("SWu tunnel failed: %w; connect_join=%w; last_snapshot=%s", err, joinErr, formatSWuSnapshot(lastSnap))
				}
				return nil, fmt.Errorf("SWu tunnel failed: connect_join=%w; last_snapshot=%s", joinErr, formatSWuSnapshot(lastSnap))
			}
			if err != nil {
				logSWUIKEAuthInitialFailure(err)
				if isDataplanePermissionError(err) {
					return nil, fmt.Errorf("SWu userspace dataplane failed: configuring TUN requires root/CAP_NET_ADMIN: %w; last_snapshot=%s", err, formatSWuSnapshot(lastSnap))
				}
				return nil, fmt.Errorf("SWu tunnel failed: %w; last_snapshot=%s", err, formatSWuSnapshot(lastSnap))
			}
			if !lastSnap.Established || !snapshotHasLocalIP(lastSnap) {
				return nil, fmt.Errorf("SWu tunnel finished without usable Child SA; last_snapshot=%s", formatSWuSnapshot(lastSnap))
			}
			lease.setReadySnapshot(lastSnap)
			return lease, nil
		case <-lease.ready:
			lastSnap = fromExternalSnapshot(session.Snapshot())
			if !lastSnap.Established || !snapshotHasLocalIP(lastSnap) {
				if joinErr := lease.CancelAndJoin(); joinErr != nil {
					return nil, fmt.Errorf("SWu dataplane reported ready without usable tunnel IP; connect_join=%w; last_snapshot=%s", joinErr, formatSWuSnapshot(lastSnap))
				}
				return nil, fmt.Errorf("SWu dataplane reported ready without usable tunnel IP; last_snapshot=%s", formatSWuSnapshot(lastSnap))
			}
			lease.setReadySnapshot(lastSnap)
			return lease, nil
		case <-deadlineC:
			if err := lease.CancelAndJoin(); err != nil {
				return nil, fmt.Errorf("%w; connect_join=%w; last_snapshot=%s", errSWuConnectTimeout, err, formatSWuSnapshot(lastSnap))
			}
			return nil, fmt.Errorf("%w; last_snapshot=%s", errSWuConnectTimeout, formatSWuSnapshot(lastSnap))
		case <-ticker.C:
			lastSnap = fromExternalSnapshot(session.Snapshot())
		}
	}
}

type ikeAuthInitialDiagnostic interface {
	error
	Stage() string
	Result() string
	NotifyType() string
	ProtocolID() uint8
	DataLen() int
}

func logSWUIKEAuthInitialFailure(err error) {
	var diagnostic ikeAuthInitialDiagnostic
	if !errors.As(err, &diagnostic) || diagnostic.Stage() != "ike_auth_initial" {
		return
	}
	result := safeIKEAuthInitialResult(diagnostic.Result())
	fields := []zap.Field{
		logger.String("stage", "ike_auth_initial"),
		logger.String("result", result),
	}
	if result == "error_notify" {
		fields = append(fields,
			logger.String("notify_type", safeIKEAuthNotifyType(diagnostic.NotifyType())),
			logger.Int("protocol_id", int(diagnostic.ProtocolID())),
			logger.Int("data_len", boundedIKEAuthDataLen(diagnostic.DataLen())))
	}
	logger.Warn("SWu IKE_AUTH initial failure", fields...)
}

func safeIKEAuthInitialResult(result string) string {
	switch result {
	case "decrypt_failed", "integrity_failed", "error_notify", "missing_eap", "malformed", "canceled":
		return result
	default:
		return "malformed"
	}
}

func safeIKEAuthNotifyType(notifyType string) string {
	switch notifyType {
	case "unsupported_critical_payload",
		"invalid_ike_spi",
		"invalid_major_version",
		"invalid_syntax",
		"invalid_message_id",
		"invalid_spi",
		"no_proposal_chosen",
		"invalid_ke_payload",
		"authentication_failed",
		"single_pair_required",
		"no_additional_sas",
		"internal_address_failure",
		"failed_cp_required",
		"ts_unacceptable",
		"invalid_selectors",
		"temporary_failure",
		"child_sa_not_found",
		"other_error_notify":
		return notifyType
	default:
		return "other_error_notify"
	}
}

func boundedIKEAuthDataLen(dataLen int) int {
	if dataLen < 0 {
		return 0
	}
	const maxIKEPayloadLen = 65535
	if dataLen > maxIKEPayloadLen {
		return maxIKEPayloadLen
	}
	return dataLen
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
