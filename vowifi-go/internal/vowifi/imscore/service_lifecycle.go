package imscore

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"

	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

// Start runs the full IMS Core lifecycle: REGISTER FSM, ipsec transport runtime,
// TCP write scheduler, and post-register messaging attach.
func (s *Service) Start(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("imscore: service is nil")
	}
	if s.cfg.AKA == nil {
		return fmt.Errorf("imscore: Config.AKA is required")
	}
	if s.cfg.LocalIP == nil {
		return fmt.Errorf("imscore: Config.LocalIP is required")
	}

	addr := strings.TrimSpace(s.imsCfg.Registrar)
	if addr == "" {
		addr = strings.TrimSpace(s.cfg.PCSCFAddr)
	}
	logger.Info(fmt.Sprintf("[%s] IMS Core 正在启动", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("addr", addr),
		logger.String("transport", strings.TrimSpace(s.imsCfg.Transport)),
		logger.String("preset_id", strings.TrimSpace(s.imsCfg.CarrierPresetID)),
		logger.String("register_template", strings.TrimSpace(s.imsCfg.IMSRegisterTemplate.ID)),
		logger.String("register_policy", registerPolicyID(s.imsCfg.IMSRegisterTemplate)),
		logger.String("register_policy_source", strings.TrimSpace(s.imsCfg.IMSRegisterPolicySource)))

	swu, err := s.resolveSWUDialer()
	if err != nil {
		return err
	}
	s.swu = swu

	lifecycleCtx, cancel := context.WithCancel(ctx)
	s.lifecycleCtx = lifecycleCtx
	s.lifecycleCancel = cancel

	registerCtx, registerCancel := context.WithTimeout(lifecycleCtx, registerDialTimeout)
	defer registerCancel()

	reg, err := s.runRegisterFlow(registerCtx)
	if err != nil {
		logger.Warn("IMS register failed",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("pcscf", s.cfg.PCSCFAddr),
			logger.Int("registrar_candidates", len(s.cfg.RegistrarCandidates)),
			logger.String("error", err.Error()))
		return fmt.Errorf("register: %w", err)
	}

	winningPCSCF := strings.TrimSpace(reg.pcscfAddr)
	if winningPCSCF == "" {
		winningPCSCF = s.cfg.PCSCFAddr
	}
	s.cfg.PCSCFAddr = winningPCSCF
	s.imsCfg.Registrar = winningPCSCF
	s.imsCfg.PCSCF = winningPCSCF

	s.registered = true
	s.expiresSeconds = reg.expiresSeconds
	s.verifyHeader = reg.verifyHeader
	s.sipSecurityMode = "ipsec3gpp"
	s.ipsecInstalled = reg.secureConn != nil
	s.pcscf = winningPCSCF
	s.localAddr = s.cfg.LocalIP.String()

	if reg.secureConn != nil && reg.transport != nil && !reg.secureConn.PacketMode() {
		rt, err := startTransportRuntime(lifecycleCtx, s.cfg, swu, reg.ipsecPolicy, reg.transport, reg.secureConn)
		if err != nil {
			logger.Warn("IMS transport runtime start failed",
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("error", err.Error()))
		} else {
			s.transportRuntime = rt
			s.logTCPWriterLoop(lifecycleCtx, reg.secureConn)
		}
	}

	if err := s.attachMessaging(lifecycleCtx, winningPCSCF, reg); err != nil {
		return err
	}
	s.started = true
	return nil
}

func (s *Service) resolveSWUDialer() (voiceclient.SWUTCPDialer, error) {
	if s == nil {
		return nil, fmt.Errorf("imscore: service is nil")
	}
	if us, ok := s.network.(*UserspaceIMSNetwork); ok && us != nil {
		if dialer := us.SWUDialer(); dialer != nil {
			return dialer, nil
		}
	}
	return newSWUNetstack(s.cfg.LocalIP, s.cfg.Dataplane)
}

func (s *Service) logTCPWriterLoop(ctx context.Context, conn net.Conn) {
	if s == nil || s.transportRuntime == nil || conn == nil {
		return
	}
	local := ""
	if conn.LocalAddr() != nil {
		local = conn.LocalAddr().String()
	}
	logger.Info(fmt.Sprintf("[%s] TCP 专用写通道调度器已启动", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("local", local))

	go func() {
		<-ctx.Done()
		logger.Info(fmt.Sprintf("[%s] TCP 专用写通道调度器已退出", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("local", local))
	}()
}

// attachMessaging hooks voiceclient for SMS/USSD after imscore registration.
func (s *Service) attachMessaging(ctx context.Context, winningPCSCF string, reg *registerResult) error {
	if reg == nil || reg.secureConn == nil || !reg.secureConn.PacketMode() {
		return fmt.Errorf("voiceclient attach: secure ESP packet channel unavailable")
	}
	protectedPCSCF := winningPCSCF
	if remoteIP := net.IP(reg.ipsecPolicy.RemoteIP); remoteIP != nil && reg.ipsecPolicy.FlowC.RemotePort > 0 {
		protectedPCSCF = net.JoinHostPort(remoteIP.String(), strconv.Itoa(reg.ipsecPolicy.FlowC.RemotePort))
	}
	voiceCfg := voiceclient.Config{
		DeviceID:        s.cfg.DeviceID,
		TraceID:         s.cfg.TraceID,
		LocalIP:         s.cfg.LocalIP,
		LocalPort:       reg.ipsecPolicy.FlowC.LocalPort,
		PCSCFAddr:       protectedPCSCF,
		SecurityVerify:  reg.verifyHeader,
		SMSC:            s.cfg.SMSC,
		ServiceRoutes:   append([]string(nil), reg.serviceRoutes...),
		Realm:           s.cfg.Realm,
		PrivateID:       s.cfg.PrivateID,
		PublicURI:       s.cfg.PublicURI,
		HomeDomain:      s.cfg.HomeDomain,
		IMSI:            s.cfg.IMSI,
		Transport:       "udp",
		MCC:             s.cfg.MCC,
		MNC:             s.cfg.MNC,
		CellID:          s.cfg.CellID,
		AKA:             s.cfg.AKA,
		DeliveryStore:   s.cfg.DeliveryStore,
		SIPInstanceURN:  s.cfg.SIPInstanceURN,
		RegisterProfile: voiceclient.SimAdminGBEERegisterProfile(),
		SkipRegister:    true,
	}
	if s.cfg.RegisterExpirySeconds > 0 {
		voiceCfg.RegisterExpiry = time.Duration(s.cfg.RegisterExpirySeconds) * time.Second
	}
	inner, err := voiceclient.AttachSecureMessaging(ctx, voiceCfg, reg.secureConn)
	if err != nil {
		return fmt.Errorf("voiceclient attach: %w", err)
	}
	s.inner = inner
	return nil
}

// Stop tears down the IMS Core lifecycle.
func (s *Service) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.lifecycleCancel != nil {
		s.lifecycleCancel()
	}
	return s.Close(ctx)
}
