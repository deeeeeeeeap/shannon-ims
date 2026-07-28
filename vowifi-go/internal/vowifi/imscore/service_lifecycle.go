package imscore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
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
		status := 0
		result := "register_failed"
		var attemptErr *registrarAttemptError
		if errors.As(err, &attemptErr) {
			status = attemptErr.statusCode
			result = attemptErr.reason
		} else if errors.Is(err, context.Canceled) {
			result = "canceled"
		}
		logRegisterDiagnostic(registerDiagnostic{
			stage:          "register_failed",
			status:         status,
			result:         result,
			transport:      s.imsCfg.Transport,
			addressFamily:  registerAddressFamily(s.cfg.PCSCFAddr),
			candidateTotal: len(s.cfg.RegistrarCandidates),
			hasWarning:     true,
			reachedAuth:    registerErrorReachedAuthPhase(err),
		})
		return newSafeRegisterFailure(err)
	}
	if err := assertProtectedChannelExclusivity(reg); err != nil {
		return err
	}
	usesProtectedTCP := protectedResultUsesTCPRuntime(reg)
	if usesProtectedTCP {
		if err := s.adoptProtectedTCPResult(reg); err != nil {
			return err
		}
	}
	if reg.portRelease != nil {
		s.protectedPortRelease = reg.portRelease
		reg.portRelease = nil
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
	s.ipsecInstalled = reg.secureConn != nil || usesProtectedTCP
	s.pcscf = winningPCSCF
	s.localAddr = s.cfg.LocalIP.String()

	if shouldStartLegacyTransportRuntime(reg) {
		rt, err := startTransportRuntime(lifecycleCtx, s.cfg, swu, reg.ipsecPolicy, reg.transport, reg.secureConn)
		if err != nil {
			logger.Warn("IMS transport runtime start failed")
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
	logger.Info("IMS TCP writer started")

	go func() {
		<-ctx.Done()
		logger.Info("IMS TCP writer stopped")
	}()
}

// attachMessaging hooks voiceclient for SMS/USSD after imscore registration.
func (s *Service) attachMessaging(ctx context.Context, winningPCSCF string, reg *registerResult) error {
	messagingProfile, err := messagingRegisterProfileForBehavior(s.cfg.CarrierBehavior)
	if err != nil {
		return fmt.Errorf("voiceclient attach: %w", err)
	}
	if s != nil && s.protectedRuntimes != nil && s.protectedRuntimes.current() != nil {
		if reg == nil || reg.protectedClientConn == nil {
			return fmt.Errorf("voiceclient attach: protected TCP client flow unavailable")
		}
		runtime := s.protectedRuntimes.current()
		clientConn := reg.protectedClientConn
		reg.protectedClientConn = nil
		streamConn, err := newProtectedTCPMessagingConn(runtime, clientConn)
		if err != nil {
			_ = clientConn.Close()
			return fmt.Errorf("voiceclient attach: %w", err)
		}
		protectedPCSCF := strings.TrimSpace(winningPCSCF)
		if protectedPCSCF == "" {
			protectedPCSCF = strings.TrimSpace(s.cfg.PCSCFAddr)
		}
		voiceCfg := voiceclient.Config{
			DeviceID:        s.cfg.DeviceID,
			TraceID:         s.cfg.TraceID,
			LocalIP:         s.cfg.LocalIP,
			LocalPort:       reg.ipsecPolicy.FlowC.LocalPort,
			ContactPort:     reg.ipsecPolicy.FlowS.LocalPort,
			PCSCFAddr:       protectedPCSCF,
			SecurityVerify:  reg.verifyHeader,
			SMSC:            s.cfg.SMSC,
			ServiceRoutes:   append([]string(nil), reg.serviceRoutes...),
			Realm:           s.cfg.Realm,
			PrivateID:       s.cfg.PrivateID,
			PublicURI:       s.cfg.PublicURI,
			HomeDomain:      s.cfg.HomeDomain,
			IMSI:            s.cfg.IMSI,
			Transport:       "tcp",
			MCC:             s.cfg.MCC,
			MNC:             s.cfg.MNC,
			CellID:          s.cfg.CellID,
			AKA:             s.cfg.AKA,
			DeliveryStore:   s.cfg.DeliveryStore,
			SIPInstanceURN:  s.cfg.SIPInstanceURN,
			RegisterProfile: messagingProfile,
			SkipRegister:    true,
		}
		if s.cfg.RegisterExpirySeconds > 0 {
			voiceCfg.RegisterExpiry = time.Duration(s.cfg.RegisterExpirySeconds) * time.Second
		}
		inner, err := voiceclient.AttachSecureStreamMessaging(ctx, voiceCfg, streamConn)
		if err != nil {
			_ = streamConn.Close()
			return fmt.Errorf("voiceclient attach: %w", err)
		}
		s.inner = inner
		return nil
	}
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
		RegisterProfile: messagingProfile,
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

func messagingRegisterProfileForBehavior(behavior policy.CarrierBehavior) (voiceclient.RegisterProfile, error) {
	switch behavior.MessagingPresentation {
	case "", policy.MessagingPresentationSimAdminGBEE:
		return voiceclient.SimAdminGBEERegisterProfile(), nil
	default:
		return voiceclient.RegisterProfile{}, fmt.Errorf(
			"unsupported messaging presentation %q",
			behavior.MessagingPresentation,
		)
	}
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
