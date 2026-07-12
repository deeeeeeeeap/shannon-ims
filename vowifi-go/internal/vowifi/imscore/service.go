package imscore

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

// Service is the RE-recovered imscore IMS messaging surface.
type Service struct {
	imsCfg IMSConfig
	cfg    Config

	registered      bool
	expiresSeconds  int
	verifyHeader    string
	sipSecurityMode string
	ipsecInstalled  bool
	pcscf           string
	localAddr       string
	started         bool

	network          IMSNetwork
	transportRuntime *transportRuntime
	swu              voiceclient.SWUTCPDialer

	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	inner *voiceclient.Client
}

// Dial is a compatibility wrapper around StartSessionIMSCore for legacy callers.
func Dial(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.AKA == nil {
		return nil, fmt.Errorf("imscore: Config.AKA is required")
	}
	if cfg.LocalIP == nil {
		return nil, fmt.Errorf("imscore: Config.LocalIP is required")
	}
	if strings.TrimSpace(cfg.PCSCFAddr) == "" {
		return nil, fmt.Errorf("imscore: Config.PCSCFAddr is required")
	}
	if strings.TrimSpace(cfg.PrivateID) == "" || strings.TrimSpace(cfg.PublicURI) == "" {
		return nil, fmt.Errorf("imscore: IMS identity is required")
	}

	voiceCfg := voiceclient.Config{
		DeviceID:            cfg.DeviceID,
		TraceID:             cfg.TraceID,
		LocalIP:             cfg.LocalIP,
		Dataplane:           cfg.Dataplane,
		PCSCFAddr:           cfg.PCSCFAddr,
		RegistrarCandidates: cfg.RegistrarCandidates,
		Realm:               cfg.Realm,
		PrivateID:           cfg.PrivateID,
		PublicURI:           cfg.PublicURI,
		HomeDomain:          cfg.HomeDomain,
		IMSI:                cfg.IMSI,
		MCC:                 cfg.MCC,
		MNC:                 cfg.MNC,
		CellID:              cfg.CellID,
		AKA:                 cfg.AKA,
		DeliveryStore:       cfg.DeliveryStore,
		SIPInstanceURN:      cfg.SIPInstanceURN,
		RegisterProfile:     voiceclient.RegisterProfile{UserAgent: cfg.UserAgent},
	}
	if cfg.RegisterExpirySeconds > 0 {
		voiceCfg.RegisterExpiry = time.Duration(cfg.RegisterExpirySeconds) * time.Second
	}

	network, err := NewUserspaceIMSNetwork(cfg.LocalIP, cfg.Dataplane)
	if err != nil {
		return nil, err
	}
	imsCfg := IMSConfigFromVoice(voiceCfg, cfg.Template, "")
	return StartSessionIMSCore(ctx, imsCfg, network, StartSessionInput{
		TraceID:               cfg.TraceID,
		LocalIP:               cfg.LocalIP,
		Dataplane:             cfg.Dataplane,
		RegistrarCandidates:   cfg.RegistrarCandidates,
		AKA:                   cfg.AKA,
		DeliveryStore:         cfg.DeliveryStore,
		IMSI:                  cfg.IMSI,
		MCC:                   cfg.MCC,
		MNC:                   cfg.MNC,
		CellID:                cfg.CellID,
		RegisterExpirySeconds: cfg.RegisterExpirySeconds,
	})
}

func (s *Service) SendSMS(ctx context.Context, peer, content string, parts []messaging.SMSPart) (messaging.SendOutcome, error) {
	if s == nil || s.inner == nil {
		return messaging.SendOutcome{}, fmt.Errorf("IMS service not ready")
	}
	return s.inner.SendSMS(ctx, peer, content, parts)
}

func (s *Service) SendUSSD(ctx context.Context, command string) (*messaging.USSDResult, error) {
	if s == nil || s.inner == nil {
		return nil, fmt.Errorf("IMS service not ready")
	}
	return s.inner.SendUSSD(ctx, command)
}

func (s *Service) ContinueUSSD(ctx context.Context, sessionID, input string) (*messaging.USSDResult, error) {
	if s == nil || s.inner == nil {
		return nil, fmt.Errorf("IMS service not ready")
	}
	return s.inner.ContinueUSSD(ctx, sessionID, input)
}

func (s *Service) CancelUSSD(ctx context.Context, sessionID string) error {
	if s == nil || s.inner == nil {
		return fmt.Errorf("IMS service not ready")
	}
	return s.inner.CancelUSSD(ctx, sessionID)
}

func (s *Service) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.lifecycleCancel != nil {
		s.lifecycleCancel()
		s.lifecycleCancel = nil
	}
	if s.transportRuntime != nil {
		s.transportRuntime.Close()
		s.transportRuntime = nil
	}
	var innerErr error
	if s.inner != nil {
		innerErr = s.inner.Close(ctx)
		s.inner = nil
	}
	if us, ok := s.network.(*UserspaceIMSNetwork); ok {
		_ = us.Close()
	} else if s.swu != nil {
		_ = s.swu.Close()
	}
	s.swu = nil
	return innerErr
}

func (s *Service) Status() map[string]interface{} {
	if s == nil {
		return map[string]interface{}{"enabled": false}
	}
	return map[string]interface{}{
		"enabled":            true,
		"device_id":          s.cfg.DeviceID,
		"registered":         s.registered,
		"reg_status":         "registered",
		"registrar":          s.pcscf,
		"local_addr":         s.localAddr,
		"sip_security_mode":  s.sipSecurityMode,
		"trace_id":           s.cfg.TraceID,
		"signaling_ready":    s.registered,
		"ipsec_installed":    s.ipsecInstalled,
		"effective_security": securityModeLabel(s.ipsecInstalled),
		"register_template":  s.imsCfg.IMSRegisterTemplate.ID,
		"preset_id":          s.imsCfg.CarrierPresetID,
		"verify":             s.verifyHeader,
		"expires_seconds":    s.expiresSeconds,
	}
}

func securityModeLabel(ipsec bool) string {
	if ipsec {
		return "ipsec3gpp"
	}
	return "plain"
}

// ConfigFromVoice builds imscore.Config from an established runtimehost voiceclient.Config.
func ConfigFromVoice(v voiceclient.Config, template policy.IMSRegisterTemplate) Config {
	return Config{
		DeviceID:              v.DeviceID,
		TraceID:               v.TraceID,
		LocalIP:               v.LocalIP,
		Dataplane:             v.Dataplane,
		PCSCFAddr:             v.PCSCFAddr,
		RegistrarCandidates:   v.RegistrarCandidates,
		Realm:                 v.Realm,
		PrivateID:             v.PrivateID,
		PublicURI:             v.PublicURI,
		HomeDomain:            v.HomeDomain,
		IMSI:                  v.IMSI,
		SMSC:                  v.SMSC,
		AKA:                   v.AKA,
		Template:              template,
		MCC:                   v.MCC,
		MNC:                   v.MNC,
		CellID:                v.CellID,
		SIPInstanceURN:        v.SIPInstanceURN,
		UserAgent:             v.RegisterProfile.UserAgent,
		RegisterExpirySeconds: int(v.RegisterExpiry / time.Second),
		DeliveryStore:         v.DeliveryStore,
	}
}

// ParsePCSCFHostPort splits a P-CSCF address for logging and policy setup.
func ParsePCSCFHostPort(addr string) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid P-CSCF host %q", host)
	}
	return ip, port, nil
}
