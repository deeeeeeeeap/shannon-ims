package imscore

import (
	"net"
	"strings"

	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

// IMSConfig is the author v1.1.2 imscore service configuration surface.
type IMSConfig struct {
	Enabled                    bool
	DeviceID                   string
	PCSCF                      string
	Registrar                  string
	Domain                     string
	Realm                      string
	IMPI                       string
	IMPU                       string
	CarrierPresetID            string
	IMSRegisterTemplate        policy.IMSRegisterTemplate
	IMSRegisterPolicySource    string
	LocalAddr                  string
	LocalPort                  int
	Transport                  string
	UserAgent                  string
	PAccessNetworkInfo         string
	CellularNetworkInfo        string
	SIPInstance                string
	IcsiRef                    string
	TCPKeepaliveSeconds        int
	OptionsPingIntervalSeconds int
	EnableIPSec3GPP            *bool
}

// DialOptions carries TCP dial tuning for IMSNetwork.DialContext.
type DialOptions struct {
	Timeout   int64
	KeepAlive int64
	TCPMSS    int
}

// StartSessionInput carries runtimehost session context not present on IMSConfig.
type StartSessionInput struct {
	TraceID               string
	LocalIP               net.IP
	Dataplane             voiceclient.PacketDataplane
	RegistrarCandidates   []string
	AKA                   sim.AKAProvider
	DeliveryStore         messaging.DeliveryStore
	IMSI                  string
	SMSC                  string
	MCC                   string
	MNC                   string
	CellID                string
	RegisterExpirySeconds int
}

// IMSConfigFromVoice builds the author-facing IMSConfig from runtimehost inputs.
func IMSConfigFromVoice(v voiceclient.Config, template policy.IMSRegisterTemplate, presetID string) IMSConfig {
	transport := strings.TrimSpace(v.Transport)
	if transport == "" {
		transport = "auto"
	}
	policySource := "default"
	if id := strings.TrimSpace(template.RegisterPolicy.ID); id != "" {
		policySource = id
	}
	cfg := IMSConfig{
		Enabled:                 true,
		DeviceID:                strings.TrimSpace(v.DeviceID),
		PCSCF:                   strings.TrimSpace(v.PCSCFAddr),
		Registrar:               strings.TrimSpace(v.PCSCFAddr),
		Domain:                  strings.TrimSpace(v.HomeDomain),
		Realm:                   strings.TrimSpace(v.Realm),
		IMPI:                    strings.TrimSpace(v.PrivateID),
		IMPU:                    strings.TrimSpace(v.PublicURI),
		CarrierPresetID:         strings.TrimSpace(presetID),
		IMSRegisterTemplate:     template,
		IMSRegisterPolicySource: policySource,
		Transport:               transport,
		UserAgent:               strings.TrimSpace(v.RegisterProfile.UserAgent),
		SIPInstance:             strings.TrimSpace(v.SIPInstanceURN),
	}
	if v.LocalIP != nil {
		cfg.LocalAddr = v.LocalIP.String()
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "SimAdmin VoWiFi"
	}
	if strings.TrimSpace(cfg.CarrierPresetID) == "" {
		cfg.CarrierPresetID = "3gpp-default"
	}
	if strings.TrimSpace(cfg.IMSRegisterTemplate.ID) == "" {
		cfg.IMSRegisterTemplate = policy.DefaultGiffgaffTemplate()
	}
	return cfg
}

func internalConfigFromIMS(ims IMSConfig, in StartSessionInput) Config {
	pcscf := strings.TrimSpace(ims.PCSCF)
	if pcscf == "" {
		pcscf = strings.TrimSpace(ims.Registrar)
	}
	cfg := Config{
		DeviceID:              strings.TrimSpace(ims.DeviceID),
		TraceID:               strings.TrimSpace(in.TraceID),
		LocalIP:               in.LocalIP,
		Dataplane:             in.Dataplane,
		PCSCFAddr:             pcscf,
		RegistrarCandidates:   append([]string(nil), in.RegistrarCandidates...),
		Realm:                 strings.TrimSpace(ims.Realm),
		PrivateID:             strings.TrimSpace(ims.IMPI),
		PublicURI:             strings.TrimSpace(ims.IMPU),
		HomeDomain:            strings.TrimSpace(ims.Domain),
		IMSI:                  strings.TrimSpace(in.IMSI),
		SMSC:                  strings.TrimSpace(in.SMSC),
		AKA:                   in.AKA,
		Template:              ims.IMSRegisterTemplate,
		MCC:                   strings.TrimSpace(in.MCC),
		MNC:                   strings.TrimSpace(in.MNC),
		CellID:                strings.TrimSpace(in.CellID),
		SIPInstanceURN:        strings.TrimSpace(ims.SIPInstance),
		UserAgent:             strings.TrimSpace(ims.UserAgent),
		RegisterExpirySeconds: in.RegisterExpirySeconds,
		DeliveryStore:         in.DeliveryStore,
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "SimAdmin VoWiFi"
	}
	if strings.TrimSpace(cfg.Template.ID) == "" {
		cfg.Template = policy.DefaultGiffgaffTemplate()
	}
	return cfg
}

func registerPolicyID(t policy.IMSRegisterTemplate) string {
	if id := strings.TrimSpace(t.RegisterPolicy.ID); id != "" {
		return id
	}
	return "default"
}
