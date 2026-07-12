package imscore

import (
	"fmt"
	"strings"

	"github.com/1239t/swu-go/pkg/logger"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

// SetupService constructs an imscore Service from resolved IMS configuration.
func SetupService(imsCfg IMSConfig, network IMSNetwork, in StartSessionInput) (*Service, error) {
	if in.AKA == nil {
		return nil, fmt.Errorf("imscore: AKA provider is required")
	}
	if in.LocalIP == nil {
		return nil, fmt.Errorf("imscore: local IP is required")
	}
	registrar := strings.TrimSpace(imsCfg.Registrar)
	if registrar == "" {
		registrar = strings.TrimSpace(imsCfg.PCSCF)
	}
	if registrar == "" {
		return nil, fmt.Errorf("imscore: registrar/P-CSCF is required")
	}
	if strings.TrimSpace(imsCfg.IMPI) == "" || strings.TrimSpace(imsCfg.IMPU) == "" {
		return nil, fmt.Errorf("imscore: IMS identity is required")
	}

	template := imsCfg.IMSRegisterTemplate
	if strings.TrimSpace(template.ID) == "" {
		template = policy.DefaultGiffgaffTemplate()
	}
	imsCfg.IMSRegisterTemplate = template
	imsCfg.Registrar = registrar
	if strings.TrimSpace(imsCfg.PCSCF) == "" {
		imsCfg.PCSCF = registrar
	}
	if strings.TrimSpace(imsCfg.Transport) == "" {
		imsCfg.Transport = "auto"
	}
	if strings.TrimSpace(imsCfg.IMSRegisterPolicySource) == "" {
		imsCfg.IMSRegisterPolicySource = registerPolicyID(template)
	}

	discoveredRegistrar, registrarSource, candidates := discoverRegistrarViaIMSNetwork(
		append([]string(nil), in.RegistrarCandidates...),
		in.LocalIP,
		registrar,
	)
	if discoveredRegistrar != "" {
		registrar = discoveredRegistrar
		imsCfg.Registrar = registrar
		imsCfg.PCSCF = registrar
	}
	if len(candidates) == 0 {
		candidates = []string{registrar}
	}

	internal := internalConfigFromIMS(imsCfg, in)
	internal.PCSCFAddr = registrar
	internal.RegistrarCandidates = candidates
	in.RegistrarCandidates = candidates

	reportRegistrarDiscoveryProgress(internal.TraceID, imsCfg.DeviceID, registrar, registrarSource, len(candidates))
	logIMSConfigResolved(imsCfg, internal, len(candidates))

	return &Service{
		imsCfg:  imsCfg,
		cfg:     internal,
		network: network,
	}, nil
}

func logIMSConfigResolved(imsCfg IMSConfig, cfg Config, candidateCount int) {
	logger.Info("IMS config resolved",
		logger.String("device_id", strings.TrimSpace(imsCfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("registrar", strings.TrimSpace(imsCfg.Registrar)),
		logger.String("preset_id", strings.TrimSpace(imsCfg.CarrierPresetID)),
		logger.String("register_template", strings.TrimSpace(imsCfg.IMSRegisterTemplate.ID)),
		logger.String("register_policy", registerPolicyID(imsCfg.IMSRegisterTemplate)),
		logger.String("register_policy_source", strings.TrimSpace(imsCfg.IMSRegisterPolicySource)),
		logger.Int("registrar_candidates", candidateCount),
		logger.String("transport", strings.TrimSpace(imsCfg.Transport)),
		logger.Bool("strict_security_server_offer", imsCfg.IMSRegisterTemplate.StrictSecurityServerOffer))
}