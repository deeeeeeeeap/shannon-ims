package imscore

import (
	"fmt"
	"strings"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
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
	// RFC 3310 section 4 requires a realm directive in the Digest AKA
	// Authorization header. identity.PreparedSession.IMSRealm returns "" when
	// the profile lacks a usable MCC/MNC, so reject it here instead of emitting
	// an Authorization header with realm="".
	if strings.TrimSpace(imsCfg.Realm) == "" {
		return nil, fmt.Errorf("imscore: IMS realm is required")
	}

	behavior := imsCfg.CarrierBehavior
	if behavior.RegisterWireFormat == "" {
		behavior = policy.Default3GPPBehavior()
	}
	imsCfg.CarrierBehavior = behavior
	template := behavior.RegisterTemplate
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
		imsCfg:            imsCfg,
		cfg:               internal,
		network:           network,
		protectedChannels: ipsec3gpp.NewProtectedChannelOwner(),
	}, nil
}

func logIMSConfigResolved(imsCfg IMSConfig, cfg Config, candidateCount int) {
	// realm_source distinguishes an ISIM-provisioned operator home domain from
	// the TS 23.003 PLMN-derived fallback. Only the closed enum is logged; the
	// realm and PLMN digits are not.
	realm := strings.TrimSpace(cfg.Realm)
	if realm == "" {
		realm = strings.TrimSpace(imsCfg.Realm)
	}
	logRegisterDiagnostic(registerDiagnostic{
		stage:            "config_resolved",
		result:           "none",
		transport:        imsCfg.Transport,
		addressFamily:    registerAddressFamily(imsCfg.Registrar),
		candidateTotal:   candidateCount,
		requiresSecAgree: imsCfg.CarrierBehavior.RegisterTemplate.RequireSecAgree || imsCfg.CarrierBehavior.RegisterTemplate.ProxyRequireSecAgree,
		realmSource:      classifyRegisterRealmSource(realm, cfg.MCC, cfg.MNC),
	})
}
