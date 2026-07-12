package policy

import (
	"fmt"
	"strings"
)

// BuildSecurityClientHeader renders the comma-separated Security-Client value
// for the template mechanisms, filling client/server SPIs and ports.
func BuildSecurityClientHeader(template IMSRegisterTemplate, spiC, spiS uint32, portC, portS int) string {
	mechanisms := template.SecurityClientMechanisms
	if len(mechanisms) == 0 {
		mechanisms = DefaultSecurityClientMechanisms()
	}

	parts := make([]string, 0, len(mechanisms))
	for _, mech := range mechanisms {
		parts = append(parts, formatSecurityClientMechanism(mech, spiC, spiS, portC, portS))
	}
	return strings.Join(parts, ",")
}

func formatSecurityClientMechanism(mech IPSec3GPPSecurityMechanism, spiC, spiS uint32, portC, portS int) string {
	alg := strings.TrimSpace(mech.Alg)
	ealg := normalizeEAlg(mech.EAlg)

	// Compact Qualcomm-style order (no spaces after ';'):
	// alg, prot, mod, ealg, spi-c, spi-s, port-c, port-s
	if prot := strings.TrimSpace(mech.Prot); prot != "" {
		mode := strings.TrimSpace(mech.Mode)
		if mode == "" {
			mode = "trans"
		}
		return fmt.Sprintf(
			"ipsec-3gpp;alg=%s;prot=%s;mod=%s;ealg=%s;spi-c=%d;spi-s=%d;port-c=%d;port-s=%d",
			alg, prot, mode, ealg, spiC, spiS, portC, portS,
		)
	}

	return fmt.Sprintf(
		"ipsec-3gpp;alg=%s;ealg=%s;spi-c=%d;spi-s=%d;port-c=%d;port-s=%d",
		alg, ealg, spiC, spiS, portC, portS,
	)
}

func normalizeEAlg(ealg string) string {
	ealg = strings.TrimSpace(ealg)
	if ealg == "" {
		return "null"
	}
	return ealg
}
