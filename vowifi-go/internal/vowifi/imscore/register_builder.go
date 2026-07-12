package imscore

import (
	"strings"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

// buildTemplateSecurityClient renders the single preferred Security-Client
// mechanism used on the initial REGISTER (author register_builder.go).
func buildTemplateSecurityClient(template policy.IMSRegisterTemplate, spiC, spiS uint32, portC, portS int) string {
	return buildInitialSecurityClient(template, initialRegisterVariant{}, spiC, spiS, portC, portS)
}

func buildInitialSecurityClient(template policy.IMSRegisterTemplate, variant initialRegisterVariant, spiC, spiS uint32, portC, portS int) string {
	mech := preferredSecurityClientMechanism(template)
	if variant.hasSecurityClientMechanism {
		mech = variant.securityClientMechanism
	}
	if template.OmitInitialSecurityClientProtocol {
		mech.Prot = ""
		mech.Mode = ""
	} else {
		if strings.TrimSpace(mech.Prot) == "" {
			mech.Prot = "esp"
		}
		if strings.TrimSpace(mech.Mode) == "" {
			mech.Mode = "trans"
		}
	}
	return policy.BuildSecurityClientHeader(
		policy.IMSRegisterTemplate{SecurityClientMechanisms: []policy.IPSec3GPPSecurityMechanism{mech}},
		spiC, spiS, portC, portS,
	)
}


func initialSecurityClientProbeMechanisms(template policy.IMSRegisterTemplate) []policy.IPSec3GPPSecurityMechanism {
	type pair struct {
		alg  string
		ealg string
	}
	desired := []pair{
		{alg: "hmac-sha-1-96", ealg: "aes-cbc"},
		{alg: "hmac-sha-1-96", ealg: "null"},
		{alg: "hmac-sha-1-96", ealg: "des-ede3-cbc"},
		{alg: "hmac-md5-96", ealg: "null"},
		{alg: "hmac-md5-96", ealg: "aes-cbc"},
		{alg: "hmac-md5-96", ealg: "des-ede3-cbc"},
	}
	supported := supportedSecurityClientMechanisms(template)
	out := make([]policy.IPSec3GPPSecurityMechanism, 0, len(desired))
	for _, want := range desired {
		for _, mechanism := range supported {
			if strings.EqualFold(strings.TrimSpace(mechanism.Alg), want.alg) &&
				strings.EqualFold(canonicalTemplateEAlg(mechanism.EAlg), want.ealg) {
				out = append(out, mechanism)
				break
			}
		}
	}
	return out
}

// buildFullSecurityClient renders all template mechanisms for sec-agree verify
// rounds that require the full client capability set.
func buildFullSecurityClient(template policy.IMSRegisterTemplate, spiC, spiS uint32, portC, portS int) string {
	return policy.BuildSecurityClientHeader(template, spiC, spiS, portC, portS)
}

func preferredSecurityClientMechanism(template policy.IMSRegisterTemplate) policy.IPSec3GPPSecurityMechanism {
	mechanisms := supportedSecurityClientMechanisms(template)
	for i := len(mechanisms) - 1; i >= 0; i-- {
		m := mechanisms[i]
		if strings.EqualFold(strings.TrimSpace(m.Alg), "hmac-sha-1-96") &&
			strings.EqualFold(canonicalTemplateEAlg(m.EAlg), "aes-cbc") {
			return policy.IPSec3GPPSecurityMechanism{
				Alg:  m.Alg,
				EAlg: m.EAlg,
				Prot: "esp",
				Mode: "trans",
			}
		}
	}
	if len(mechanisms) > 0 {
		m := mechanisms[len(mechanisms)-1]
		if strings.TrimSpace(m.Prot) == "" {
			m.Prot = "esp"
		}
		if strings.TrimSpace(m.Mode) == "" {
			m.Mode = "trans"
		}
		return m
	}
	return policy.IPSec3GPPSecurityMechanism{
		Alg:  "hmac-sha-1-96",
		EAlg: "aes-cbc",
		Prot: "esp",
		Mode: "trans",
	}
}

func supportedSecurityClientMechanisms(template policy.IMSRegisterTemplate) []policy.IPSec3GPPSecurityMechanism {
	if len(template.SecurityClientMechanisms) > 0 {
		return template.SecurityClientMechanisms
	}
	return policy.DefaultSecurityClientMechanisms()
}

func securityClientMechanismCount(template policy.IMSRegisterTemplate) int {
	return len(supportedSecurityClientMechanisms(template))
}

func canonicalTemplateEAlg(ealg string) string {
	ealg = strings.TrimSpace(strings.ToLower(ealg))
	if ealg == "" || ealg == "null" {
		return "null"
	}
	return ealg
}

func secAgreeEnabled(template policy.IMSRegisterTemplate) bool {
	mode := strings.ToLower(strings.TrimSpace(template.SecAgreeMode))
	return mode == "" || mode == "auto" || mode == "on" || mode == "true"
}
