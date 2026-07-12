package imscore

import (
	"fmt"
	"strings"

	"github.com/emiago/sipgo/sip"
)

type initialRegisterSecurityDecision struct {
	accept           bool
	requireIPSec     bool
	plainOK          bool
	reason           string
	securityServer   bool
}

// decideInitialRegisterSuccessSecurity handles REGISTER 200 before auth challenge.
func decideInitialRegisterSuccessSecurity(cfg Config, res *sip.Response) (initialRegisterSecurityDecision, error) {
	if res == nil {
		return initialRegisterSecurityDecision{}, fmt.Errorf("missing REGISTER response")
	}
	if res.StatusCode != sip.StatusOK {
		return initialRegisterSecurityDecision{}, fmt.Errorf("unexpected status %d", res.StatusCode)
	}

	secServer := res.GetHeader("Security-Server")
	hasServer := secServer != nil && strings.TrimSpace(secServer.Value()) != ""
	secAgree := secAgreeEnabled(cfg.Template)

	switch {
	case hasServer && secAgree:
		return initialRegisterSecurityDecision{
			accept:         true,
			requireIPSec:   true,
			securityServer: true,
			reason:         "initial_200_security_server_without_ipsec_install_required",
		}, nil
	case hasServer && !secAgree:
		return initialRegisterSecurityDecision{
			accept:         true,
			requireIPSec:   false,
			securityServer: true,
			reason:         "initial_200_security_server_ignored_without_ipsec_install",
		}, nil
	case !hasServer && secAgree:
		return initialRegisterSecurityDecision{
			accept:   true,
			plainOK:  true,
			reason:   "initial_200_without_security_server_auto_plain",
		}, nil
	default:
		return initialRegisterSecurityDecision{
			accept:  true,
			plainOK: true,
			reason:  "initial_200_plain",
		}, nil
	}
}