package imscore

import (
	"testing"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/emiago/sipgo/sip"
)

func TestBuildSecurityVerifyPreservesSecurityServerValueVerbatim(t *testing.T) {
	const securityServer = "ipsec-3gpp;q=0.9;alg=hmac-sha-1-96;mod=trans;ealg=aes-cbc, " +
		"ipsec-3gpp;q=0.8;alg=hmac-sha-1-96;mod=trans;ealg=null;spi-c=101;spi-s=102;port-c=5062;port-s=5063"

	res := sip.NewResponse(sip.StatusUnauthorized, "Unauthorized")
	res.AppendHeader(sip.NewHeader("Security-Server", securityServer))
	cfg := Config{Template: policy.ResolveIMSRegisterTemplate("234", "15")}

	verify, selected, err := buildSecurityVerifyFromChallenge(cfg, res)
	if err != nil {
		t.Fatalf("buildSecurityVerifyFromChallenge: %v", err)
	}
	if selected == nil {
		t.Fatal("buildSecurityVerifyFromChallenge returned no selected offer")
	}
	if verify != securityServer {
		t.Fatalf("Security-Verify = %q, want verbatim Security-Server %q", verify, securityServer)
	}
}
