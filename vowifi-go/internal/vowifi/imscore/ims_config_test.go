package imscore

import (
	"testing"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

func TestEmptyCarrierBehaviorDefaultsTo3GPP(t *testing.T) {
	imsCfg := IMSConfigFromVoice(voiceclient.Config{}, policy.CarrierBehavior{}, "")
	if got := imsCfg.CarrierBehavior.RegisterTemplate.ID; got != "3gpp-default" {
		t.Fatalf("IMSConfig template ID = %q, want 3gpp-default", got)
	}

	internal := internalConfigFromIMS(IMSConfig{}, StartSessionInput{})
	if got := internal.CarrierBehavior.RegisterTemplate.ID; got != "3gpp-default" {
		t.Fatalf("internal Config template ID = %q, want 3gpp-default", got)
	}
}
