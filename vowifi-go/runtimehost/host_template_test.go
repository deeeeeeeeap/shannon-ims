package runtimehost

import (
	"strings"
	"testing"

	"github.com/1239t/vowifi-go/runtimehost/identity"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

func TestResolveIMSRegisterTemplateForVodafoneUK(t *testing.T) {
	tmpl := resolveIMSRegisterTemplate("234", "015")
	if tmpl.ID != "vodafone_uk_23415" {
		t.Fatalf("template ID = %q, want vodafone_uk_23415", tmpl.ID)
	}
}

func TestResolveIMSUserAgentForVodafoneUK(t *testing.T) {
	tmpl := resolveIMSRegisterTemplate("234", "015")
	if got := resolveIMSUserAgent(tmpl, "SimAdmin VoWiFi"); got != "Vodafone VOLTE Qualcomm" {
		t.Fatalf("User-Agent = %q, want Vodafone VOLTE Qualcomm", got)
	}
}

func TestResolveIMSRegisterIdentitiesDefaultsToIMSIHomeDomain(t *testing.T) {
	prepared := &identity.PreparedSession{
		Profile: identity.Profile{
			IMSI: "234150000000001",
			MCC:  "234",
			MNC:  "15",
		},
	}
	eap := "0234150000000001@nai.epc.mnc015.mcc234.3gppnetwork.org"
	privateID, publicURI := resolveIMSRegisterIdentities(eap, "234150000000001", prepared, voiceclient.RegisterProfile{})
	if privateID != "234150000000001@ims.mnc015.mcc234.3gppnetwork.org" {
		t.Fatalf("privateID = %q, want IMSI@home (not EAP NAI)", privateID)
	}
	if !strings.HasPrefix(publicURI, "sip:234150000000001@") {
		t.Fatalf("publicURI = %q, want sip:IMSI@home", publicURI)
	}
	if strings.Contains(privateID, "nai.epc") {
		t.Fatalf("privateID still uses EAP NAI: %q", privateID)
	}
}

func TestResolveIMSRegisterIdentitiesKeepsPrivateIDWhenRequested(t *testing.T) {
	prepared := &identity.PreparedSession{
		Profile: identity.Profile{
			IMSI: "234150000000001",
			MCC:  "234",
			MNC:  "15",
		},
	}
	eap := "0234150000000001@nai.epc.mnc015.mcc234.3gppnetwork.org"
	privateID, _ := resolveIMSRegisterIdentities(eap, "234150000000001", prepared, voiceclient.RegisterProfile{
		AuthorizationIdentity: "private_id",
	})
	if privateID != eap {
		t.Fatalf("privateID = %q, want EAP NAI when private_id requested", privateID)
	}
}
