package runtimehost

import (
	"strings"
	"testing"

	"github.com/1239t/vowifi-go/runtimehost/identity"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

// A card with a fully provisioned ISIM supplies its own IMPI (EF_IMPI), IMPU
// (EF_IMPU) and home domain (EF_DOMAIN). identity's package documentation and
// EAPIdentity both treat that ISIM identity as authoritative over an
// IMSI-derived NAI, per normal 3GPP UE behaviour (TS 31.103 stores the IMPI on
// the card; TS 24.229 has the UE register under it).
//
// The SIP Digest username must follow the same rule the public URI already
// does: prefer the card's value, synthesise only when the card has none.
// Presenting a synthesised IMPI that the network cannot resolve is a pre-auth
// rejection shape.
//
// All values below are synthetic: reserved .invalid domains and an all-zero
// test IMSI. No real identity, PLMN, or carrier host appears.
const (
	isimTestIMSI      = "000000000000000"
	isimTestIMPI      = "synthetic-impi@ims.synthetic-operator.invalid"
	isimTestIMPU      = "sip:synthetic-impu@ims.synthetic-operator.invalid"
	isimTestDomain    = "ims.synthetic-operator.invalid"
	isimTestEAPRootID = "0000000000000000@nai.epc.mnc001.mcc001.3gppnetwork.org"
)

func preparedSessionWithISIM() *identity.PreparedSession {
	return &identity.PreparedSession{
		Profile: identity.Profile{IMSI: isimTestIMSI, MCC: "001", MNC: "01"},
		IMSIdentity: identity.IMSIdentityInfo{
			RequestedSource: "live_imsi",
			ActualSource:    identity.IMSIdentitySourceISIM,
			Applied:         true,
			IMPI:            isimTestIMPI,
			IMPU:            isimTestIMPU,
			Domain:          isimTestDomain,
		},
	}
}

func preparedSessionWithoutISIM() *identity.PreparedSession {
	return &identity.PreparedSession{
		Profile: identity.Profile{IMSI: isimTestIMSI, MCC: "001", MNC: "01"},
		IMSIdentity: identity.IMSIdentityInfo{
			RequestedSource: "live_imsi",
			ActualSource:    identity.IMSIdentitySourceIMSI,
			Applied:         true,
		},
	}
}

// RED: the generic 3gpp-default path leaves AuthorizationIdentity unset, which
// currently forces the imsi_home_domain shape and discards the card's IMPI.
func TestResolveIMSRegisterIdentitiesPrefersISIMIMPI(t *testing.T) {
	prepared := preparedSessionWithISIM()
	// 3gpp-default carries no AuthorizationIdentity override.
	profile := voiceclient.RegisterProfile{}

	privateID, publicURI := resolveIMSRegisterIdentities(
		isimTestEAPRootID, isimTestIMSI, prepared, profile)

	if privateID != isimTestIMPI {
		t.Fatalf("Digest username did not use the card's ISIM IMPI")
	}
	if publicURI != isimTestIMPU {
		t.Fatalf("public URI did not use the card's ISIM IMPU")
	}
	// The synthesised shape must not appear when the card provisioned an IMPI.
	if strings.HasPrefix(privateID, isimTestIMSI+"@") {
		t.Fatal("Digest username was synthesised from the IMSI despite a provisioned ISIM IMPI")
	}
}

// An explicit imsi_home_domain request is a deliberate operator/handset
// override and must still win over the card, so existing presets keep working.
func TestResolveIMSRegisterIdentitiesHonoursExplicitIMSIShapeOverISIM(t *testing.T) {
	prepared := preparedSessionWithISIM()
	profile := voiceclient.RegisterProfile{AuthorizationIdentity: "imsi_home_domain"}

	privateID, _ := resolveIMSRegisterIdentities(
		isimTestEAPRootID, isimTestIMSI, prepared, profile)

	want := isimTestIMSI + "@" + isimTestDomain
	if privateID != want {
		t.Fatalf("explicit imsi_home_domain shape was not honoured")
	}
}

// Without an ISIM IMPI the synthesised shape remains the correct fallback.
func TestResolveIMSRegisterIdentitiesFallsBackToIMSIShapeWithoutISIM(t *testing.T) {
	prepared := preparedSessionWithoutISIM()
	profile := voiceclient.RegisterProfile{}

	privateID, _ := resolveIMSRegisterIdentities(
		isimTestEAPRootID, isimTestIMSI, prepared, profile)

	if privateID == "" {
		t.Fatal("no Digest username was resolved without an ISIM")
	}
	if !strings.HasPrefix(privateID, isimTestIMSI+"@") {
		t.Fatal("expected the IMSI-derived Digest username when the card has no ISIM IMPI")
	}
}

// A partially populated ISIM must not yield a half-card, half-synthesised
// identity: with no IMPI on the card the IMSI shape is used for the username.
func TestResolveIMSRegisterIdentitiesIgnoresBlankISIMIMPI(t *testing.T) {
	prepared := preparedSessionWithISIM()
	prepared.IMSIdentity.IMPI = "   "
	profile := voiceclient.RegisterProfile{}

	privateID, _ := resolveIMSRegisterIdentities(
		isimTestEAPRootID, isimTestIMSI, prepared, profile)

	if strings.TrimSpace(privateID) == "" {
		t.Fatal("blank ISIM IMPI produced an empty Digest username")
	}
	if !strings.HasPrefix(privateID, isimTestIMSI+"@") {
		t.Fatal("blank ISIM IMPI should fall back to the IMSI-derived username")
	}
}

// A nil PreparedSession must not panic and must not invent an identity.
func TestResolveIMSRegisterIdentitiesHandlesNilPreparedSession(t *testing.T) {
	privateID, _ := resolveIMSRegisterIdentities(
		isimTestEAPRootID, isimTestIMSI, nil, voiceclient.RegisterProfile{})
	if privateID != isimTestEAPRootID {
		t.Fatal("without a prepared session the EAP identity should remain the Digest username")
	}
}
