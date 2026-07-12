// Package identity builds the VoWiFi "start profile": which ePDG to dial and
// which identity/AKA application to authenticate with, for a given SIM.
//
// The ePDG address and NAI are derived per 3GPP TS 23.003 (§19.3.2 root NAI,
// §28.3.1 operator identifier FQDN) so any PLMN works with zero configuration.
// The carrier package supplies per-PLMN *overrides* for operators whose real
// deployment deviates from that default. A card with a fully-provisioned ISIM
// application (IMPI + at least one IMPU + home network domain — common on
// AT&T-issued SIMs) always takes priority over the IMSI-derived NAI, per
// normal 3GPP UE behavior.
package identity

import (
	"fmt"
	"strings"

	"github.com/1239t/vowifi-go/runtimehost/carrier"
)

// Identity is the ISIM/USIM identity read from the card. ICCID/IMSI/MSISDN
// come from the USIM; IMPI/IMPU/Domain are only present on cards with a
// provisioned ISIM application.
type Identity struct {
	ICCID  string
	IMSI   string
	MSISDN string
	IMPI   string
	IMPU   []string
	Domain string
}

type Profile struct {
	IMSI string
	MCC  string
	MNC  string
	IMEI string
	SMSC string
}

const (
	AKAAppPreferenceUSIM       = "usim"
	AKAAppPreferenceAuto       = "auto"
	AKAAppPreferenceISIM       = "isim"
	AKAAppPreferenceISIMStrict = "isim_strict"
)

const (
	IMSIdentitySourceIMSI = "imsi"
	IMSIdentitySourceISIM = "isim"
)

// IMSIdentityInfo is the resolved authentication identity for the session.
// When ActualSource is IMSIdentitySourceISIM, IMPI/IMPU/Domain are populated
// and should be used for SIP registration in place of an IMSI-derived NAI.
type IMSIdentityInfo struct {
	RequestedSource  string
	ActualSource     string
	AKAAppPreference string
	Applied          bool
	IMPI             string
	IMPU             string
	Domain           string
}

type EffectiveCarrierInfo struct {
	MCC      string
	MNC      string
	PresetID string
}

type PreparedSession struct {
	Profile            Profile
	EffectiveCarrier   EffectiveCarrierInfo
	EPDGSource         string
	EPDGAddr           string
	IdentityIMEISource string
	IMSIdentity        IMSIdentityInfo
}

// EAPIdentity returns the identity string to use as the IKE_ID / EAP-AKA
// identity: the ISIM IMPI when ActualSource is ISIM, otherwise the
// IMSI-derived 3GPP root NAI computed the same way PrepareStart resolved
// the profile in the first place. Returns "" if Profile is incomplete
// (shouldn't happen for a PreparedSession that came from a successful
// PrepareStart, but this doesn't re-validate that).
func (p PreparedSession) EAPIdentity() string {
	if p.IMSIdentity.ActualSource == IMSIdentitySourceISIM && p.IMSIdentity.IMPI != "" {
		return p.IMSIdentity.IMPI
	}
	mnc3, err := padMNC(p.Profile.MNC)
	if err != nil {
		return ""
	}
	imsi := strings.TrimSpace(p.Profile.IMSI)
	mcc := strings.TrimSpace(p.Profile.MCC)
	if imsi == "" || mcc == "" {
		return ""
	}
	return rootNAI(imsi, mcc, mnc3)
}

// IMSRealm returns the SIP/IMS realm for REGISTER and Authorization: the
// ISIM home network domain when available, otherwise the IMSI-derived
// default per 3GPP TS 23.003's "epc" realm construction (the same MCC/MNC
// pattern EAPIdentity/operatorIdentifierEPDGFQDN already use). Returns ""
// on the same incomplete-Profile conditions as EAPIdentity.
func (p PreparedSession) IMSRealm() string {
	if p.IMSIdentity.ActualSource == IMSIdentitySourceISIM && p.IMSIdentity.Domain != "" {
		return p.IMSIdentity.Domain
	}
	mnc3, err := padMNC(p.Profile.MNC)
	if err != nil {
		return ""
	}
	mcc := strings.TrimSpace(p.Profile.MCC)
	if mcc == "" {
		return ""
	}
	return "ims.mnc" + mnc3 + ".mcc" + mcc + ".3gppnetwork.org"
}

type PrepareStartInput struct {
	DeviceID            string
	Profile             Profile
	RuntimeEPDGOverride string
	Access              interface{}
}

// ISIMReader is satisfied structurally by runtimehost's ModemAccess adapter.
// It's declared here (rather than imported) so this package never needs to
// import runtimehost, which would create an import cycle.
type ISIMReader interface {
	GetISIMIdentity() (Identity, error)
}

func ReadISIMIdentity(m interface{}) (Identity, error) {
	reader, ok := m.(ISIMReader)
	if !ok {
		return Identity{}, fmt.Errorf("identity: access does not support ISIM identity read")
	}
	return reader.GetISIMIdentity()
}

// NormalizeProfile trims whitespace and canonicalizes MNC digit-width
// (stripping any leading zero) so profiles built from a 2-digit vs. 3-digit
// MNC source compare equal.
func NormalizeProfile(p Profile) Profile {
	return Profile{
		IMSI: strings.TrimSpace(p.IMSI),
		MCC:  strings.TrimSpace(p.MCC),
		MNC:  normalizeMNCDigits(strings.TrimSpace(p.MNC)),
		IMEI: strings.TrimSpace(p.IMEI),
		SMSC: strings.TrimSpace(p.SMSC),
	}
}

func normalizeMNCDigits(mnc string) string {
	trimmed := strings.TrimLeft(mnc, "0")
	if trimmed == "" && mnc != "" {
		return "0"
	}
	return trimmed
}

// padMNC normalizes a 2- or 3-digit MNC to the zero-padded 3-digit form used
// in 3GPP FQDNs (e.g. "10" -> "010").
func padMNC(mnc string) (string, error) {
	mnc = strings.TrimSpace(mnc)
	switch len(mnc) {
	case 2:
		return "0" + mnc, nil
	case 3:
		return mnc, nil
	default:
		return "", fmt.Errorf("invalid MNC %q: must be 2 or 3 digits", mnc)
	}
}

// rootNAI builds the 3GPP root NAI used for EAP-AKA at the ePDG
// (TS 23.003 §19.3.2, §28.2): "0" + IMSI + "@nai.epc.mnc<mnc3>.mcc<mcc>.3gppnetwork.org".
// The leading "0" marks this as a permanent (non-pseudonym) identity.
func rootNAI(imsi, mcc, mnc3 string) string {
	return "0" + imsi + "@nai.epc.mnc" + mnc3 + ".mcc" + mcc + ".3gppnetwork.org"
}

// operatorIdentifierEPDGFQDN builds the home ePDG FQDN per 3GPP TS 23.003 §28.3.1.
func operatorIdentifierEPDGFQDN(mcc, mnc3 string) string {
	return "epdg.epc.mnc" + mnc3 + ".mcc" + mcc + ".pub.3gppnetwork.org"
}

// resolveISIM reads the ISIM identity via Access, if the adapter supports it.
// It returns (nil, nil) when there's no ISIM on the card at all — read fails,
// or every field comes back empty — so the caller falls back to IMSI/USIM.
// It returns an error only for a *partial* ISIM identity (some fields
// populated, not all): that's a provisioning fault, not an absence, and must
// not be silently papered over by guessing at the missing pieces.
func resolveISIM(access interface{}) (*Identity, error) {
	reader, ok := access.(ISIMReader)
	if !ok {
		return nil, nil
	}
	id, err := reader.GetISIMIdentity()
	if err != nil {
		return nil, nil
	}
	impi := strings.TrimSpace(id.IMPI)
	domain := strings.TrimSpace(id.Domain)
	hasIMPU := len(id.IMPU) > 0 && strings.TrimSpace(id.IMPU[0]) != ""

	if impi == "" && domain == "" && !hasIMPU {
		return nil, nil
	}
	if impi == "" || domain == "" || !hasIMPU {
		return nil, fmt.Errorf("identity: ISIM 身份不完整 (impi=%q impu_count=%d domain=%q)", impi, len(id.IMPU), domain)
	}
	return &Identity{IMPI: impi, IMPU: id.IMPU, Domain: domain}, nil
}

func PrepareStart(input PrepareStartInput) (PreparedSession, error) {
	profile := input.Profile
	imsi := strings.TrimSpace(profile.IMSI)
	mcc := strings.TrimSpace(profile.MCC)
	mnc := strings.TrimSpace(profile.MNC)
	if imsi == "" || mcc == "" || mnc == "" {
		return PreparedSession{}, fmt.Errorf("identity: incomplete profile (imsi/mcc/mnc required)")
	}
	mnc3, err := padMNC(mnc)
	if err != nil {
		return PreparedSession{}, fmt.Errorf("identity: %w", err)
	}

	// A malformed ISIM must reject the whole start *before* the orchestrator
	// disconnects the data plane / enters flight mode, so check it first.
	isim, err := resolveISIM(input.Access)
	if err != nil {
		return PreparedSession{}, err
	}

	cfg := carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{MCC: mcc, MNC: mnc})

	prepared := PreparedSession{
		Profile: profile,
		EffectiveCarrier: EffectiveCarrierInfo{
			MCC:      mcc,
			MNC:      mnc,
			PresetID: cfg.PresetID,
		},
		IdentityIMEISource: "profile",
	}

	switch {
	case strings.TrimSpace(input.RuntimeEPDGOverride) != "":
		prepared.EPDGSource = "redirect"
		prepared.EPDGAddr = strings.TrimSpace(input.RuntimeEPDGOverride)
	case cfg.EPDGAddr != "":
		prepared.EPDGSource = "carrier_override"
		prepared.EPDGAddr = cfg.EPDGAddr
	default:
		prepared.EPDGSource = "3gpp_default"
		prepared.EPDGAddr = operatorIdentifierEPDGFQDN(mcc, mnc3)
	}

	if isim != nil {
		prepared.IMSIdentity = IMSIdentityInfo{
			RequestedSource:  "live_imsi",
			ActualSource:     IMSIdentitySourceISIM,
			AKAAppPreference: AKAAppPreferenceISIMStrict,
			Applied:          true,
			IMPI:             isim.IMPI,
			IMPU:             isim.IMPU[0],
			Domain:           isim.Domain,
		}
		return prepared, nil
	}

	akaPref := cfg.AKAAppPreference
	if akaPref == "" || akaPref == AKAAppPreferenceISIM || akaPref == AKAAppPreferenceISIMStrict {
		// No usable ISIM on the card: a preset that asks for ISIM falls back to
		// USIM rather than failing startup outright.
		akaPref = AKAAppPreferenceUSIM
	}

	if usesCarrierDeviceModelIdentity(cfg.PresetID) {
		prepared.IdentityIMEISource = "carrier_device_model"
		prepared.IMSIdentity = IMSIdentityInfo{
			RequestedSource:  "derived",
			ActualSource:     "derived",
			AKAAppPreference: akaPref,
			Applied:          false,
		}
		return prepared, nil
	}

	prepared.IMSIdentity = IMSIdentityInfo{
		RequestedSource:  "live_imsi",
		ActualSource:     IMSIdentitySourceIMSI,
		AKAAppPreference: akaPref,
		Applied:          true,
	}

	return prepared, nil
}

func usesCarrierDeviceModelIdentity(presetID string) bool {
	switch strings.TrimSpace(presetID) {
	case "giffgaff_23410":
		return true
	default:
		return false
	}
}
