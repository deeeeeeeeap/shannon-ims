package imscore

import "strings"

// Closed enum describing where the Digest AKA realm came from.
//
// A card with a provisioned ISIM supplies an operator-specific home domain.
// Without one, identity.PreparedSession.IMSRealm synthesises the TS 23.003
// form "ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org" from the PLMN digits. Both are
// legal, but a network that only knows its ISIM-provisioned domain cannot
// resolve a subscriber presented under the synthesised one, and rejecting an
// unresolvable identity before issuing a challenge is a pre-auth 403 shape.
//
// This classification exists so that case can be told apart from the other
// one without logging the realm itself.
const (
	registerRealmSourceAbsent           = "absent"
	registerRealmSource3GPPDerived      = "3gpp_derived"
	registerRealmSourceOperatorSpecific = "operator_specific"
	registerRealmSourceUnknown          = "unknown"
)

// classifyRegisterRealmSource reports whether realm equals the TS 23.003
// PLMN-derived IMS home domain for mcc/mnc.
//
// It is pure and returns one of the four closed-enum values above. The realm,
// the derived domain, the PLMN digits, and any fragment of the input are never
// returned, so the result is safe for the strict diagnostics whitelist.
func classifyRegisterRealmSource(realm, mcc, mnc string) string {
	trimmed := strings.TrimSpace(realm)
	if trimmed == "" {
		return registerRealmSourceAbsent
	}
	derived, ok := plmnDerivedIMSHomeDomain(mcc, mnc)
	if !ok {
		// Without a usable PLMN the two cannot be distinguished; never guess.
		return registerRealmSourceUnknown
	}
	if strings.EqualFold(trimmed, derived) {
		return registerRealmSource3GPPDerived
	}
	return registerRealmSourceOperatorSpecific
}

// plmnDerivedIMSHomeDomain builds the TS 23.003 IMS home domain for a PLMN.
// It reports false when MCC/MNC are not the exact 3-digit / 2-or-3-digit
// numeric forms the construction requires.
func plmnDerivedIMSHomeDomain(mcc, mnc string) (string, bool) {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	if len(mcc) != 3 || !isASCIIDigits(mcc) {
		return "", false
	}
	if !isASCIIDigits(mnc) {
		return "", false
	}
	switch len(mnc) {
	case 2:
		mnc = "0" + mnc
	case 3:
	default:
		return "", false
	}
	return "ims.mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org", true
}

func isASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// canonicalRegisterRealmSource clamps a realm-source value to the closed enum
// so a hostile or unset value can never reach a diagnostic field.
func canonicalRegisterRealmSource(value string) string {
	switch value {
	case registerRealmSourceAbsent,
		registerRealmSource3GPPDerived,
		registerRealmSourceOperatorSpecific:
		return value
	default:
		return registerRealmSourceUnknown
	}
}
