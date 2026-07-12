package policy

import "strings"

// DefaultSecurityClientMechanisms returns the standard 6-mechanism phone-style
// Security-Client set used when a carrier preset does not override mechanisms.
func DefaultSecurityClientMechanisms() []IPSec3GPPSecurityMechanism {
	return []IPSec3GPPSecurityMechanism{
		{Alg: "hmac-md5-96", EAlg: "des-ede3-cbc"},
		{Alg: "hmac-md5-96", EAlg: "aes-cbc"},
		{Alg: "hmac-md5-96", EAlg: "null"},
		{Alg: "hmac-sha-1-96", EAlg: "des-ede3-cbc"},
		{Alg: "hmac-sha-1-96", EAlg: "aes-cbc"},
		{Alg: "hmac-sha-1-96", EAlg: "null"},
	}
}

// DefaultGiffgaffTemplate matches extracted preset giffgaff_23410.yaml and the
// embedded author binary carrier registry.
func DefaultGiffgaffTemplate() IMSRegisterTemplate {
	mechanisms := DefaultSecurityClientMechanisms()
	return IMSRegisterTemplate{
		ID:                          "giffgaff",
		SecAgreeMode:                "auto",
		IncludePANIAuthenticated:    true,
		StrictSecurityServerOffer:   true,
		EnableInitialRejectFallback: false,
		ContactParamOrder: []string{
			"access_type",
			"audio",
			"smsip",
			"icsi_ref",
			"sip_instance",
		},
		SecurityClientMechanisms: mechanisms,
	}
}

// ResolveIMSRegisterTemplate selects the IMS REGISTER behavior required by a
// home PLMN while keeping the existing generic fallback for unknown carriers.
func ResolveIMSRegisterTemplate(mcc, mnc string) IMSRegisterTemplate {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimLeft(strings.TrimSpace(mnc), "0")
	if mnc == "" {
		mnc = "0"
	}
	if mcc == "234" && mnc == "15" {
		return VodafoneUKTemplate()
	}
	return DefaultGiffgaffTemplate()
}

// VodafoneUKTemplate matches Vodafone UK's Qualcomm IMS profile: the first
// REGISTER advertises sec-agree and carries an empty AKA Authorization profile.
func VodafoneUKTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID:                                     "vodafone_uk_23415",
		SecAgreeMode:                           "on",
		IncludePANI:                            false,
		IncludePANIAuthenticated:               false,
		StrictSecurityServerOffer:              true,
		UsePlainDigestPlaceholder:              true,
		EnableInitialRejectFallback:            false,
		OmitRoute:                              true,
		MinimalInitialHeaders:                  true,
		RequireSecAgree:                        false,
		ProxyRequireSecAgree:                   false,
		OmitInitialSecurityClientProtocol:      false,
		ProbeInitialSecurityClientOnBadRequest: true,
		UserAgent:                              "Vodafone VOLTE Qualcomm",
		SupportedHeader:                        "path,sec-agree",
		ContactParamOrder: []string{
			"access_type",
			"audio",
			"smsip",
			"icsi_ref",
			"sip_instance",
			"reg_id",
		},
		SecurityClientMechanisms: DefaultSecurityClientMechanisms(),
	}
}
