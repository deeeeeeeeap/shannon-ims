package carrier

import (
	"strings"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

// IMSRegisterProfileOptions carries optional REGISTER header overrides resolved
// from carrier_overrides.json for a home PLMN.
type IMSRegisterProfileOptions struct {
	Profile        voiceclient.RegisterProfile
	SIPInstanceURN string
	RegisterExpiry time.Duration
}

// ResolveIMSRegisterProfile returns REGISTER mimic options when a carrier preset
// requests a non-default handset profile (e.g. xiaomi_mi11 for giffgaff testing).
func ResolveIMSRegisterProfile(mcc, mnc string) IMSRegisterProfileOptions {
	preset, ok := lookup(mcc, mnc)
	if !ok {
		return IMSRegisterProfileOptions{}
	}
	switch strings.ToLower(strings.TrimSpace(preset.IMSRegisterProfile)) {
	case "xiaomi_mi11", "phone_xiaomi", "xiaomi_mi11_register":
		profile := voiceclient.XiaomiMi11RegisterProfile()
		sipInstance := voiceclient.FormatGSMAIMEIURN(strings.TrimSpace(preset.PhoneIMEI))
		if sipInstance == "" {
			sipInstance = "urn:gsma:imei:8699887-766554-4"
		}
		return IMSRegisterProfileOptions{
			Profile:        profile,
			SIPInstanceURN: sipInstance,
			RegisterExpiry: time.Duration(profile.RegisterExpirySeconds) * time.Second,
		}
	case "simadmin_gb_ee", "simadmin_ee", "gb_ee", "rmx3366":
		profile := voiceclient.SimAdminGBEERegisterProfile()
		profile.SecurityClientFormat = "phone_multi"
		profile.UserAgent = "rmx3366 VoWiFi"
		sipInstance := voiceclient.FormatGSMAIMEIURN(strings.TrimSpace(preset.PhoneIMEI))
		return IMSRegisterProfileOptions{
			Profile:        profile,
			SIPInstanceURN: sipInstance,
		}
	case "simadmin_ios", "simadmin_iphone", "iphone15", "iphone15_4_like":
		profile := voiceclient.SimAdminIOSRegisterProfile()
		return IMSRegisterProfileOptions{
			Profile: profile,
		}
	default:
		return IMSRegisterProfileOptions{}
	}
}