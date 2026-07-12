package voiceclient

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const imsMmtelICSIRef = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"

// RegisterProfile controls carrier-specific IMS REGISTER headers.
type RegisterProfile struct {
	ContactFeatures          string
	IncludeAcceptContact     bool
	IncludePPreferredID      bool
	IncludePVisitedNetworkID bool
	IncludePAccessNetworkInfo bool
	IncludeRoute             bool
	IncludeCellularNetwork   bool
	IncludeSecurityClient    bool
	IncludeRequireSecAgree   bool
	InitialAuthorization     string
	SecurityClientFormat     string
	SupportedHeader          string
	IncludePANIAuthenticated bool
	UserAgent                string
	ContactUserRandom        bool
	RegisterExpirySeconds    int
	// VariantSet enables multi-variant REGISTER retries (e.g. "simadmin_gb_ee").
	VariantSet string
	// AuthorizationIdentity selects the digest username shape for REGISTER.
	//   "" / "private_id" — cfg.PrivateID (EAP NAI)
	//   "imsi_home_domain" — {imsi}@{realm}
	//   "prefixed_imsi_home_domain" — 0{imsi}@{realm}
	//   "imsi_phone_uri" — public URI uses ;user=phone
	AuthorizationIdentity string
}

func DefaultGBEERegisterProfile() RegisterProfile {
	return RegisterProfile{
		ContactFeatures:           "ims_features",
		IncludeAcceptContact:      true,
		IncludePPreferredID:       true,
		IncludePVisitedNetworkID:  true,
		IncludePAccessNetworkInfo: true,
		IncludeRoute:              true,
		IncludeCellularNetwork:    true,
		IncludeSecurityClient:     true,
		InitialAuthorization:      "aka_empty_uri_first",
		SecurityClientFormat:      "full_spaced",
		SupportedHeader:           "path,sec-agree,gruu",
		IncludePANIAuthenticated:  true,
		UserAgent:                 "SimAdmin VoWiFi",
	}
}

// XiaomiMi11RegisterProfile mimics a Xiaomi M2011K2G (Mi 11) VoWiFi REGISTER as
// captured on giffgaff: wlan1 accesstype, GSMA IMEI sip.instance, multi-variant
// Security-Client, and no Route/P-Access-Network-Info/P-Preferred-Identity extras.
// SimAdminGBEERegisterProfile mirrors SimAdmin GB_EE_23433 live REGISTER policy:
// rmx3366 VoWiFi UA, ee_ims_features contact, and the full GB EE variant set.
func SimAdminGBEERegisterProfile() RegisterProfile {
	profile := DefaultGBEERegisterProfile()
	profile.UserAgent = "rmx3366 VoWiFi"
	profile.VariantSet = "simadmin_gb_ee"
	profile.AuthorizationIdentity = "imsi_home_domain"
	return profile
}

// SimAdminIOSRegisterProfile mirrors SimAdmin iPhone handset disguise (DE O2 / NZ Spark):
// iphone15,4_like VoWiFi UA, require sec-agree, and IMS home-domain identity.
func SimAdminIOSRegisterProfile() RegisterProfile {
	profile := DefaultGBEERegisterProfile()
	profile.UserAgent = "iphone15,4_like VoWiFi"
	profile.IncludeRequireSecAgree = true
	profile.InitialAuthorization = "aka_empty_uri_first"
	profile.AuthorizationIdentity = "imsi_home_domain"
	return profile
}

func XiaomiMi11RegisterProfile() RegisterProfile {
	return RegisterProfile{
		ContactFeatures:           "phone_xiaomi",
		IncludeAcceptContact:      false,
		IncludePPreferredID:       false,
		IncludePVisitedNetworkID:  false,
		IncludePAccessNetworkInfo: false,
		IncludeRoute:              false,
		IncludeCellularNetwork:    true,
		IncludeSecurityClient:     true,
		IncludeRequireSecAgree:    true,
		InitialAuthorization:      "aka_empty_uri_first",
		SecurityClientFormat:      "phone_multi",
		SupportedHeader:           "path,sec-agree",
		IncludePANIAuthenticated:  false,
		UserAgent:                 "_M2011K2G_Qualcomm_1690275146_Android13",
		ContactUserRandom:         true,
		RegisterExpirySeconds:     600000,
	}
}

func (p RegisterProfile) Normalized() RegisterProfile {
	out := p
	if strings.TrimSpace(out.ContactFeatures) == "" {
		out.ContactFeatures = "ims_features"
	}
	if strings.TrimSpace(out.InitialAuthorization) == "" {
		out.InitialAuthorization = "aka_empty_uri_first"
	}
	if strings.TrimSpace(out.SecurityClientFormat) == "" {
		out.SecurityClientFormat = "full_spaced"
	}
	if strings.TrimSpace(out.SupportedHeader) == "" {
		out.SupportedHeader = "path,sec-agree,gruu"
	}
	if strings.TrimSpace(out.UserAgent) == "" {
		out.UserAgent = "SimAdmin VoWiFi"
	}
	return out
}

func gbEERegisterVariants() []RegisterProfile {
	return simAdminGBEERegisterVariants()
}

func simAdminGBEERegisterVariants() []RegisterProfile {
	base := SimAdminGBEERegisterProfile()
	base.VariantSet = ""
	mk := func(
		auth, identity string,
		requireSecAgree bool,
		includeSecurityClient bool,
	) RegisterProfile {
		out := base
		out.InitialAuthorization = auth
		out.AuthorizationIdentity = identity
		out.IncludeRequireSecAgree = requireSecAgree
		out.IncludeSecurityClient = includeSecurityClient
		return out
	}
	mkMinimal := func(auth, identity string) RegisterProfile {
		out := mk(auth, identity, true, true)
		out.IncludeRoute = false
		out.IncludePPreferredID = false
		out.IncludePVisitedNetworkID = false
		out.IncludePAccessNetworkInfo = false
		out.IncludeCellularNetwork = false
		out.IncludeAcceptContact = false
		return out
	}
	return []RegisterProfile{
		mk("aka_empty_uri_first", "imsi_home_domain", false, true),
		mk("none", "imsi_home_domain", false, true),
		mk("aka_empty", "imsi_home_domain", false, true),
		mk("aka_zero_response_uri_first", "imsi_home_domain", false, true),
		mk("aka_empty_uri_first", "imsi_home_domain", true, true),
		mk("none", "imsi_home_domain", true, true),
		mk("none", "prefixed_imsi_home_domain", false, true),
		mk("none", "imsi_phone_uri", false, true),
		mk("none", "private_id", false, true),
		// Minimal sec-agree only (worthdoingbadly/Linphone-style): no location
		// headers so the network can return 401 IMS-AKA instead of 403 location.
		mkMinimal("aka_empty_uri_first", "imsi_home_domain"),
		mkMinimal("none", "private_id"),
	}
}

func registerVariantsForProfile(profile RegisterProfile) []RegisterProfile {
	switch strings.ToLower(strings.TrimSpace(profile.VariantSet)) {
	case "simadmin_gb_ee":
		variants := simAdminGBEERegisterVariants()
		variants[0].UserAgent = profile.UserAgent
		return variants
	default:
		if strings.TrimSpace(profile.ContactFeatures) != "" {
			return []RegisterProfile{profile}
		}
		return nil
	}
}

func UsesIMSIHomeDomainIdentity(profile RegisterProfile) bool {
	switch strings.ToLower(strings.TrimSpace(profile.AuthorizationIdentity)) {
	case "imsi_home_domain", "prefixed_imsi_home_domain", "imsi_phone_uri":
		return true
	default:
		return strings.TrimSpace(profile.VariantSet) == "simadmin_gb_ee"
	}
}

func BuildIMSIdentity(imsi, realm, domain, shape string) (privateID, publicURI string) {
	imsi = strings.TrimSpace(imsi)
	realm = strings.TrimSpace(realm)
	domain = strings.TrimSpace(domain)
	if imsi == "" || realm == "" || domain == "" {
		return "", ""
	}
	switch strings.ToLower(strings.TrimSpace(shape)) {
	case "prefixed_imsi_home_domain":
		prefixed := "0" + imsi
		return prefixed + "@" + realm, "sip:" + prefixed + "@" + domain
	case "imsi_phone_uri":
		return imsi + "@" + realm, "sip:" + imsi + "@" + domain + ";user=phone"
	default:
		return imsi + "@" + realm, "sip:" + imsi + "@" + domain
	}
}

func registerProfileForConfig(cfg Config) RegisterProfile {
	mcc, mnc := strings.TrimSpace(cfg.MCC), strings.TrimSpace(cfg.MNC)
	if mcc == "" || mnc == "" {
		mcc, mnc = mccMncFromIMSDomain(cfg.HomeDomain)
	}
	if mcc == "" || mnc == "" {
		mcc, mnc = mccMncFromIMSDomain(cfg.Realm)
	}
	switch simAdminProfileKey(mcc, mnc) {
	case "234-10", "234-33":
		return DefaultGBEERegisterProfile()
	default:
		return RegisterProfile{
			ContactFeatures:           "sms_only",
			IncludeAcceptContact:      true,
			IncludePPreferredID:       true,
			IncludePVisitedNetworkID:  true,
			IncludePAccessNetworkInfo: true,
			IncludeRoute:              true,
			IncludeCellularNetwork:    false,
			IncludeSecurityClient:     true,
			InitialAuthorization:      "none",
			SecurityClientFormat:      "full_spaced",
			SupportedHeader:           "path,sec-agree,gruu",
			IncludePANIAuthenticated:  true,
			UserAgent:                 "SimAdmin VoWiFi",
		}
	}
}

type securityClientState struct {
	spiC  uint32
	spiS  uint32
	portC uint16
	portS uint16
}

func newSecurityClientState() securityClientState {
	return securityClientState{
		spiC:  randomNonZeroUint32(),
		spiS:  randomNonZeroUint32(),
		portC: 5064,
		portS: 5063,
	}
}

func FormatGSMAIMEIURN(imei string) string {
	digits := make([]byte, 0, 15)
	for i := 0; i < len(imei); i++ {
		ch := imei[i]
		if ch >= '0' && ch <= '9' {
			digits = append(digits, ch)
		}
	}
	if len(digits) < 14 {
		return ""
	}
	if len(digits) > 15 {
		digits = digits[:15]
	}
	tac := string(digits[:8])
	snr := string(digits[8:14])
	return fmt.Sprintf("urn:gsma:imei:%s-%s-0", tac, snr)
}

// NewSIPInstanceURN returns a random RFC 4122 UUID URN for +sip.instance.
func NewSIPInstanceURN() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "urn:uuid:00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"urn:uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
	)
}

func newContactUserUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
	)
}

func simAdminProfileKey(mcc, mnc string) string {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	if len(mnc) > 2 {
		mnc = strings.TrimLeft(mnc, "0")
	}
	if mnc == "" {
		mnc = "0"
	}
	if len(mnc) == 1 {
		mnc = "0" + mnc
	}
	return fmt.Sprintf("%s-%s", mcc, mnc)
}

func mccMncFromIMSDomain(domain string) (mcc, mnc string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if idx := strings.Index(domain, "mcc"); idx >= 0 {
		end := strings.Index(domain[idx:], ".")
		if end < 0 {
			end = len(domain) - idx
		}
		mcc = strings.TrimSpace(domain[idx+3 : idx+end])
	}
	if idx := strings.Index(domain, "mnc"); idx >= 0 {
		end := strings.Index(domain[idx:], ".")
		if end < 0 {
			end = len(domain) - idx
		}
		mnc = strings.TrimSpace(domain[idx+3 : idx+end])
	}
	return mcc, mnc
}

func plmnFromIMSDomain(domain string) string {
	mcc, mnc := mccMncFromIMSDomain(domain)
	if mcc == "" || mnc == "" {
		return ""
	}
	mnc = strings.TrimLeft(mnc, "0")
	if mnc == "" {
		mnc = "0"
	}
	return mcc + mnc
}

func buildCellularNetworkInfo(plmn, cellID string) string {
	plmn = strings.TrimSpace(plmn)
	if plmn == "" {
		plmn = "00000"
	}
	eci := strings.TrimSpace(cellID)
	if eci == "" {
		eci = "0000000"
	}
	return fmt.Sprintf("3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=%s%s;cell-info-age=0", plmn, eci)
}

func buildPAccessNetworkInfo(profile RegisterProfile) string {
	if profile.IncludePANIAuthenticated {
		return "IEEE-802.11;i-wlan-node-id=000000000000;network-provided"
	}
	return "IEEE-802.11;i-wlan-node-id=000000000000"
}

func (c Config) buildContactHeader(profile RegisterProfile, sipInstance, contactUser string) string {
	transport := c.transportNetwork()
	user := strings.TrimSpace(contactUser)
	if user == "" {
		user = c.contactUser()
	}
	if user == "" {
		user = "anonymous"
	}
	local := fmt.Sprintf("sip:%s@%s;transport=%s",
		user,
		netJoinHostPort(c.LocalIP.String(), c.localPort()),
		transport,
	)
	var b strings.Builder
	b.WriteString("<")
	b.WriteString(local)
	b.WriteString(">")
	switch strings.ToLower(strings.TrimSpace(profile.ContactFeatures)) {
	case "phone_xiaomi":
		b.WriteString(`;+g.3gpp.accesstype="wlan1"`)
		b.WriteString(";audio")
		b.WriteString(`;+g.3gpp.icsi-ref="`)
		b.WriteString(imsMmtelICSIRef)
		b.WriteString(`"`)
		if strings.TrimSpace(sipInstance) != "" {
			b.WriteString(`;+sip.instance="<`)
			b.WriteString(sipInstance)
			b.WriteString(`>"`)
		}
	case "sms_only":
		b.WriteString(`;+g.3gpp.accesstype="IEEE-802.11"`)
		b.WriteString(";+g.3gpp.smsip")
	default:
		b.WriteString(`;+g.3gpp.accesstype="IEEE-802.11"`)
		b.WriteString(";audio")
		b.WriteString(";+g.3gpp.smsip")
		b.WriteString(`;+g.3gpp.icsi-ref="`)
		b.WriteString(imsMmtelICSIRef)
		b.WriteString(`"`)
		if strings.TrimSpace(sipInstance) != "" {
			b.WriteString(`;+sip.instance="<`)
			b.WriteString(sipInstance)
			b.WriteString(`>"`)
		}
	}
	b.WriteString(";expires=")
	b.WriteString(fmt.Sprintf("%d", int(c.contactExpires(profile).Seconds())))
	return b.String()
}

func (c Config) contactExpires(profile RegisterProfile) time.Duration {
	if profile.RegisterExpirySeconds > 0 {
		return time.Duration(profile.RegisterExpirySeconds) * time.Second
	}
	return c.registerExpiry()
}

func buildSecurityClientHeader(profile RegisterProfile, state securityClientState) string {
	alg, ealg, proto, mode := "hmac-sha-1-96", "aes-cbc", "esp", "trans"
	switch strings.ToLower(strings.TrimSpace(profile.SecurityClientFormat)) {
	case "phone_multi":
		combos := []struct{ alg, ealg string }{
			{"hmac-md5-96", "des-ede3-cbc"},
			{"hmac-md5-96", "aes-cbc"},
			{"hmac-md5-96", "null"},
			{"hmac-sha-1-96", "des-ede3-cbc"},
			{"hmac-sha-1-96", "aes-cbc"},
			{"hmac-sha-1-96", "null"},
		}
		parts := make([]string, 0, len(combos))
		for _, combo := range combos {
			parts = append(parts, fmt.Sprintf(
				"ipsec-3gpp; alg=%s; ealg=%s; spi-c=%d; spi-s=%d; port-c=%d; port-s=%d",
				combo.alg, combo.ealg, state.spiC, state.spiS, state.portC, state.portS,
			))
		}
		return strings.Join(parts, ",")
	case "minimal_spaced":
		return fmt.Sprintf(
			"ipsec-3gpp; alg=%s; ealg=%s; spi-c=%d; spi-s=%d; port-c=%d; port-s=%d",
			alg, ealg, state.spiC, state.spiS, state.portC, state.portS,
		)
	default:
		return fmt.Sprintf(
			"ipsec-3gpp; alg=%s; ealg=%s; prot=%s; mod=%s; spi-c=%d; spi-s=%d; port-c=%d; port-s=%d",
			alg, ealg, proto, mode, state.spiC, state.spiS, state.portC, state.portS,
		)
	}
}

func buildInitialAuthorization(cfg Config, profile RegisterProfile, requestURI string) string {
	switch strings.ToLower(strings.TrimSpace(profile.InitialAuthorization)) {
	case "none":
		return ""
	case "aka_empty_uri_first":
		return fmt.Sprintf(
			`Digest uri="%s",username="%s",algorithm=AKAv1-MD5,response="",realm="%s",nonce=""`,
			quoteSipParam(requestURI),
			quoteSipParam(authorizationUsername(cfg, profile)),
			quoteSipParam(strings.TrimSpace(cfg.Realm)),
		)
	case "aka_empty":
		return fmt.Sprintf(
			`Digest username="%s",realm="%s",nonce="",uri="%s",response="",algorithm=AKAv1-MD5`,
			quoteSipParam(authorizationUsername(cfg, profile)),
			quoteSipParam(strings.TrimSpace(cfg.Realm)),
			quoteSipParam(requestURI),
		)
	case "aka_zero_response":
		return fmt.Sprintf(
			`Digest username="%s",realm="%s",nonce="",uri="%s",response="00000000000000000000000000000000",algorithm=AKAv1-MD5`,
			quoteSipParam(authorizationUsername(cfg, profile)),
			quoteSipParam(strings.TrimSpace(cfg.Realm)),
			quoteSipParam(requestURI),
		)
	case "aka_zero_response_uri_first":
		return fmt.Sprintf(
			`Digest uri="%s",username="%s",algorithm=AKAv1-MD5,response="00000000000000000000000000000000",realm="%s",nonce=""`,
			quoteSipParam(requestURI),
			quoteSipParam(authorizationUsername(cfg, profile)),
			quoteSipParam(strings.TrimSpace(cfg.Realm)),
		)
	default:
		return ""
	}
}

func authorizationUsername(cfg Config, profile RegisterProfile) string {
	return strings.TrimSpace(cfg.PrivateID)
}

func quoteSipParam(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}

func randomNonZeroUint32() uint32 {
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(1<<32-1))
		if err != nil {
			return 0xc0ffee01
		}
		if v := uint32(n.Int64()) + 1; v != 0 {
			return v
		}
	}
}

func netJoinHostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}