package imscore

import (
	"net"
	"strings"
	"testing"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

func TestBuildTemplateSecurityClientSingleMechanism(t *testing.T) {
	got := buildTemplateSecurityClient(policy.DefaultGiffgaffTemplate(), 1, 2, 5064, 5063)
	if strings.Count(got, "ipsec-3gpp") != 1 {
		t.Fatalf("expected single mechanism, got %q", got)
	}
	for _, want := range []string{
		"alg=hmac-sha-1-96",
		"ealg=aes-cbc",
		"prot=esp",
		"mod=trans",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("header %q missing %q", got, want)
		}
	}
}

func TestResolveStableSIPInstanceUsesConfig(t *testing.T) {
	cfg := Config{SIPInstanceURN: "urn:uuid:fixed-id"}
	if got := resolveStableSIPInstance(cfg); got != "urn:uuid:fixed-id" {
		t.Fatalf("got %q", got)
	}
}

func TestVodafoneUKInitialRegisterIncludesAKAEmptyAuthorization(t *testing.T) {
	cfg := Config{
		HomeDomain: "ims.mnc015.mcc234.3gppnetwork.org",
		Realm:      "ims.mnc015.mcc234.3gppnetwork.org",
		PrivateID:  "subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		Template:   policy.ResolveIMSRegisterTemplate("234", "15"),
	}

	want := `Digest uri="sip:ims.mnc015.mcc234.3gppnetwork.org",username="subscriber@ims.mnc015.mcc234.3gppnetwork.org",algorithm=AKAv1-MD5,response="",realm="ims.mnc015.mcc234.3gppnetwork.org",nonce=""`
	if got := buildInitialAuthorization(cfg, ""); got != want {
		t.Fatalf("initial Authorization = %q, want %q", got, want)
	}
}

func TestVodafoneUKInitialRegisterOmitsRoute(t *testing.T) {
	cfg := Config{
		HomeDomain:         "ims.mnc015.mcc234.3gppnetwork.org",
		Realm:              "ims.mnc015.mcc234.3gppnetwork.org",
		PrivateID:          "subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		PublicURI:          "sip:subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		IMSI:               "234150000000000",
		LocalIP:            net.ParseIP("10.0.0.2"),
		PCSCFAddr:          "10.0.0.3:5060",
		TransportPCSCFAddr: "10.0.0.3:5060",
		Template:           policy.ResolveIMSRegisterTemplate("234", "15"),
	}
	state := registerState{spiC: 1, spiS: 2, portC: 5064, portS: 5063, sipInstance: "urn:uuid:test"}

	req, err := buildRegisterRequest(cfg, state, true, initialRegisterVariant{})
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}
	if route := req.GetHeader("Route"); route != nil {
		t.Fatalf("Vodafone UK initial REGISTER Route = %q, want omitted", route.Value())
	}
}

func TestVodafoneUKInitialRegisterIncludesSIPInstanceWithoutGRUUSupported(t *testing.T) {
	cfg := Config{
		HomeDomain:         "ims.mnc015.mcc234.3gppnetwork.org",
		Realm:              "ims.mnc015.mcc234.3gppnetwork.org",
		PrivateID:          "subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		PublicURI:          "sip:subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		IMSI:               "234150000000000",
		LocalIP:            net.ParseIP("10.0.0.2"),
		PCSCFAddr:          "10.0.0.3:5060",
		TransportPCSCFAddr: "10.0.0.3:5060",
		Template:           policy.ResolveIMSRegisterTemplate("234", "15"),
	}
	state := registerState{spiC: 1, spiS: 2, portC: 5064, portS: 5063, sipInstance: "urn:uuid:test"}

	req, err := buildRegisterRequest(cfg, state, true, initialRegisterVariant{})
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}
	if supported := req.GetHeader("Supported"); supported == nil || strings.Contains(supported.Value(), "gruu") {
		t.Fatalf("Vodafone UK Supported = %v, want no gruu", supported)
	}
	contact := req.GetHeader("Contact")
	if contact == nil || !strings.Contains(contact.Value(), `+sip.instance="<urn:uuid:test>"`) {
		t.Fatalf("Vodafone UK Contact = %v, want +sip.instance", contact)
	}
	if !strings.Contains(contact.Value(), ";reg-id=1") {
		t.Fatalf("Vodafone UK Contact = %v, want reg-id=1", contact)
	}
}

func TestVodafoneUKInitialRegisterUsesMinimalHeaderSet(t *testing.T) {
	cfg := Config{
		HomeDomain:         "ims.mnc015.mcc234.3gppnetwork.org",
		Realm:              "ims.mnc015.mcc234.3gppnetwork.org",
		PrivateID:          "subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		PublicURI:          "sip:subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		IMSI:               "234150000000000",
		LocalIP:            net.ParseIP("10.0.0.2"),
		PCSCFAddr:          "10.0.0.3:5060",
		TransportPCSCFAddr: "10.0.0.3:5060",
		Template:           policy.ResolveIMSRegisterTemplate("234", "15"),
		UserAgent:          "Vodafone VOLTE Qualcomm",
	}
	state := registerState{spiC: 1, spiS: 2, portC: 5064, portS: 5063}

	req, err := buildRegisterRequest(cfg, state, true, initialRegisterVariants(cfg)[0])
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}

	for _, name := range []string{
		"Allow",
		"P-Preferred-Identity",
		"P-Visited-Network-ID",
		"Cellular-Network-Info",
		"Accept-Contact",
		"P-Access-Network-Info",
	} {
		if got := req.GetHeader(name); got != nil {
			t.Fatalf("Vodafone UK initial REGISTER %s = %q, want omitted", name, got.Value())
		}
	}
	for _, name := range []string{
		"Security-Client",
		"Content-Length",
	} {
		if got := req.GetHeader(name); got == nil {
			t.Fatalf("Vodafone UK initial REGISTER missing %s", name)
		}
	}
}

func TestRandomNonZeroUint32StaysWithinSigned31Bit(t *testing.T) {
	for i := 0; i < 64; i++ {
		v := randomNonZeroUint32()
		if v == 0 || v > 0x7fffffff {
			t.Fatalf("randomNonZeroUint32() = %d, want 1..0x7fffffff", v)
		}
	}
}

func TestRandomConsecutiveSPIPair(t *testing.T) {
	for i := 0; i < 64; i++ {
		c, s := randomConsecutiveSPIPair()
		if c == 0 || c > 0x7ffffffe {
			t.Fatalf("spi-c=%d out of range", c)
		}
		if s != c+1 {
			t.Fatalf("spi-s=%d want spi-c+1=%d", s, c+1)
		}
		if s > 0x7fffffff {
			t.Fatalf("spi-s=%d exceeds 31-bit", s)
		}
	}
}

func TestVodafoneUKInitialRegisterStartsServerInitiatedSecurityAgreement(t *testing.T) {
	cfg := Config{
		HomeDomain:         "ims.mnc015.mcc234.3gppnetwork.org",
		PublicURI:          "sip:subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		IMSI:               "234150000000000",
		LocalIP:            net.ParseIP("10.0.0.2"),
		PCSCFAddr:          "10.0.0.3:5060",
		TransportPCSCFAddr: "10.0.0.3:5060",
		Template:           policy.ResolveIMSRegisterTemplate("234", "15"),
	}

	req, err := buildRegisterRequest(cfg, registerState{spiC: 1, spiS: 2, portC: 5064, portS: 5063}, true, initialRegisterVariants(cfg)[0])
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}
	if got := req.GetHeader("Require"); got != nil {
		t.Fatalf("Vodafone UK initial REGISTER Require = %q, want omitted", got.Value())
	}
	if got := req.GetHeader("Proxy-Require"); got != nil {
		t.Fatalf("Vodafone UK initial REGISTER Proxy-Require = %q, want omitted", got.Value())
	}
	if got := req.GetHeader("Supported"); got == nil || !strings.Contains(got.Value(), "sec-agree") {
		t.Fatalf("Vodafone UK initial REGISTER Supported = %v, want sec-agree advertised", got)
	}
	if got := req.GetHeader("Security-Client"); got == nil {
		t.Fatal("Vodafone UK initial REGISTER missing Security-Client")
	}
}

func TestVodafoneUKInitialRegisterIncludesSecurityClientProtocolAndMode(t *testing.T) {
	cfg := Config{
		HomeDomain:         "ims.mnc015.mcc234.3gppnetwork.org",
		PublicURI:          "sip:subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		IMSI:               "234150000000000",
		LocalIP:            net.ParseIP("10.0.0.2"),
		PCSCFAddr:          "10.0.0.3:5060",
		TransportPCSCFAddr: "10.0.0.3:5060",
		Template:           policy.ResolveIMSRegisterTemplate("234", "15"),
	}

	req, err := buildRegisterRequest(cfg, registerState{spiC: 10, spiS: 11, portC: 5062, portS: 5063}, true, initialRegisterVariants(cfg)[0])
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}
	securityClient := req.GetHeader("Security-Client")
	if securityClient == nil {
		t.Fatal("Vodafone UK initial REGISTER missing Security-Client")
	}
	value := securityClient.Value()
	if strings.Count(value, "ipsec-3gpp") != 1 {
		t.Fatalf("Vodafone UK Security-Client mechanisms = %d, want 1: %q", strings.Count(value, "ipsec-3gpp"), value)
	}
	for _, want := range []string{"prot=esp", "mod=trans", "port-c=5062", "port-s=5063", "spi-c=10", "spi-s=11"} {
		if !strings.Contains(value, want) {
			t.Fatalf("Vodafone UK Security-Client = %q, missing %q", value, want)
		}
	}
	if strings.Contains(value, "; ") {
		t.Fatalf("Vodafone UK Security-Client = %q, want compact no-space params", value)
	}
	// Qualcomm order: alg before prot before ealg
	algIdx := strings.Index(value, "alg=")
	protIdx := strings.Index(value, "prot=")
	ealgIdx := strings.Index(value, "ealg=")
	if !(algIdx >= 0 && protIdx > algIdx && ealgIdx > protIdx) {
		t.Fatalf("Vodafone UK Security-Client = %q, want alg,prot,mod,ealg order", value)
	}
}

func TestVodafoneUKInitialRegisterOmitsPANI(t *testing.T) {
	cfg := Config{
		HomeDomain:         "ims.mnc015.mcc234.3gppnetwork.org",
		PublicURI:          "sip:subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		IMSI:               "234150000000000",
		LocalIP:            net.ParseIP("10.0.0.2"),
		PCSCFAddr:          "10.0.0.3:5060",
		TransportPCSCFAddr: "10.0.0.3:5060",
		Template:           policy.ResolveIMSRegisterTemplate("234", "15"),
	}

	req, err := buildRegisterRequest(cfg, registerState{spiC: 1, spiS: 2, portC: 5064, portS: 5063}, true, initialRegisterVariants(cfg)[0])
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}
	if pani := req.GetHeader("P-Access-Network-Info"); pani != nil {
		t.Fatalf("Vodafone UK initial REGISTER P-Access-Network-Info = %q, want omitted", pani.Value())
	}
}

func TestVodafoneUKInitialRegisterProbesSingleSecurityMechanismsInOrder(t *testing.T) {
	cfg := Config{
		HomeDomain:         "ims.mnc015.mcc234.3gppnetwork.org",
		PublicURI:          "sip:subscriber@ims.mnc015.mcc234.3gppnetwork.org",
		IMSI:               "234150000000000",
		LocalIP:            net.ParseIP("10.0.0.2"),
		PCSCFAddr:          "10.0.0.3:5060",
		TransportPCSCFAddr: "10.0.0.3:5060",
		Template:           policy.ResolveIMSRegisterTemplate("234", "15"),
	}
	state := registerState{spiC: 1, spiS: 2, portC: 5064, portS: 5063}
	want := []struct {
		alg  string
		ealg string
	}{
		{alg: "hmac-sha-1-96", ealg: "aes-cbc"},
		{alg: "hmac-sha-1-96", ealg: "null"},
		{alg: "hmac-sha-1-96", ealg: "des-ede3-cbc"},
		{alg: "hmac-md5-96", ealg: "null"},
		{alg: "hmac-md5-96", ealg: "aes-cbc"},
		{alg: "hmac-md5-96", ealg: "des-ede3-cbc"},
	}

	variants := initialRegisterVariants(cfg)
	if len(variants) != len(want) {
		t.Fatalf("Vodafone UK initial variants = %d, want %d", len(variants), len(want))
	}
	for i, variant := range variants {
		req, err := buildRegisterRequest(cfg, state, true, variant)
		if err != nil {
			t.Fatalf("variant %d buildRegisterRequest: %v", i+1, err)
		}
		header := req.GetHeader("Security-Client")
		if header == nil {
			t.Fatalf("variant %d missing Security-Client", i+1)
		}
		value := header.Value()
		if got := strings.Count(value, "ipsec-3gpp"); got != 1 {
			t.Fatalf("variant %d mechanisms = %d, want 1: %q", i+1, got, value)
		}
		for _, part := range []string{"alg=" + want[i].alg, "ealg=" + want[i].ealg} {
			if !strings.Contains(value, part) {
				t.Fatalf("variant %d Security-Client = %q, missing %q", i+1, value, part)
			}
		}
	}
}

func TestVodafoneUKRawInitialRegisterUsesStrictCRLFAndSecurityFirst(t *testing.T) {
	cfg := registerSessionTestConfig()
	session := newRegisterSession(cfg, nil, nil, "udp", 0)
	session.localPort = 41234
	session.callID = "fixed-call-id"
	session.cseq = 10001
	variant := initialRegisterVariants(cfg)[0]
	variant.requireSecAgree = true
	variant.proxyRequireSecAgree = true

	req, err := buildRegisterRequest(cfg, *session.state, true, variant)
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}
	if err := session.decorateRegisterRequest(req); err != nil {
		t.Fatalf("decorateRegisterRequest: %v", err)
	}
	payload, err := buildVodafoneInitialRegisterPayload(req)
	if err != nil {
		t.Fatalf("buildVodafoneInitialRegisterPayload: %v", err)
	}
	raw := string(payload)
	withoutCRLF := strings.ReplaceAll(raw, "\r\n", "")
	if strings.ContainsAny(withoutCRLF, "\r\n") {
		t.Fatalf("raw REGISTER contains non-CRLF line endings")
	}
	if !strings.HasSuffix(raw, "Content-Length: 0\r\n\r\n") {
		t.Fatalf("raw REGISTER must end with Content-Length and one empty line")
	}
	securityIndex := strings.Index(raw, "\r\nSecurity-Client: ")
	authorizationIndex := strings.Index(raw, "\r\nAuthorization: Digest ")
	requireIndex := strings.Index(raw, "\r\nRequire: sec-agree\r\n")
	proxyRequireIndex := strings.Index(raw, "\r\nProxy-Require: sec-agree\r\n")
	if authorizationIndex < 0 || securityIndex < 0 || requireIndex < 0 || proxyRequireIndex < 0 || !(authorizationIndex < securityIndex && securityIndex < requireIndex && requireIndex < proxyRequireIndex) {
		t.Fatalf("raw REGISTER sec-agree order is invalid")
	}
}
