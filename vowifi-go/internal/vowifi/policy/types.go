package policy

type UnprotectedRegisterTransportPolicy string

const (
	UnprotectedRegisterUDPThenTCP UnprotectedRegisterTransportPolicy = "udp_then_tcp"
	UnprotectedRegisterTCPOnly    UnprotectedRegisterTransportPolicy = "tcp_only"
)

type ProtectedRegisterTransportPolicy string

const (
	ProtectedRegisterSizeAware ProtectedRegisterTransportPolicy = "size_aware"
	ProtectedRegisterUDPOnly   ProtectedRegisterTransportPolicy = "udp_only"
)

type RegisterWireFormat string

const (
	RegisterWireStandard   RegisterWireFormat = "standard"
	RegisterWireVodafoneUK RegisterWireFormat = "vodafone_uk"
)

type MessagingPresentation string

const (
	MessagingPresentationSimAdminGBEE MessagingPresentation = "simadmin_gb_ee"
)

// CarrierBehavior is the complete home-PLMN wire-policy decision. Callers may
// log RegisterTemplate.ID, but protocol decisions consume the typed fields.
type CarrierBehavior struct {
	RegisterTemplate         IMSRegisterTemplate
	UnprotectedAutoTransport UnprotectedRegisterTransportPolicy
	ProtectedAutoTransport   ProtectedRegisterTransportPolicy
	RegisterWireFormat       RegisterWireFormat
	MessagingPresentation    MessagingPresentation
}

// IMSRegisterTemplate describes carrier-specific IMS REGISTER header and
// sec-agree behavior. Field layout matches vowifi-go v1.1.2 RE extraction.
type IMSRegisterTemplate struct {
	ID                                              string
	UsePlainDigestPlaceholder                       bool
	Expires                                         int
	SMSReceiverTransport                            string
	ContactMode                                     string
	FixedPANI                                       string
	SupportedHeader                                 string
	AllowHeader                                     string
	AccessType                                      string
	ICSIRef                                         string
	ContactParamOrder                               []string
	VoiceSupportedHeader                            string
	VoiceAllowHeader                                string
	VoiceAcceptContact                              string
	VoicePPreferredService                          string
	UserAgent                                       string
	ForceHeaderPort5060                             bool
	OmitRoute                                       bool
	MinimalInitialHeaders                           bool
	RequireSecAgree                                 bool
	ProxyRequireSecAgree                            bool
	OmitInitialSecurityClientProtocol               bool
	ProbeInitialSecurityClientOnBadRequest          bool
	RetryInitialWithoutRequiredSecAgreeOnBadRequest bool
	IncludePANI                                     bool
	IncludePANIAuthenticated                        bool
	IncludeConnectionKeepaliveInAuth                bool
	SecAgreeMode                                    string
	SecurityClientIncludesServerParams              bool
	SecurityClientMechanisms                        []IPSec3GPPSecurityMechanism
	StrictSecurityServerOffer                       bool
	EnableInitialRejectFallback                     bool
	FallbackIncludesServerParamsInSecCl             bool
	RegisterPolicy                                  IMSRegisterPolicy
}

// IPSec3GPPSecurityMechanism is one ipsec-3gpp offer the client advertises in
// Security-Client.
type IPSec3GPPSecurityMechanism struct {
	Alg  string `yaml:"alg"`
	EAlg string `yaml:"ealg"`
	Prot string `yaml:"prot"`
	Mode string `yaml:"mode"`
}

// IMSRegisterPolicy controls REGISTER retry and fallback status-code handling.
type IMSRegisterPolicy struct {
	ID                               string `yaml:"id"`
	TemporaryStatusCodes             []int  `yaml:"temporary_status_codes"`
	ForbiddenStatusCodes             []int  `yaml:"forbidden_status_codes"`
	InitialRejectFallbackStatusCodes []int  `yaml:"initial_reject_fallback_status_codes"`
	TemporaryRetrySeconds            int    `yaml:"temporary_retry_seconds"`
}
