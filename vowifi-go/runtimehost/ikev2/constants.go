package ikev2

// IKEv2 RFC 7296 常量

// 载荷类型
type PayloadType uint8

const (
	NoNextPayload     PayloadType = 0
	SA                PayloadType = 33
	KE                PayloadType = 34
	IDi               PayloadType = 35
	IDr               PayloadType = 36
	CERT              PayloadType = 37
	CERTREQ           PayloadType = 38
	AUTH              PayloadType = 39
	NiNr              PayloadType = 40
	N                 PayloadType = 41
	D                 PayloadType = 42
	V                 PayloadType = 43
	TSI               PayloadType = 44
	TSR               PayloadType = 45
	SK                PayloadType = 46
	CP                PayloadType = 47
	EAP               PayloadType = 48
	EncryptedFragment PayloadType = 53 // RFC 7383
)

// 交换类型
type ExchangeType uint8

const (
	IKE_SA_INIT        ExchangeType = 34
	IKE_AUTH           ExchangeType = 35
	CREATE_CHILD_SA    ExchangeType = 36
	INFORMATIONAL      ExchangeType = 37
	IKE_SESSION_RESUME ExchangeType = 38 // RFC 5723: Session Resumption
)

// 协议 ID
type ProtocolID uint8

const (
	ProtoIKE ProtocolID = 1
	ProtoAH  ProtocolID = 2
	ProtoESP ProtocolID = 3
)

// 变换类型
type TransformType uint8

const (
	TransformTypeEncr  TransformType = 1
	TransformTypePRF   TransformType = 2
	TransformTypeInteg TransformType = 3
	TransformTypeDH    TransformType = 4
	TransformTypeESN   TransformType = 5
)

type AlgorithmType uint16

// 变换类型 1 - 加密算法变换 ID
const (
	ENCR_DES_IV64   AlgorithmType = 1
	ENCR_DES        AlgorithmType = 2
	ENCR_3DES       AlgorithmType = 3
	ENCR_RC5        AlgorithmType = 4
	ENCR_IDEA       AlgorithmType = 5
	ENCR_CAST       AlgorithmType = 6
	ENCR_BLOWFISH   AlgorithmType = 7
	ENCR_3IDEA      AlgorithmType = 8
	ENCR_DES_IV32   AlgorithmType = 9
	ENCR_NULL       AlgorithmType = 11
	ENCR_AES_CBC    AlgorithmType = 12
	ENCR_AES_CTR    AlgorithmType = 13
	ENCR_AES_CCM_8  AlgorithmType = 14
	ENCR_AES_CCM_12 AlgorithmType = 15
	ENCR_AES_CCM_16 AlgorithmType = 16
	ENCR_AES_GCM_8  AlgorithmType = 18
	ENCR_AES_GCM_12 AlgorithmType = 19
	ENCR_AES_GCM_16 AlgorithmType = 20
)

// 变换类型 2 - 伪随机函数变换 ID
const (
	PRF_HMAC_MD5      AlgorithmType = 1
	PRF_HMAC_SHA1     AlgorithmType = 2
	PRF_HMAC_TIGER    AlgorithmType = 3
	PRF_AES128_XCBC   AlgorithmType = 4
	PRF_HMAC_SHA2_256 AlgorithmType = 5
	PRF_HMAC_SHA2_384 AlgorithmType = 6
	PRF_HMAC_SHA2_512 AlgorithmType = 7
	PRF_AES128_CMAC   AlgorithmType = 8
)

// 变换类型 3 - 完整性算法变换 ID
const (
	AUTH_NONE              AlgorithmType = 0
	AUTH_HMAC_MD5_96       AlgorithmType = 1
	AUTH_HMAC_SHA1_96      AlgorithmType = 2
	AUTH_DES_MAC           AlgorithmType = 3
	AUTH_KPDK_MD5          AlgorithmType = 4
	AUTH_AES_XCBC_96       AlgorithmType = 5
	AUTH_HMAC_MD5_128      AlgorithmType = 6
	AUTH_HMAC_SHA1_160     AlgorithmType = 7
	AUTH_AES_CMAC_96       AlgorithmType = 8
	AUTH_AES_128_GMAC      AlgorithmType = 9
	AUTH_AES_192_GMAC      AlgorithmType = 10
	AUTH_AES_256_GMAC      AlgorithmType = 11
	AUTH_HMAC_SHA2_256_128 AlgorithmType = 12
	AUTH_HMAC_SHA2_384_192 AlgorithmType = 13
	AUTH_HMAC_SHA2_512_256 AlgorithmType = 14
)

// 变换类型 4 - Diffie-Hellman 组变换 ID
const (
	MODP_768_bit  AlgorithmType = 1
	MODP_1024_bit AlgorithmType = 2
	MODP_1536_bit AlgorithmType = 5
	MODP_2048_bit AlgorithmType = 14
	MODP_3072_bit AlgorithmType = 15
	MODP_4096_bit AlgorithmType = 16
	MODP_6144_bit AlgorithmType = 17
	MODP_8192_bit AlgorithmType = 18
)

// 属性类型
const (
	AttributeKeyLength uint16 = 14
)

// 通知消息类型 - 错误类型
const (
	UNSUPPORTED_CRITICAL_PAYLOAD uint16 = 1
	INVALID_IKE_SPI              uint16 = 4
	INVALID_MAJOR_VERSION        uint16 = 5
	INVALID_SYNTAX               uint16 = 7
	INVALID_MESSAGE_ID           uint16 = 9
	INVALID_SPI                  uint16 = 11
	NO_PROPOSAL_CHOSEN           uint16 = 14
	INVALID_KE_PAYLOAD           uint16 = 17
	AUTHENTICATION_FAILED        uint16 = 24
	SINGLE_PAIR_REQUIRED         uint16 = 34
	NO_ADDITIONAL_SAS            uint16 = 35
	INTERNAL_ADDRESS_FAILURE     uint16 = 36
	FAILED_CP_REQUIRED           uint16 = 37
	TS_UNACCEPTABLE              uint16 = 38
	INVALID_SELECTORS            uint16 = 39
	TEMPORARY_FAILURE            uint16 = 43
	CHILD_SA_NOT_FOUND           uint16 = 44
)

// 通知消息类型 - 状态类型
const (
	INITIAL_CONTACT               uint16 = 16384
	SET_WINDOW_SIZE               uint16 = 16385
	ADDITIONAL_TS_POSSIBLE        uint16 = 16386
	IPCOMP_SUPPORTED              uint16 = 16387
	NAT_DETECTION_SOURCE_IP       uint16 = 16388
	NAT_DETECTION_DESTINATION_IP  uint16 = 16389
	COOKIE                        uint16 = 16390
	USE_TRANSPORT_MODE            uint16 = 16391
	HTTP_CERT_LOOKUP_SUPPORTED    uint16 = 16392
	REKEY_SA                      uint16 = 16393
	ESP_TFC_PADDING_NOT_SUPPORTED uint16 = 16394
	NON_FIRST_FRAGMENTS_ALSO      uint16 = 16395
	// MOBIKE (RFC 4555) — 按 IANA IKEv2 Parameters Registry 排列
	MOBIKE_SUPPORTED        uint16 = 16396 // RFC 4555: 移动性支持能力协商
	ADDITIONAL_IP4_ADDRESS  uint16 = 16397 // RFC 4555: 备用 IPv4 地址
	ADDITIONAL_IP6_ADDRESS  uint16 = 16398 // RFC 4555: 备用 IPv6 地址
	NO_ADDITIONAL_ADDRESSES uint16 = 16399 // RFC 4555: 无更多备用地址
	UPDATE_SA_ADDRESSES     uint16 = 16400 // RFC 4555: 更新 SA 端点地址
	COOKIE2                 uint16 = 16401 // RFC 4555: 路径验证 Cookie
	NO_NATS_ALLOWED         uint16 = 16402 // RFC 4555: 禁止 NAT

	AUTH_LIFETIME uint16 = 16403 // RFC 4478: ePDG 通告 IKE SA 最大生命周期（秒）

	REDIRECT_SUPPORTED uint16 = 16406 // RFC 5685: 支持重定向
	REDIRECT           uint16 = 16407 // RFC 5685: 重定向到其他网关

	// RFC 5723: Session Resumption
	TICKET_LT_OPAQUE uint16 = 16409
	TICKET_REQUEST   uint16 = 16410
	TICKET_ACK       uint16 = 16411
	TICKET_NACK      uint16 = 16412
	TICKET_OPAQUE    uint16 = 16413

	EAP_ONLY_AUTHENTICATION uint16 = 16417 // RFC 5998: 仅 EAP 认证

	IKEV2_MESSAGE_ID_SYNC uint16 = 16422 // RFC 6311: 消息 ID 同步

	// IKE Fragmentation (RFC 7383)
	IKEV2_FRAGMENTATION_SUPPORTED uint16 = 16430

	DEVICE_IDENTITY      uint16 = 16432 // 3GPP TS 24.302: 设备身份
	DEVICE_IDENTITY_3GPP uint16 = 41101 // 3GPP 私有: 设备身份（IMEI）
)

// RFC 5685 Redirect Gateway Identity Type
const (
	RedirectGWIPv4 uint8 = 1
	RedirectGWIPv6 uint8 = 2
	RedirectGWFQDN uint8 = 3
)

// IntegToString 将完整性算法 ID 转换为字符串描述

func EncrToString(id uint16) string {
	switch AlgorithmType(id) {
	case ENCR_DES_IV64:
		return "DES_IV64"
	case ENCR_DES:
		return "DES"
	case ENCR_3DES:
		return "3DES"
	case ENCR_RC5:
		return "RC5"
	case ENCR_IDEA:
		return "IDEA"
	case ENCR_CAST:
		return "CAST"
	case ENCR_BLOWFISH:
		return "BLOWFISH"
	case ENCR_3IDEA:
		return "3IDEA"
	case ENCR_DES_IV32:
		return "DES_IV32"
	case ENCR_NULL:
		return "NULL"
	case ENCR_AES_CBC:
		return "AES_CBC"
	case ENCR_AES_CTR:
		return "AES_CTR"
	case ENCR_AES_CCM_8:
		return "AES_CCM_8"
	case ENCR_AES_CCM_12:
		return "AES_CCM_12"
	case ENCR_AES_CCM_16:
		return "AES_CCM_16"
	case ENCR_AES_GCM_8:
		return "AES_GCM_8"
	case ENCR_AES_GCM_12:
		return "AES_GCM_12"
	case ENCR_AES_GCM_16:
		return "AES_GCM_16"
	default:
		return "UNKNOWN"
	}
}

func PRFToString(id uint16) string {
	switch AlgorithmType(id) {
	case PRF_HMAC_MD5:
		return "HMAC_MD5"
	case PRF_HMAC_SHA1:
		return "HMAC_SHA1"
	case PRF_HMAC_TIGER:
		return "HMAC_TIGER"
	case PRF_AES128_XCBC:
		return "AES128_XCBC"
	case PRF_HMAC_SHA2_256:
		return "HMAC_SHA2_256"
	case PRF_HMAC_SHA2_384:
		return "HMAC_SHA2_384"
	case PRF_HMAC_SHA2_512:
		return "HMAC_SHA2_512"
	case PRF_AES128_CMAC:
		return "AES128_CMAC"
	default:
		return "UNKNOWN"
	}
}

func IntegToString(id uint16) string {
	switch AlgorithmType(id) {
	case AUTH_NONE:
		return "NONE"
	case AUTH_HMAC_MD5_96:
		return "HMAC_MD5_96"
	case AUTH_HMAC_SHA1_96:
		return "HMAC_SHA1_96"
	case AUTH_DES_MAC:
		return "DES_MAC"
	case AUTH_KPDK_MD5:
		return "KPDK_MD5"
	case AUTH_AES_XCBC_96:
		return "AES_XCBC_96"
	case AUTH_HMAC_MD5_128:
		return "HMAC_MD5_128"
	case AUTH_HMAC_SHA1_160:
		return "HMAC_SHA1_160"
	case AUTH_AES_CMAC_96:
		return "AES_CMAC_96"
	case AUTH_AES_128_GMAC:
		return "AES_128_GMAC"
	case AUTH_AES_192_GMAC:
		return "AES_192_GMAC"
	case AUTH_AES_256_GMAC:
		return "AES_256_GMAC"
	case AUTH_HMAC_SHA2_256_128:
		return "HMAC_SHA2_256_128"
	case AUTH_HMAC_SHA2_384_192:
		return "HMAC_SHA2_384_192"
	case AUTH_HMAC_SHA2_512_256:
		return "HMAC_SHA2_512_256"
	default:
		return "UNKNOWN"
	}
}

func DHToString(id uint16) string {
	switch AlgorithmType(id) {
	case MODP_768_bit:
		return "MODP_768"
	case MODP_1024_bit:
		return "MODP_1024"
	case MODP_1536_bit:
		return "MODP_1536"
	case MODP_2048_bit:
		return "MODP_2048"
	case MODP_3072_bit:
		return "MODP_3072"
	case MODP_4096_bit:
		return "MODP_4096"
	case MODP_6144_bit:
		return "MODP_6144"
	case MODP_8192_bit:
		return "MODP_8192"
	default:
		if id == 0 {
			return "NONE"
		}
		return "UNKNOWN"
	}
}
