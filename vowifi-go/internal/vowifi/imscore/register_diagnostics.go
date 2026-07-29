package imscore

import (
	"net"
	"strings"

	"github.com/1239t/swu-go/pkg/logger"
	"go.uber.org/zap"
)

type registerDiagnostic struct {
	stage                string
	status               int
	result               string
	variant              string
	variantIndex         int
	variantTotal         int
	transport            string
	addressFamily        string
	candidateIndex       int
	candidateTotal       int
	headerCount          int
	challengeRound       int
	mechanismCount       int
	expiresSeconds       int
	hasWarning           bool
	hasUnsupported       bool
	hasRequire           bool
	requiresSecAgree     bool
	hasWWWAuthenticate   bool
	hasProxyAuthenticate bool
	hasSecurityServer    bool
	hasPath              bool
	hasServiceRoute      bool
	reachedAuth          bool
	protected            bool
	ipsecInstalled       bool
	syncFailure          bool

	// Warning metadata is independent of hasWarning on purpose. hasWarning is
	// overloaded: on stage=initial_response it means a Warning header existed,
	// but several other stages set it only to raise the log level. These fields
	// carry the de-identified classification and are populated exclusively from
	// a real SIP response at stage=initial_response.
	warningPresent     bool
	warningCount       int
	warningCode        int
	warningClass       string
	warningParseResult string

	// realmSource reports whether the Digest AKA realm came from the card's
	// ISIM (operator-specific) or was synthesised from MCC/MNC per TS 23.003.
	// It is populated only at stage=config_resolved and never carries the realm.
	realmSource string

	// Userspace ESP transform counters, bounded by registerESPCounterMax. When
	// the protected REGISTER times out these are the only way to tell apart
	// "no packet ever came back" from "packets arrived and were dropped by the
	// transform or the replay window". They are counters only: no ESP payload,
	// no SPI, no address, no key material.
	peerIPInboundPackets  int
	espOutboundPackets    int
	espInboundPackets     int
	espTransformErrors    int
	espPassthroughPackets int
	espReplayDuplicate    int
	espReplayTooOld       int

	// sipMessageLen is the encoded length of the REGISTER about to go on the
	// wire, and exceedsUDPMTULimit reports whether it crosses the RFC 3261
	// §18.1.1 threshold above which a request MUST NOT be sent over UDP when
	// the path MTU is unknown. Both are needed because the initial REGISTER
	// (which gets a 401) and the protected REGISTER (which times out) differ
	// mainly in size: the protected one carries the full Authorization
	// response plus Security-Verify. Length only, never any SIP content.
	sipMessageLen      int
	exceedsUDPMTULimit bool

	// innerPacketLen is the IPv6+UDP+ESP packet the protected REGISTER becomes
	// before it enters the SWu tunnel. rawIPPacketCount is how many raw IP
	// packets the SWu connection writes for it, and fragmented reports whether
	// IPv6 fragmentation was required at all.
	//
	// These are two fields on purpose. A single "fragment_count" was ambiguous:
	// 1 could be read either as "one fragment was produced", i.e. fragmentation
	// happened, or as "one packet, unfragmented". Splitting them makes the
	// unfragmented case unambiguous (count=1, fragmented=false) and keeps "the
	// request had to be fragmented" a logged fact rather than something
	// reconstructed from outer packet lengths afterwards.
	innerPacketLen   int
	rawIPPacketCount int
	fragmented       bool
}

// registerDiagnosticAllowedFieldKeys is the single source of truth for the
// strict logging whitelist. Every key must map to a bool, a bounded integer, or
// a closed enum; no key may carry raw SIP, identity, address, or credential
// material.
func registerDiagnosticAllowedFieldKeys() map[string]struct{} {
	return map[string]struct{}{
		"stage": {}, "status": {}, "result": {}, "variant": {},
		"variant_index": {}, "variant_total": {}, "transport": {},
		"address_family": {}, "candidate_index": {}, "candidate_total": {},
		"header_count": {}, "challenge_round": {}, "mechanism_count": {},
		"expires_seconds": {}, "has_warning": {}, "has_unsupported": {},
		"has_require": {}, "requires_sec_agree": {}, "has_www_authenticate": {},
		"has_proxy_authenticate": {}, "has_security_server": {}, "has_path": {},
		"has_service_route": {}, "reached_auth": {}, "protected": {},
		"ipsec_installed": {}, "sync_failure": {},
		"warning_present": {}, "warning_count": {}, "warning_code": {},
		"warning_class": {}, "warning_parse_result": {},
		"realm_source":          {},
		"peer_ip_inbound_count": {},
		"esp_outbound_packets":  {}, "esp_inbound_packets": {},
		"esp_transform_errors": {}, "esp_passthrough_packets": {},
		"esp_replay_duplicate": {}, "esp_replay_too_old": {},
		"sip_message_len": {}, "exceeds_udp_mtu_limit": {},
		"inner_packet_len": {}, "raw_ip_packet_count": {}, "fragmented": {},

		// Measured facts about a protected TCP exchange. Every one is a bounded
		// count, a bool, or a closed enum, and each is observed rather than
		// modelled - which is the whole reason this group exists separately from
		// inner_packet_len above.
		//
		// Deliberately absent: any sequence or acknowledgement number. Byte
		// PROGRESS answers "was our data accepted" without recording
		// connection-identifying wire state, so tcp_bytes_acked is a count of bytes
		// and never an ack value.
		"tcp_data_segments": {}, "tcp_max_inner_packet_len": {},
		"tcp_fragmented": {}, "tcp_bytes_written": {}, "tcp_bytes_acked": {},
		"tcp_fully_acked": {}, "tcp_retransmissions": {},
		"tcp_effective_mss": {}, "tcp_response_frames": {}, "tcp_closure": {},
	}
}

// registerESPCounterMax bounds every ESP counter that reaches a diagnostic.
const registerESPCounterMax = 1000000

func boundRegisterESPCounter(value int) int {
	if value < 0 {
		return 0
	}
	if value > registerESPCounterMax {
		return registerESPCounterMax
	}
	return value
}

// registerUDPSafeMessageLimit is the RFC 3261 §18.1.1 threshold: when a request
// is within 200 bytes of the path MTU, or larger than 1300 bytes when the path
// MTU is unknown, a client MUST use a congestion-controlled transport instead of
// UDP. The protected REGISTER always runs over UDP inside ESP, so this is the
// only bound that applies to it.
const registerUDPSafeMessageLimit = 1300

// registerSIPMessageMaxLen bounds the logged length so a hostile or corrupted
// value can never turn the size field into an unbounded integer.
const registerSIPMessageMaxLen = 65535

// registerSIPMessageExceedsUDPLimit is the single source of truth for the
// RFC 3261 §18.1.1 verdict. The diagnostic emit site and any future transport
// decision must both call this, so they cannot drift apart.
func registerSIPMessageExceedsUDPLimit(size int) bool {
	return size > registerUDPSafeMessageLimit
}

func boundRegisterSIPMessageLen(value int) int {
	if value < 0 {
		return 0
	}
	if value > registerSIPMessageMaxLen {
		return registerSIPMessageMaxLen
	}
	return value
}

// boundRegisterESPCounterU64 clamps a raw Transport.Stats() counter.
func boundRegisterESPCounterU64(value uint64) int {
	if value > uint64(registerESPCounterMax) {
		return registerESPCounterMax
	}
	return int(value)
}

func logRegisterDiagnostic(d registerDiagnostic) {
	fields := []zap.Field{
		logger.String("stage", canonicalRegisterDiagnosticStage(d.stage)),
		logger.Int("status", d.status),
		logger.String("result", canonicalRegisterDiagnosticResult(d.result)),
		logger.String("variant", canonicalRegisterDiagnosticVariant(d.variant)),
		logger.Int("variant_index", d.variantIndex),
		logger.Int("variant_total", d.variantTotal),
		logger.String("transport", canonicalRegisterTransportDiagnostic(d.transport)),
		logger.String("address_family", canonicalRegisterAddressFamily(d.addressFamily)),
		logger.Int("candidate_index", d.candidateIndex),
		logger.Int("candidate_total", d.candidateTotal),
		logger.Int("header_count", d.headerCount),
		logger.Int("challenge_round", d.challengeRound),
		logger.Int("mechanism_count", d.mechanismCount),
		logger.Int("expires_seconds", d.expiresSeconds),
		logger.Bool("has_warning", d.hasWarning),
		logger.Bool("has_unsupported", d.hasUnsupported),
		logger.Bool("has_require", d.hasRequire),
		logger.Bool("requires_sec_agree", d.requiresSecAgree),
		logger.Bool("has_www_authenticate", d.hasWWWAuthenticate),
		logger.Bool("has_proxy_authenticate", d.hasProxyAuthenticate),
		logger.Bool("has_security_server", d.hasSecurityServer),
		logger.Bool("has_path", d.hasPath),
		logger.Bool("has_service_route", d.hasServiceRoute),
		logger.Bool("reached_auth", d.reachedAuth),
		logger.Bool("protected", d.protected),
		logger.Bool("ipsec_installed", d.ipsecInstalled),
		logger.Bool("sync_failure", d.syncFailure),
		logger.Bool("warning_present", d.warningPresent),
		logger.Int("warning_count", boundRegisterWarningCount(d.warningCount)),
		logger.Int("warning_code", canonicalRegisterWarningCode(d.warningCode)),
		logger.String("warning_class", canonicalRegisterWarningClass(d.warningClass)),
		logger.String("warning_parse_result", canonicalRegisterWarningParseResult(d.warningParseResult)),
		logger.String("realm_source", canonicalRegisterRealmSource(d.realmSource)),
		logger.Int("peer_ip_inbound_count", boundRegisterESPCounter(d.peerIPInboundPackets)),
		logger.Int("esp_outbound_packets", boundRegisterESPCounter(d.espOutboundPackets)),
		logger.Int("esp_inbound_packets", boundRegisterESPCounter(d.espInboundPackets)),
		logger.Int("esp_transform_errors", boundRegisterESPCounter(d.espTransformErrors)),
		logger.Int("esp_passthrough_packets", boundRegisterESPCounter(d.espPassthroughPackets)),
		logger.Int("esp_replay_duplicate", boundRegisterESPCounter(d.espReplayDuplicate)),
		logger.Int("esp_replay_too_old", boundRegisterESPCounter(d.espReplayTooOld)),
		logger.Int("sip_message_len", boundRegisterSIPMessageLen(d.sipMessageLen)),
		logger.Bool("exceeds_udp_mtu_limit", d.exceedsUDPMTULimit),
		logger.Int("inner_packet_len", boundRegisterSIPMessageLen(d.innerPacketLen)),
		logger.Int("raw_ip_packet_count", boundRegisterESPCounter(d.rawIPPacketCount)),
		logger.Bool("fragmented", d.fragmented),
	}
	// Log level stays keyed on hasWarning alone. warningPresent must not change
	// existing level behavior.
	if d.hasWarning {
		logger.Warn("IMS REGISTER diagnostic", fields...)
		return
	}
	logger.Info("IMS REGISTER diagnostic", fields...)
}

func canonicalRegisterDiagnosticStage(value string) string {
	switch strings.TrimSpace(value) {
	case "config_resolved", "discovery", "transport_start", "transport_retry",
		"candidate_attempt", "candidate_rejected", "transport_connected",
		"initial_attempt", "initial_response", "variant_retry", "sec_agree_retry",
		"auth_challenge", "auth_resync", "auth_success", "ipsec_install",
		"protected_send", "protected_accept", "complete", "request_prepared",
		"sip_read", "sip_write", "initial_jitter", "register_failed",
		"protected_read_timeout":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func canonicalRegisterDiagnosticResult(value string) string {
	switch strings.TrimSpace(value) {
	case "none", "ok", "bad_request", "unauthorized", "forbidden",
		"proxy_auth_required", "extension_required", "sip_response",
		"no_sip_response", "canceled", "network_failure", "initial_reject_fallback",
		"forbidden_without_auth_challenge", "transport_probe_timeout",
		"temporary_sip_failure", "register_transport_failed",
		"sec_agree_required", "sec_agree_equivalent_variant_already_rejected",
		"sec_agree_challenge_invalid", "sec_agree_already_requested",
		"sec_agree_challenge_unsupported", "response_correlation_mismatch",
		"initial_variants_exhausted_after_bad_request", "auth_phase_reached",
		"challenge_received", "resync_sent", "aka_complete", "installed",
		"sending", "accepted", "register_failed", "candidate_rejected":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func canonicalRegisterDiagnosticVariant(value string) string {
	switch strings.TrimSpace(value) {
	case "default", "with_required_sec_agree", "without_required_sec_agree", "security_mechanism_probe":
		return strings.TrimSpace(value)
	default:
		return "default"
	}
}

func canonicalRegisterTransportDiagnostic(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "udp":
		return "udp"
	case "tcp":
		return "tcp"
	default:
		return "unknown"
	}
}

func canonicalRegisterAddressFamily(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ipv4":
		return "ipv4"
	case "ipv6":
		return "ipv6"
	default:
		return "unknown"
	}
}

func registerAddressFamily(addr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(addr), "[]")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "unknown"
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func registerStatusResult(status int) string {
	switch status {
	case 200:
		return "ok"
	case 400:
		return "bad_request"
	case 401:
		return "unauthorized"
	case 403:
		return "forbidden"
	case 407:
		return "proxy_auth_required"
	case 421:
		return "extension_required"
	case 0:
		return "no_sip_response"
	default:
		return "sip_response"
	}
}

// logProtectedRegisterMessageSize reports the serialized length of the
// protected REGISTER and whether it crosses the RFC 3261 §18.1.1 UDP
// threshold. The protected REGISTER is the only REGISTER in the flow that is
// pinned to UDP, so a request past that threshold is standards-noncompliant
// and may be dropped by the peer with no SIP or ICMP error at all.
//
// Length and a bool only: never the request line, headers, or body.
//
// ipsecInstalled is true because this only runs after installIPSecFromChallenge
// succeeded. Omitting it made stage=protected_send report ipsec_installed=false
// one line after stage=ipsec_install reported true, which read as though the SA
// had been torn down in between. It had not.
func logProtectedRegisterMessageSize(messageLen int) {
	innerLen := registerProtectedInnerPacketLen(messageLen)
	logRegisterDiagnostic(registerDiagnostic{
		stage:              "protected_send",
		result:             "sending",
		transport:          "udp",
		protected:          true,
		ipsecInstalled:     true,
		sipMessageLen:      messageLen,
		exceedsUDPMTULimit: registerSIPMessageExceedsUDPLimit(messageLen),
		innerPacketLen:     innerLen,
		rawIPPacketCount:   registerProtectedRawIPPacketCount(innerLen),
		fragmented:         registerProtectedInnerIsFragmented(innerLen),
	})
}

// logProtectedTransportDecision records which transport the protected REGISTER
// will use, and the two measurements that decided it.
//
// It deliberately reuses the existing whitelisted fields rather than adding a
// key for the reason: the reason is already derivable from the pair
// (sip_message_len, inner_packet_len) plus the transport, and every new key in
// registerDiagnosticAllowedFieldKeys is a new chance to leak something. The
// stage stays protected_send so a reader sees one decision line per attempt.
//
// Derived integers, bools and a closed transport enum only. No SIP text,
// identity, address, port value or SPI.
func logProtectedTransportDecision(plan protectedRegisterPlan) {
	innerLen := registerProtectedInnerPacketLen(plan.SIPMessageLen)
	logRegisterDiagnostic(registerDiagnostic{
		stage:              "protected_send",
		result:             "sending",
		transport:          plan.Transport,
		protected:          true,
		ipsecInstalled:     true,
		sipMessageLen:      plan.SIPMessageLen,
		exceedsUDPMTULimit: registerSIPMessageExceedsUDPLimit(plan.SIPMessageLen),
		innerPacketLen:     innerLen,
		rawIPPacketCount:   registerProtectedRawIPPacketCount(innerLen),
		fragmented:         registerProtectedInnerIsFragmented(innerLen),
	})
}

// logProtectedRegisterReadFailure reports the bounded userspace-ESP counters
// after a protected REGISTER produced no SIP response.
//
// Transport.Stats() already tracks these, but nothing logged them, so a timeout
// could not be told apart from packets arriving and being dropped by the ESP
// transform or the anti-replay window. Counters only: no ESP payload, no SPI,
// no address, no key material.
func logProtectedRegisterReadFailure(state *registerState) {
	d := registerDiagnostic{
		stage:     "protected_read_timeout",
		result:    "no_sip_response",
		protected: true,
	}
	if state != nil && state.channel != nil {
		stats := state.channel.Stats()
		d.ipsecInstalled = true
		d.peerIPInboundPackets = boundRegisterESPCounterU64(stats.PeerInboundPackets)
		d.espOutboundPackets = boundRegisterESPCounterU64(stats.OutboundPackets)
		d.espInboundPackets = boundRegisterESPCounterU64(stats.InboundPackets)
		d.espTransformErrors = boundRegisterESPCounterU64(stats.TransformErrors)
		d.espPassthroughPackets = boundRegisterESPCounterU64(stats.PassthroughPackets)
		d.espReplayDuplicate = boundRegisterESPCounterU64(stats.Replay.Duplicate)
		d.espReplayTooOld = boundRegisterESPCounterU64(stats.Replay.TooOld)
	}
	logRegisterDiagnostic(d)
}

func registerVariantDiagnosticName(variant initialRegisterVariant) string {
	if variant.hasSecurityClientMechanism {
		return "security_mechanism_probe"
	}
	switch strings.TrimSpace(variant.name) {
	case "with_required_sec_agree", "without_required_sec_agree":
		return strings.TrimSpace(variant.name)
	default:
		return "default"
	}
}
