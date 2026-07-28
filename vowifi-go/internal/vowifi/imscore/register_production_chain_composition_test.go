package imscore

import (
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

// This file is the characterization test for the protected REGISTER's size and
// header composition. It exists because an earlier measurement in this package
// built its baseline with buildRegisterRequest(initial=false), which is NOT how
// the protected REGISTER is produced. Production clones the INITIAL request:
//
//	buildRegisterRequest(initial=true)   <- MinimalInitialHeaders applies HERE
//	  -> decorateRegisterRequest          register_session.go registerOnce
//	  -> lastReq.Clone()                  register_session.go:395
//	  -> RemoveHeader(Via/Authorization), AppendHeader(Authorization)
//	  -> decorateRegisterRequest
//	  -> buildAuthenticatedRegister       clone + Authorization + Security-Verify
//	  -> prepareProtectedRegisterRequest  Via/CSeq/Contact rewrite
//
// Because MinimalInitialHeaders is already true for 3gpp-default, the initial
// request never carries Allow, Accept-Contact, P-Preferred-Identity,
// P-Visited-Network-ID or Cellular-Network-Info -- and neither does the
// protected clone. A previous attempt to strip Allow/Accept-Contact from the
// protected request therefore saved nothing on device: the 190-byte saving only
// ever existed in the wrong baseline. That code has been removed; these tests
// pin the facts so the mistake cannot be repeated.
//
// Confirmed on device (2026-07-26): protected sip_message_len=1360,
// inner_packet_len=1452, fragment_count=2, while the initial REGISTER is
// answered with a 401 at a size that needs no fragmentation.
//
// Everything here records header NAMES, byte LENGTHS and counts only. No test
// asserts or prints a header value, URI, address, identity, nonce,
// Authorization or key material.

// headersAbsentFromMinimalInitialRegister are the optional headers that
// buildRegisterRequest omits when MinimalInitialHeaders is set. They are listed
// here so the test can prove the protected clone inherits their absence.
var headersAbsentFromMinimalInitialRegister = []string{
	"Allow",
	"Accept-Contact",
	"P-Preferred-Identity",
	"P-Visited-Network-ID",
	"Cellular-Network-Info",
}

// syntheticProtectedRegisterConfig builds a Config with entirely synthetic
// identities whose lengths match real-world shapes (15-digit IMSI, full realm)
// so measured sizes are representative. These values are longer than the
// device's, so the synthetic total runs above the measured 1360.
func syntheticProtectedRegisterConfig() Config {
	return Config{
		TraceID:               "synthetic-trace",
		DeviceID:              "synthetic-device",
		CarrierBehavior:       policy.Default3GPPBehavior(),
		HomeDomain:            "ims.mnc240.mcc310.3gppnetwork.org",
		Realm:                 "ims.mnc240.mcc310.3gppnetwork.org",
		PublicURI:             "sip:310240000000000@ims.mnc240.mcc310.3gppnetwork.org",
		PrivateID:             "310240000000000@ims.mnc240.mcc310.3gppnetwork.org",
		IMSI:                  "310240000000000",
		MCC:                   "310",
		MNC:                   "240",
		CellID:                "74BDCCFFA99",
		UserAgent:             "VoHive-IMS/1.0",
		RegisterExpirySeconds: 3600,
		SIPInstanceURN:        "urn:gsma:imei:35000000-000000-0",
		LocalIP:               net.ParseIP("2607:fc20:a27c:3ab2:ac39:52db:65f0:5f80"),
		PCSCFAddr:             "[2607:fc20:a27c:3ab2:ac39:52db:65f0:5f80]:5060",
		TransportPCSCFAddr:    "[fd00:976a:14f7:36::5]:5060",
	}
}

func syntheticProtectedRegisterState(cfg Config) *registerState {
	return &registerState{
		spiC:          2001,
		spiS:          2002,
		portC:         5062,
		portS:         5063,
		transportMode: "udp",
		fromTag:       "0000000000000000",
		sipInstance:   cfg.SIPInstanceURN,
		ck:            make([]byte, 16),
		ik:            make([]byte, 16),
	}
}

// syntheticChallengeResponse is a 401 carrying a synthetic Security-Server offer
// shaped like a real P-CSCF's.
func syntheticChallengeResponse(t *testing.T) *sip.Response {
	t.Helper()
	res := sip.NewResponse(sip.StatusUnauthorized, "Unauthorized")
	res.AppendHeader(sip.NewHeader(
		"Security-Server",
		"ipsec-3gpp;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=aes-cbc;spi-c=2001;spi-s=2002;port-c=6001;port-s=6002",
	))
	return res
}

// syntheticAuthorizationHeader has the length profile of a real AKAv1-MD5
// Authorization but contains no credential material: the nonce is all 'A', the
// response all zeros.
func syntheticAuthorizationHeader() string {
	return `Digest username="310240000000000@ims.mnc240.mcc310.3gppnetwork.org",` +
		`realm="ims.mnc240.mcc310.3gppnetwork.org",` +
		`nonce="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",` +
		`uri="sip:ims.mnc240.mcc310.3gppnetwork.org",` +
		`response="00000000000000000000000000000000",` +
		`algorithm=AKAv1-MD5,cnonce="0000000000000000",qop=auth,nc=00000001,` +
		`opaque="0000000000000000"`
}

// headerValueLen reports the wire cost of every instance of a header,
// "Name: value\r\n" each. It returns a length, never the value.
func headerValueLen(req *sip.Request, name string) int {
	total := 0
	for _, h := range req.GetHeaders(name) {
		if h == nil {
			continue
		}
		total += len(name) + 2 + len(h.Value()) + 2
	}
	return total
}

// countIPSec3GPPMechanisms counts comma-separated ipsec-3gpp entries.
func countIPSec3GPPMechanisms(headerValue string) int {
	count := 0
	for _, part := range strings.Split(headerValue, ",") {
		if strings.Contains(strings.ToLower(part), "ipsec-3gpp") {
			count++
		}
	}
	return count
}

// buildProductionChainProtectedRegister drives the exact production sequence and
// returns the initial request, the protected request and the protected size.
func buildProductionChainProtectedRegister(t *testing.T) (*sip.Request, *sip.Request, int) {
	t.Helper()
	cfg := syntheticProtectedRegisterConfig()
	state := syntheticProtectedRegisterState(cfg)

	// A registerSession is what owns decorateRegisterRequest in production.
	session := &registerSession{
		cfg:           cfg,
		transportMode: "udp",
		state:         state,
		phase:         registerPhaseInitial,
		callID:        "00000000-0000-4000-8000-000000000000",
		cseq:          10001,
		localPort:     5060,
	}

	// Step 1-2: the INITIAL REGISTER, exactly as registerOnce builds it.
	initialReq, err := buildRegisterRequest(cfg, *state, true, initialRegisterVariant{
		includePANI:     templateIncludesPANI(cfg.CarrierBehavior.RegisterTemplate),
		includeCellular: true,
	})
	if err != nil {
		t.Fatalf("buildRegisterRequest(initial): %v", err)
	}
	if err := session.decorateRegisterRequest(initialReq); err != nil {
		t.Fatalf("decorateRegisterRequest(initial): %v", err)
	}

	// Step 3-4: the challenged REGISTER is a clone of the initial one
	// (register_session.go:395), not a fresh non-initial build.
	challenge := syntheticChallengeResponse(t)
	challengedReq := initialReq.Clone()
	challengedReq.RemoveHeader("Via")
	challengedReq.RemoveHeader("Authorization")
	challengedReq.AppendHeader(sip.NewHeader("Authorization", syntheticAuthorizationHeader()))
	if err := session.decorateRegisterRequest(challengedReq); err != nil {
		t.Fatalf("decorateRegisterRequest(challenged): %v", err)
	}

	// Step 5-7: install IPsec, then build and prepare the protected request.
	if err := installIPSecFromChallenge(cfg, state, challenge); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	protectedReq, _, err := buildAuthenticatedRegister(cfg, *state, challengedReq, challenge)
	if err != nil {
		t.Fatalf("buildAuthenticatedRegister: %v", err)
	}
	if err := prepareProtectedRegisterRequest(cfg, *state, protectedReq); err != nil {
		t.Fatalf("prepareProtectedRegisterRequest: %v", err)
	}
	return initialReq, protectedReq, len(protectedReq.String())
}

// TestProductionChainProtectedRegisterInheritsMinimalInitialHeaders proves the
// headers a previous fix tried to strip are already absent from BOTH the initial
// and the protected request. This is why that fix changed nothing on device.
func TestProductionChainProtectedRegisterInheritsMinimalInitialHeaders(t *testing.T) {
	initialReq, protectedReq, size := buildProductionChainProtectedRegister(t)

	if !policy.Default3GPPTemplate().MinimalInitialHeaders {
		t.Fatal("3gpp-default no longer sets MinimalInitialHeaders; this test's premise is gone")
	}
	for _, name := range headersAbsentFromMinimalInitialRegister {
		if n := headerValueLen(initialReq, name); n != 0 {
			t.Fatalf("initial REGISTER carries %s (%d bytes); MinimalInitialHeaders should have omitted it", name, n)
		}
		if n := headerValueLen(protectedReq, name); n != 0 {
			t.Fatalf("protected REGISTER carries %s (%d bytes); it should inherit the initial request's absence", name, n)
		}
	}
	t.Logf("MEASURED production_chain_sip_len=%d strippable_minimal_header_bytes=0", size)
}

// TestProductionChainSecurityClientCarriesOneMechanism pins the other dead end:
// the protected Security-Client serializes a single mechanism, so converging it
// saves nothing. mechanism_count=6 in the device diagnostic only reports how
// many mechanisms the TEMPLATE supports.
func TestProductionChainSecurityClientCarriesOneMechanism(t *testing.T) {
	_, protectedReq, _ := buildProductionChainProtectedRegister(t)

	header := protectedReq.GetHeader("Security-Client")
	if header == nil {
		t.Fatal("protected REGISTER carries no Security-Client header")
	}
	got := countIPSec3GPPMechanisms(header.Value())
	if got != 1 {
		t.Fatalf("Security-Client mechanisms = %d, want 1", got)
	}
	if supported := securityClientMechanismCount(policy.Default3GPPTemplate()); supported <= 1 {
		t.Fatalf("template supports %d mechanisms; the count>serialized distinction no longer holds", supported)
	}
	t.Logf("MEASURED serialized_mechanisms=%d template_mechanisms=%d",
		got, securityClientMechanismCount(policy.Default3GPPTemplate()))
}

// TestProductionChainProtectedRegisterComposition reports where the bytes of the
// real protected REGISTER go, and asserts that no further header removal can
// reach the unfragmented budget.
func TestProductionChainProtectedRegisterComposition(t *testing.T) {
	initialReq, protectedReq, size := buildProductionChainProtectedRegister(t)
	initialSize := len(initialReq.String())

	type entry struct {
		name  string
		bytes int
	}
	seen := map[string]bool{}
	entries := []entry{}
	for _, h := range protectedReq.Headers() {
		if h == nil || seen[h.Name()] {
			continue
		}
		seen[h.Name()] = true
		entries = append(entries, entry{name: h.Name(), bytes: headerValueLen(protectedReq, h.Name())})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].bytes > entries[j].bytes })

	headerTotal := 0
	for _, e := range entries {
		headerTotal += e.bytes
		t.Logf("HEADER %s bytes=%d", e.name, e.bytes)
	}
	t.Logf("MEASURED request_line_and_terminator_bytes=%d", size-headerTotal)
	t.Logf("MEASURED initial_sip_len=%d protected_sip_len=%d delta=%d",
		initialSize, size, size-initialSize)

	inner := registerProtectedInnerPacketLen(size)
	t.Logf("MEASURED inner_packet_len=%d fragment_count=%d",
		inner, registerProtectedRawIPPacketCount(inner))
	t.Logf("BUDGET target=%d overshoot=%d",
		protectedRegisterMaxUnfragmentedSIPLen,
		size-protectedRegisterMaxUnfragmentedSIPLen)

	// The protected request must still be the one that overflows; if it ever
	// fits, this whole line of investigation is obsolete and should be revisited
	// rather than silently passing.
	if size <= protectedRegisterMaxUnfragmentedSIPLen {
		t.Fatalf("protected REGISTER is %d bytes and now fits the budget %d; re-evaluate",
			size, protectedRegisterMaxUnfragmentedSIPLen)
	}

	// Headers a UE could omit without touching identity, credentials, routing or
	// the sec-agree negotiation. Reported for triage only; nothing removes them.
	optional := map[string]bool{"User-Agent": true, "Expires": true}
	optionalTotal := 0
	for _, e := range entries {
		if optional[e.name] {
			optionalTotal += e.bytes
		}
	}
	t.Logf("MEASURED remaining_optional_header_bytes=%d", optionalTotal)

	// The decisive fact: even removing every remaining optional header leaves
	// the request far over budget, so header trimming is not a viable fix.
	if size-optionalTotal <= protectedRegisterMaxUnfragmentedSIPLen {
		t.Fatalf("removing %d optional bytes now reaches the budget; header trimming became viable and should be reconsidered",
			optionalTotal)
	}
	t.Logf("REACHES_BUDGET removing_remaining_optional=false")
}

// TestProductionChainInitialRegisterFitsUnfragmented documents the asymmetry
// that makes the protected request the only one that fragments. The initial
// REGISTER was answered with a 401 on device, so its size is known to work on
// this network.
func TestProductionChainInitialRegisterFitsUnfragmented(t *testing.T) {
	initialReq, _, protectedSize := buildProductionChainProtectedRegister(t)
	initialSize := len(initialReq.String())

	initialInner := registerProtectedInnerPacketLen(initialSize)
	protectedInner := registerProtectedInnerPacketLen(protectedSize)
	t.Logf("MEASURED initial_sip_len=%d initial_inner_len=%d fragment_count=%d",
		initialSize, initialInner, registerProtectedRawIPPacketCount(initialInner))

	if initialSize >= protectedSize {
		t.Fatalf("initial REGISTER (%d) is not smaller than the protected one (%d)", initialSize, protectedSize)
	}
	if registerProtectedRawIPPacketCount(initialInner) != 1 {
		t.Fatalf("initial REGISTER inner packet %d fragments; it was answered with a 401 on device and must not",
			initialInner)
	}
	if registerProtectedRawIPPacketCount(protectedInner) < 2 {
		t.Fatalf("protected REGISTER inner packet %d no longer fragments; re-evaluate", protectedInner)
	}
}

// TestProductionChainCompositionNeverExposesValues guards the measurement
// helpers themselves: they must only ever produce lengths.
func TestProductionChainCompositionNeverExposesValues(t *testing.T) {
	_, protectedReq, _ := buildProductionChainProtectedRegister(t)
	for _, name := range []string{
		"Authorization", "Security-Client", "Security-Verify", "Contact", "From", "To",
	} {
		if n := headerValueLen(protectedReq, name); n < 0 {
			t.Fatalf("header %s produced a negative length", name)
		}
	}
}
