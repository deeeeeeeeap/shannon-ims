package imscore

import (
	"net"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
)

// A protected REGISTER that is ESP-correct and unfragmented still gets no
// answer if it is encrypted for, and sent to, the wrong P-CSCF. That is a live
// possibility here: the 2026-07-26 17:23 run showed candidate 1 timing out and
// candidate 2 answering with the 401 + Security-Server, on a different IPv6
// prefix (fd00:976a:2:239 vs fd00:976a:c005:28).
//
// registerRawWithCandidate derives a per-attempt Config:
//
//	attemptCfg := s.cfg
//	attemptCfg.PCSCFAddr          = selectRegisterAttemptRegistrar(cfg, candidate.Registrar)
//	attemptCfg.TransportPCSCFAddr = candidate.Gateway   // falls back to PCSCFAddr
//	session := newRegisterSession(attemptCfg, ...)
//
// These tests replicate that derivation for a losing and a winning candidate
// and prove every security-relevant binding follows the WINNING one: the ESP
// policy remote IP, the SPI/port role mapping taken from that candidate's
// Security-Server, and the raw-IP destination the protected request is sent to.
//
// Assertions compare derived addresses, ports and SPI role assignments. No SIP
// text, identity, nonce, Authorization or key material is asserted or logged.

// candidateAttemptConfig mirrors registerRawWithCandidate's per-attempt Config
// derivation exactly.
func candidateAttemptConfig(base Config, candidate registerAttemptCandidate) Config {
	attemptCfg := base
	attemptCfg.PCSCFAddr = selectRegisterAttemptRegistrar(base, candidate.Registrar)
	attemptCfg.TransportPCSCFAddr = strings.TrimSpace(candidate.Gateway)
	if attemptCfg.TransportPCSCFAddr == "" {
		attemptCfg.TransportPCSCFAddr = attemptCfg.PCSCFAddr
	}
	return attemptCfg
}

// The two candidates from the observed run: the first is never answered, the
// second returns the 401 that drives IPsec.
const (
	losingCandidateHost  = "fd00:976a:2:239::5"
	winningCandidateHost = "fd00:976a:c005:28::5"
)

// syntheticChallengeFromCandidate builds the 401 that the WINNING candidate
// returns, with its own distinct SPIs and protected ports so a mix-up with the
// losing candidate would be detectable.
func syntheticChallengeFromCandidate(t *testing.T) *sip.Response {
	t.Helper()
	res := sip.NewResponse(sip.StatusUnauthorized, "Unauthorized")
	res.AppendHeader(sip.NewHeader(
		"Security-Server",
		"ipsec-3gpp;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=aes-cbc;"+
			"spi-c=7001;spi-s=7002;port-c=7061;port-s=7062",
	))
	return res
}

// TestProtectedRegisterUsesWinningPCSCFCandidate is the core oracle: after the
// first candidate fails and the second answers, every binding must point at the
// second.
func TestProtectedRegisterUsesWinningPCSCFCandidate(t *testing.T) {
	base := syntheticProtectedRegisterConfig()

	losing := candidateAttemptConfig(base, registerAttemptCandidate{
		Registrar: net.JoinHostPort(base.LocalIP.String(), "5060"),
		Gateway:   net.JoinHostPort(losingCandidateHost, "5060"),
	})
	winning := candidateAttemptConfig(base, registerAttemptCandidate{
		Registrar: net.JoinHostPort(base.LocalIP.String(), "5060"),
		Gateway:   net.JoinHostPort(winningCandidateHost, "5060"),
	})

	// Precondition: the two candidates really are distinct, otherwise this test
	// proves nothing.
	losingIP := effectiveIPSecRemoteIP(losing)
	winningIP := effectiveIPSecRemoteIP(winning)
	if losingIP == nil || winningIP == nil {
		t.Fatal("both candidates must resolve to an IPsec remote IP")
	}
	if losingIP.Equal(winningIP) {
		t.Fatal("test candidates are identical; cannot detect a mis-binding")
	}

	// The winning candidate's 401 drives IPsec installation.
	state := syntheticProtectedRegisterState(winning)
	challenge := syntheticChallengeFromCandidate(t)
	if err := installIPSecFromChallenge(winning, state, challenge); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}

	// 1. The ESP policy remote IP must be the winning candidate.
	policyRemote := net.IP(state.ipsecPolicy.RemoteIP)
	if !policyRemote.Equal(winningIP) {
		t.Fatalf("IPsec policy remote is not the winning candidate")
	}
	if policyRemote.Equal(losingIP) {
		t.Fatal("IPsec policy remote is bound to the losing candidate")
	}

	// 2. SPI and port roles must come from the winning candidate's
	// Security-Server. Per TS 33.203, the UE's outbound client flow uses the
	// P-CSCF's spi-s, and its outbound server flow uses the P-CSCF's spi-c.
	if got := state.ipsecPolicy.FlowC.OutboundSPI; got != 7002 {
		t.Fatalf("FlowC outbound SPI = %d, want the offered spi-s 7002", got)
	}
	if got := state.ipsecPolicy.FlowS.OutboundSPI; got != 7001 {
		t.Fatalf("FlowS outbound SPI = %d, want the offered spi-c 7001", got)
	}
	// Inbound SPIs stay the UE's own Security-Client values.
	if got := state.ipsecPolicy.FlowC.InboundSPI; got != state.spiC {
		t.Fatalf("FlowC inbound SPI = %d, want the UE spi-c", got)
	}
	if got := state.ipsecPolicy.FlowS.InboundSPI; got != state.spiS {
		t.Fatalf("FlowS inbound SPI = %d, want the UE spi-s", got)
	}
	// Remote protected ports must be the offered ones.
	if got := state.ipsecPolicy.RemotePortC; got != 7061 {
		t.Fatalf("remote port-c = %d, want the offered 7061", got)
	}
	if got := state.ipsecPolicy.RemotePortS; got != 7062 {
		t.Fatalf("remote port-s = %d, want the offered 7062", got)
	}

	// 3. The raw-IP destination of the protected request must be the winning
	// candidate. dialSecureRegisterConn dials net.IP(state.ipsecPolicy.RemoteIP),
	// and prepareProtectedRegisterRequest sets the SIP destination from the same
	// field, so both follow from the policy remote above; assert the request
	// destination explicitly because that is what actually goes on the wire.
	protectedReq, _, err := buildAuthenticatedRegister(
		winning, *state, syntheticChallengedRequest(t, winning, state), challenge)
	if err != nil {
		t.Fatalf("buildAuthenticatedRegister: %v", err)
	}
	if err := prepareProtectedRegisterRequest(winning, *state, protectedReq); err != nil {
		t.Fatalf("prepareProtectedRegisterRequest: %v", err)
	}
	destHost, destPort, err := net.SplitHostPort(protectedReq.Destination())
	if err != nil {
		t.Fatalf("protected request destination is not host:port")
	}
	if dest := net.ParseIP(destHost); dest == nil || !dest.Equal(winningIP) {
		t.Fatal("protected request destination is not the winning candidate")
	}
	// It must target the offered protected SERVER port (port-s), not port-c and
	// not a default. Per TS 33.203 the UE's outbound protected request travels
	// SA1: UE protected client port -> P-CSCF protected server port. That is why
	// prepareProtectedRegisterRequest uses FlowC.RemotePort, which NewPolicy maps
	// to the offered port-s.
	if destPort != "7062" {
		t.Fatalf("protected request destination port = %s, want the offered port-s 7062", destPort)
	}
}

// TestLosingCandidateNeverLeaksIntoProtectedBinding guards the specific failure
// this oracle exists for: a stale attempt's gateway surviving into the IPsec
// policy of a later attempt.
func TestLosingCandidateNeverLeaksIntoProtectedBinding(t *testing.T) {
	base := syntheticProtectedRegisterConfig()

	// Attempt 1 runs first and fails.
	losing := candidateAttemptConfig(base, registerAttemptCandidate{
		Registrar: net.JoinHostPort(base.LocalIP.String(), "5060"),
		Gateway:   net.JoinHostPort(losingCandidateHost, "5060"),
	})
	losingState := syntheticProtectedRegisterState(losing)
	if err := installIPSecFromChallenge(losing, losingState, syntheticChallengeResponse(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge(losing): %v", err)
	}

	// Attempt 2 then runs with a fresh Config and a fresh state, exactly as
	// registerRawWithCandidate does per candidate.
	winning := candidateAttemptConfig(base, registerAttemptCandidate{
		Registrar: net.JoinHostPort(base.LocalIP.String(), "5060"),
		Gateway:   net.JoinHostPort(winningCandidateHost, "5060"),
	})
	winningState := syntheticProtectedRegisterState(winning)
	if err := installIPSecFromChallenge(winning, winningState, syntheticChallengeFromCandidate(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge(winning): %v", err)
	}

	losingIP := effectiveIPSecRemoteIP(losing)
	if net.IP(winningState.ipsecPolicy.RemoteIP).Equal(losingIP) {
		t.Fatal("the second attempt's IPsec policy is bound to the first candidate")
	}
	// The first attempt's own policy must be unchanged; state is per-attempt.
	if !net.IP(losingState.ipsecPolicy.RemoteIP).Equal(losingIP) {
		t.Fatal("the first attempt's policy was mutated by the second attempt")
	}
	// And the two attempts must not share SPI role assignments.
	if losingState.ipsecPolicy.FlowC.OutboundSPI == winningState.ipsecPolicy.FlowC.OutboundSPI {
		t.Fatal("both attempts derived the same outbound SPI; offers were not applied per candidate")
	}
}

// TestEffectiveIPSecRemoteIPPrefersCurrentAttempt pins the precedence that makes
// the binding correct: the current attempt's gateway wins over any ranked
// fallback derived from the full candidate list.
func TestEffectiveIPSecRemoteIPPrefersCurrentAttempt(t *testing.T) {
	base := syntheticProtectedRegisterConfig()
	// A candidate list whose ranked pick is deliberately NOT the current attempt.
	base.RegistrarCandidates = []string{
		net.JoinHostPort(losingCandidateHost, "5060"),
		net.JoinHostPort(winningCandidateHost, "5060"),
	}
	cfg := candidateAttemptConfig(base, registerAttemptCandidate{
		Registrar: net.JoinHostPort(base.LocalIP.String(), "5060"),
		Gateway:   net.JoinHostPort(winningCandidateHost, "5060"),
	})
	got := effectiveIPSecRemoteIP(cfg)
	if got == nil || !got.Equal(net.ParseIP(winningCandidateHost)) {
		t.Fatal("effectiveIPSecRemoteIP did not prefer the current attempt's gateway")
	}
}

// syntheticChallengedRequest builds the challenged REGISTER that
// buildAuthenticatedRegister clones, using the production initial-request path.
func syntheticChallengedRequest(t *testing.T, cfg Config, state *registerState) *sip.Request {
	t.Helper()
	session := &registerSession{
		cfg:           cfg,
		transportMode: "udp",
		state:         state,
		phase:         registerPhaseInitial,
		callID:        "00000000-0000-4000-8000-000000000000",
		cseq:          20001,
		localPort:     5060,
	}
	req, err := buildRegisterRequest(cfg, *state, true, initialRegisterVariant{
		includePANI:     templateIncludesPANI(cfg.CarrierBehavior.RegisterTemplate),
		includeCellular: true,
	})
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}
	if err := session.decorateRegisterRequest(req); err != nil {
		t.Fatalf("decorateRegisterRequest: %v", err)
	}
	req.AppendHeader(sip.NewHeader("Authorization", syntheticAuthorizationHeader()))
	return req
}
