package imscore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/emiago/sipgo/sip"
)

type registerAttemptCandidate struct {
	Registrar string
	Transport string
	Gateway   string
}

var errProtectedPortsExhausted = errors.New("imscore: protected channel client ports are exhausted")

type registerTransportAttemptResult struct {
	result      *registerResult
	err         error
	statusCode  int
	reason      string
	reachedAuth bool
}

func (s *Service) runRegisterFlow(ctx context.Context) (*registerResult, error) {
	if s == nil {
		return nil, fmt.Errorf("imscore: service is nil")
	}
	return s.registerWithTransportCandidates(ctx)
}

func (s *Service) registerRawWithCandidate(ctx context.Context, candidate registerAttemptCandidate, transportMode string, attemptIndex int) registerTransportAttemptResult {
	attemptCfg := s.cfg
	attemptCfg.PCSCFAddr = selectRegisterAttemptRegistrar(s.cfg, candidate.Registrar)
	attemptCfg.TransportPCSCFAddr = strings.TrimSpace(candidate.Gateway)
	if attemptCfg.TransportPCSCFAddr == "" {
		attemptCfg.TransportPCSCFAddr = attemptCfg.PCSCFAddr
	}

	// Admission, ports, SPIs, SA generation, and provisional cleanup all come from
	// the Service's one ProtectedChannel owner. A stopped owner rejects before any
	// network dial, and every failed candidate returns the reservation here.
	if s.protectedChannels == nil {
		return registerTransportAttemptResult{err: errors.New("imscore: protected channel owner is unavailable")}
	}
	channel, err := s.protectedChannels.Reserve()
	if err != nil {
		if ipsec3gpp.IsProtectedChannelPortsExhausted(err) {
			err = errProtectedPortsExhausted
		}
		return registerTransportAttemptResult{err: err}
	}
	releasePending := true
	defer func() {
		if releasePending {
			_ = channel.Close()
		}
	}()
	session := newRegisterSessionWithChannel(
		attemptCfg, s.swu, s.network, transportMode, attemptIndex, channel)
	attemptCtx, cancel := context.WithTimeout(ctx, registerCandidateTimeout)
	defer cancel()

	res, err := session.runInitialRegisterFlow(attemptCtx)
	session.closeConn()
	if err != nil {
		var attemptErr *registrarAttemptError
		if errors.As(err, &attemptErr) {
			return registerTransportAttemptResult{
				err:         err,
				statusCode:  attemptErr.statusCode,
				reason:      attemptErr.reason,
				reachedAuth: registerAttemptReachedAuthPhase(attemptErr.statusCode),
			}
		}
		return registerTransportAttemptResult{
			err:         err,
			reachedAuth: registerErrorReachedAuthPhase(err),
		}
	}
	if res != nil && res.channel == channel {
		releasePending = false
	} else if res != nil && res.channel != nil {
		_ = res.channel.Close()
		return registerTransportAttemptResult{err: errors.New("imscore: REGISTER returned a foreign protected channel")}
	}
	return registerTransportAttemptResult{result: res}
}

func (s *Service) attemptRegisterMode(ctx context.Context, transportMode string, candidates []registerAttemptCandidate) (*registerResult, error) {
	var last registerTransportAttemptResult
	for i, candidate := range candidates {
		if i > 0 {
			time.Sleep(registerTransportCandidateGap)
		}
		logRegisterTransportAttempt(s.cfg, transportMode, i+1, len(candidates), candidate)
		attempt := s.registerRawWithCandidate(ctx, candidate, transportMode, i)
		last = attempt
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if attempt.result != nil {
			return attempt.result, nil
		}
		if attempt.reachedAuth || registerAttemptReachedAuthPhase(attempt.statusCode) {
			attempt.reachedAuth = true
			if attempt.err != nil {
				return nil, attempt.err
			}
		}
		hasMore := i+1 < len(candidates)
		if attempt.err != nil {
			var attemptErr *registrarAttemptError
			if errors.As(attempt.err, &attemptErr) && shouldAdvanceRegistrarForNextRetry(attemptErr.statusCode, attemptErr.reason, hasMore) {
				logRegistrarRejected(s.cfg.TraceID, s.cfg.DeviceID, candidate.Registrar, attemptErr.statusCode, attemptErr.reason, i+1, len(candidates))
				continue
			}
			if shouldAdvanceRegistrarForProbeError(attempt.err, hasMore) {
				logRegistrarRejected(s.cfg.TraceID, s.cfg.DeviceID, candidate.Registrar, 0, attempt.err.Error(), i+1, len(candidates))
				continue
			}
			return nil, attempt.err
		}
	}
	if last.err != nil {
		return nil, last.err
	}
	return nil, fmt.Errorf("imscore: register: all registrar candidates rejected")
}

func (s *Service) registerWithTransportCandidates(ctx context.Context) (*registerResult, error) {
	modes := registerTransportCandidates(s.cfg, s.imsCfg.Transport)
	var lastErr error
	var lastStatus int
	var lastReason string
	reachedAuth := false

	for modeIndex, mode := range modes {
		candidates := resolveRegisterAttemptCandidates(s.cfg, mode)
		if len(candidates) == 0 {
			continue
		}
		logRegisterDiagnostic(registerDiagnostic{
			stage:            "transport_start",
			result:           "none",
			transport:        mode,
			candidateTotal:   len(candidates),
			requiresSecAgree: secAgreeEnabled(s.cfg.CarrierBehavior.RegisterTemplate),
		})

		res, err := s.attemptRegisterMode(ctx, mode, candidates)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		var attemptErr *registrarAttemptError
		if errors.As(err, &attemptErr) {
			lastStatus = attemptErr.statusCode
			lastReason = attemptErr.reason
			reachedAuth = registerAttemptReachedAuthPhase(attemptErr.statusCode)
		} else {
			lastReason = err.Error()
		}

		fallbackReason := classifySecurityFallbackReason(s.cfg, lastStatus, lastReason, reachedAuth)
		if shouldRetryNextRegisterTransport(lastStatus, err, modeIndex, len(modes), reachedAuth) {
			logRegisterDiagnostic(registerDiagnostic{
				stage:      "transport_retry",
				status:     lastStatus,
				result:     fallbackReason,
				transport:  mode,
				hasWarning: true,
			})
			continue
		}
		return nil, err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("imscore: register: no transport candidates")
}

func classifySecurityFallbackReason(cfg Config, statusCode int, reason string, reachedAuth bool) string {
	if reachedAuth || registerAttemptReachedAuthPhase(statusCode) {
		return "auth_phase_reached"
	}
	if statusCode == sip.StatusForbidden {
		return "forbidden_without_auth_challenge"
	}
	if shouldRetryInitialRegisterForStatus(cfg, statusCode) {
		return "initial_reject_fallback"
	}
	if statusCode == 0 {
		return "transport_probe_timeout"
	}
	if isTemporaryRegisterSIPResponse(statusCode) {
		return "temporary_sip_failure"
	}
	if strings.TrimSpace(reason) != "" {
		return "register_failed"
	}
	return "register_transport_failed"
}

func registerTransportCandidates(cfg Config, transport string) []string {
	mode := strings.ToLower(strings.TrimSpace(transport))
	switch mode {
	case "", "auto":
		switch cfg.CarrierBehavior.UnprotectedAutoTransport {
		case "", policy.UnprotectedRegisterUDPThenTCP:
			return []string{"udp", "tcp"}
		case policy.UnprotectedRegisterTCPOnly:
			return []string{"tcp"}
		default:
			return nil
		}
	case "tcp":
		return []string{"tcp"}
	default:
		return []string{mode}
	}
}

func resolveRegisterAttemptCandidates(cfg Config, transportMode string) []registerAttemptCandidate {
	expanded := expandRegistrarCandidates(cfg)
	if len(expanded) == 0 {
		return nil
	}
	out := make([]registerAttemptCandidate, 0, len(expanded))
	for _, item := range expanded {
		out = append(out, registerAttemptCandidate{
			Registrar: selectRegisterAttemptRegistrar(cfg, item.Registrar),
			Transport: transportMode,
			Gateway:   item.Transport,
		})
	}
	return out
}

func selectRegisterAttemptRegistrar(cfg Config, candidate string) string {
	if v := strings.TrimSpace(candidate); v != "" {
		return v
	}
	return strings.TrimSpace(cfg.PCSCFAddr)
}

func shouldRetryNextRegisterTransport(statusCode int, err error, modeIndex, modeTotal int, reachedAuth bool) bool {
	if errors.Is(err, errProtectedPortsExhausted) {
		return false
	}
	// The typed check comes first and is the authoritative one. The three
	// conditions below it all failed to see the authenticated phase in the
	// 2026-07-27 21:48 run: a protected read timeout carries statusCode=0, is not
	// a *registrarAttemptError so reachedAuth stays false, and its message matches
	// none of registerErrorReachedAuthPhase's substrings. The result was a second
	// initial REGISTER and a second AKA run on the next transport.
	if registerReachedAuthenticatedPhase(err) {
		return false
	}
	if reachedAuth || registerAttemptReachedAuthPhase(statusCode) || registerErrorReachedAuthPhase(err) {
		return false
	}
	if modeIndex+1 >= modeTotal {
		return false
	}
	// Prefer SIP status classification when a response was received.
	// Only fall back to err-based transport retry for true no-response/connect failures.
	if statusCode != 0 {
		return false
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return false
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return true
		}
		return true
	}
	return false
}

func registerErrorReachedAuthPhase(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	for _, marker := range []string{
		"authenticated register",
		"secure channel dial",
		"ipsec install",
		"challenge round",
		"unexpected challenged register response",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func registerAttemptReachedAuthPhase(statusCode int) bool {
	return statusCode == sip.StatusUnauthorized || statusCode == sip.StatusProxyAuthRequired
}

func nextRegisterTransportAttemptCSeq(previous uint32) uint32 {
	if previous > 0 {
		return previous + 1
	}
	n, err := rand.Int(rand.Reader, big.NewInt(50000))
	if err != nil {
		return 10001
	}
	return 10000 + uint32(n.Int64()) + 1
}

func logRegisterTransportAttempt(cfg Config, transportMode string, index, total int, candidate registerAttemptCandidate) {
	_ = cfg
	address := candidate.Gateway
	if strings.TrimSpace(address) == "" {
		address = candidate.Registrar
	}
	logRegisterDiagnostic(registerDiagnostic{
		stage:          "candidate_attempt",
		result:         "none",
		transport:      transportMode,
		addressFamily:  registerAddressFamily(address),
		candidateIndex: index,
		candidateTotal: total,
	})
}
