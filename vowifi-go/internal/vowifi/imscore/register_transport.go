package imscore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
)

type registerAttemptCandidate struct {
	Registrar string
	Transport string
	Gateway   string
}

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

	session := newRegisterSession(attemptCfg, s.swu, s.network, transportMode, attemptIndex)
	attemptCtx, cancel := context.WithTimeout(ctx, registerCandidateTimeout)
	defer cancel()

	res, err := session.runInitialRegisterFlow(attemptCtx)
	session.closeConn()
	if err != nil {
		var attemptErr *registrarAttemptError
		if errors.As(err, &attemptErr) {
			return registerTransportAttemptResult{
				err:        err,
				statusCode: attemptErr.statusCode,
				reason:     attemptErr.reason,
			}
		}
		return registerTransportAttemptResult{err: err}
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
		logger.Info("IMS REGISTER transport",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("transport_mode", mode),
			logger.Int("candidate_total", len(candidates)),
			logger.String("configured_sec_agree_mode", strings.TrimSpace(s.cfg.Template.SecAgreeMode)))

		res, err := s.attemptRegisterMode(ctx, mode, candidates)
		if err == nil {
			return res, nil
		}
		lastErr = err

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
			logger.Info("IMS REGISTER transport retry",
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("transport_mode", mode),
				logger.String("security_fallback_reason", fallbackReason),
				logger.Int("status", lastStatus),
				logger.String("reason", lastReason))
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
		return strings.TrimSpace(reason)
	}
	return "register_transport_failed"
}

func registerTransportCandidates(cfg Config, transport string) []string {
	mode := strings.ToLower(strings.TrimSpace(transport))
	switch mode {
	case "", "auto":
		if strings.EqualFold(strings.TrimSpace(cfg.Template.ID), "vodafone_uk_23415") {
			return []string{"udp", "tcp"}
		}
		return []string{"tcp"}
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
	if reachedAuth || registerAttemptReachedAuthPhase(statusCode) || registerErrorReachedAuthPhase(err) {
		return false
	}
	if modeIndex+1 >= modeTotal {
		return false
	}
	// Prefer SIP status classification when a response was received.
	// Only fall back to err-based transport retry for true no-response/connect failures.
	if statusCode != 0 {
		switch statusCode {
		case sip.StatusForbidden,
			sip.StatusRequestTimeout,
			sip.StatusInternalServerError,
			sip.StatusBadGateway,
			sip.StatusServiceUnavailable,
			sip.StatusGatewayTimeout,
			sip.StatusTemporarilyUnavailable:
			return true
		default:
			return false
		}
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return false
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
	logger.Info("IMS REGISTER probing registrar candidate",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
		logger.String("transport_mode", transportMode),
		logger.Int("registrar_index", index),
		logger.Int("candidate_total", total),
		logger.String("pcscf", candidate.Registrar),
		logger.String("transport_target", candidate.Gateway))
}
