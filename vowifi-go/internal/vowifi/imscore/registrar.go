package imscore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/emiago/sipgo/sip"
	"github.com/1239t/swu-go/pkg/logger"
)

type registrarCandidate struct {
	Registrar string
	Transport string
}

type registrarAttemptError struct {
	pcscf      string
	statusCode int
	reason     string
}

func (e *registrarAttemptError) Error() string {
	return fmt.Sprintf("unexpected initial REGISTER response: %d %s", e.statusCode, e.reason)
}

func registrarCandidates(cfg Config) []string {
	if len(cfg.RegistrarCandidates) > 0 {
		return dedupeRegistrarAddrs(cfg.RegistrarCandidates)
	}
	if v := strings.TrimSpace(cfg.PCSCFAddr); v != "" {
		return []string{v}
	}
	return nil
}

func expandRegistrarCandidates(cfg Config) []registrarCandidate {
	addrs := registrarCandidates(cfg)
	if len(addrs) == 0 {
		return nil
	}

	primary, fallback := splitRegistrarCandidates(addrs, cfg.LocalIP)
	registrars := primary
	if len(registrars) == 0 {
		registrars = addrs
	}
	gateways := rankedIKEGatewayCandidates(addrs, cfg.LocalIP)

	out := make([]registrarCandidate, 0, len(registrars)*maxInt(1, len(gateways)))
	seen := make(map[string]struct{})

	appendCandidate := func(registrar, transport string) {
		registrar = strings.TrimSpace(registrar)
		transport = strings.TrimSpace(transport)
		if registrar == "" {
			return
		}
		if transport == "" {
			transport = registrar
		}
		key := registrar + "\x00" + transport
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, registrarCandidate{
			Registrar: registrar,
			Transport: transport,
		})
	}

	for _, registrar := range registrars {
		if registrarHostEqualsLocalIP(registrar, cfg.LocalIP) {
			if len(gateways) == 0 {
				appendCandidate(registrar, registrar)
				continue
			}
			for _, gateway := range gateways {
				appendCandidate(registrar, gateway)
			}
			continue
		}
		appendCandidate(registrar, registrar)
	}

	for _, registrar := range fallback {
		if registrarHostEqualsLocalIP(registrar, cfg.LocalIP) {
			continue
		}
		appendCandidate(registrar, registrar)
	}
	return out
}

func rankedIKEGatewayCandidates(addrs []string, localIP net.IP) []string {
	type scored struct {
		addr  string
		score int
	}
	items := make([]scored, 0, len(addrs))
	for _, addr := range addrs {
		if registrarHostEqualsLocalIP(addr, localIP) {
			continue
		}
		host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
		if err != nil {
			continue
		}
		items = append(items, scored{
			addr:  addr,
			score: scoreIKEGatewayHost(strings.ToLower(host)),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].score == items[j].score {
			return items[i].addr < items[j].addr
		}
		return items[i].score > items[j].score
	})

	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if _, ok := seen[item.addr]; ok {
			continue
		}
		seen[item.addr] = struct{}{}
		out = append(out, item.addr)
	}
	return out
}

func scoreIKEGatewayHost(host string) int {
	switch {
	case strings.HasPrefix(host, "2a03:dd00:1f80:"):
		return 100
	case strings.HasPrefix(host, "2a03:dd00:1f81:810:"):
		return 80
	case strings.HasPrefix(host, "2a03:dd00:1f81:10:"),
		strings.HasPrefix(host, "2a03:dd00:1f81:5010:"):
		return 10
	case strings.HasPrefix(host, "2a03:dd00:1f81:"):
		return 40
	default:
		return 30
	}
}

func pickIKEGatewayCandidate(addrs []string, localIP net.IP) string {
	gateways := rankedIKEGatewayCandidates(addrs, localIP)
	if len(gateways) == 0 {
		return ""
	}
	return gateways[0]
}

func registrarHostEqualsLocalIP(addr string, localIP net.IP) bool {
	if localIP == nil {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	rip := net.ParseIP(host)
	return rip != nil && rip.Equal(localIP)
}

func dedupeRegistrarAddrs(addrs []string) []string {
	seen := make(map[string]struct{}, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		v := strings.TrimSpace(addr)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func shouldAdvanceRegistrarForProbeError(err error, hasMore bool) bool {
	if !hasMore || err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "timed out") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "transaction ended") ||
		strings.Contains(msg, "register response timeout") ||
		strings.Contains(msg, "register connection closed")
}

func shouldAdvanceRegistrarForNextRetry(statusCode int, reason string, hasMore bool) bool {
	if !hasMore {
		return false
	}
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
		_ = reason
		return false
	}
}

func logRegistrarProbe(traceID, deviceID string, index, total int, pcscf string) {
	logger.Info("IMS REGISTER probing registrar candidate",
		logger.String("trace_id", strings.TrimSpace(traceID)),
		logger.String("device_id", strings.TrimSpace(deviceID)),
		logger.Int("candidate_index", index),
		logger.Int("candidate_total", total),
		logger.String("pcscf", pcscf))
}

func logRegistrarRejected(traceID, deviceID, pcscf string, statusCode int, reason string, index, total int) {
	logger.Warn("IMS REGISTER registrar rejected, trying next candidate",
		logger.String("trace_id", strings.TrimSpace(traceID)),
		logger.String("device_id", strings.TrimSpace(deviceID)),
		logger.String("pcscf", pcscf),
		logger.Int("status", statusCode),
		logger.String("reason", reason),
		logger.Int("candidate_index", index),
		logger.Int("candidate_total", total))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}