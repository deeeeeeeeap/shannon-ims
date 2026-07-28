package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	defaultSWUTunnelBudget = 90 * time.Second
	maxEPDGCandidates      = 8
)

var (
	errEPDGDNS          = errors.New("ePDG DNS failed")
	errTunnelIKETimeout = errors.New("tunnel_ike_timeout")
)

type epdgResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type epdgCandidate struct {
	IP     net.IP
	Family string
	Index  int
	Total  int
}

type swuSessionStarter func(context.Context, StartRequest, epdgCandidate, string) (*swuSessionLease, error)

func (i *Instance) establishSWu(
	ctx context.Context,
	req StartRequest,
	host string,
	port string,
	generation uint64,
) (*swuSessionLease, error) {
	resolver := req.epdgResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, errEPDGDNS
	}
	candidates := normalizeEPDGCandidates(addresses, maxEPDGCandidates)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: empty address set", errEPDGDNS)
	}

	starter := req.swuStarter
	if starter == nil {
		starter = func(ctx context.Context, attemptReq StartRequest, candidate epdgCandidate, port string) (*swuSessionLease, error) {
			return i.startSWuSession(ctx, attemptReq, candidate.IP.String(), port)
		}
	}

	totalBudget := req.swuTunnelBudget
	if totalBudget <= 0 {
		totalBudget = defaultSWUTunnelBudget
	}
	deadline := time.Now().Add(totalBudget)
	for idx, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		left := len(candidates) - idx
		attemptReq := req
		attemptReq.swuConnectBudget = remaining / time.Duration(left)
		attemptReq.swuCandidate = candidate

		if !i.updateStateForGeneration(generation, func(s *State) {
			s.LastReason = fmt.Sprintf("tunnel_starting family=%s candidate=%d/%d", candidate.Family, candidate.Index, candidate.Total)
			s.UpdatedAt = time.Now()
		}) || !i.notifyObserversForGeneration(ctx, generation) {
			return nil, context.Canceled
		}

		lease, err := starter(ctx, attemptReq, candidate, port)
		if err == nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				if lease != nil {
					if joinErr := lease.CancelAndJoin(); joinErr != nil {
						return nil, fmt.Errorf("%w: canceled lease join: %v", ctxErr, joinErr)
					}
				}
				return nil, ctxErr
			}
			if lease == nil {
				return nil, errors.New("SWu starter returned a nil lease")
			}
			if !i.installSWULease(generation, lease) {
				if joinErr := lease.CancelAndJoin(); joinErr != nil {
					return nil, fmt.Errorf("%w: stale lease join: %v", context.Canceled, joinErr)
				}
				return nil, context.Canceled
			}
			return lease, nil
		}
		if lease != nil {
			if joinErr := lease.CancelAndJoin(); joinErr != nil {
				return nil, fmt.Errorf("%w: candidate lease join: %v", err, joinErr)
			}
		}
		if !retryableSWUCandidateError(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w: all %d ePDG candidates timed out", errTunnelIKETimeout, len(candidates))
}

func normalizeEPDGCandidates(addresses []net.IPAddr, limit int) []epdgCandidate {
	if limit <= 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(addresses))
	resolved := make([]epdgCandidate, 0, len(addresses))
	for _, address := range addresses {
		ip := address.IP
		family := ""
		if v4 := ip.To4(); v4 != nil {
			ip = append(net.IP(nil), v4...)
			family = "ipv4"
		} else if v6 := ip.To16(); v6 != nil {
			ip = append(net.IP(nil), v6...)
			family = "ipv6"
		} else {
			continue
		}
		key := family + ":" + ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		resolved = append(resolved, epdgCandidate{IP: ip, Family: family})
	}
	if len(resolved) == 0 {
		return nil
	}

	ordered := make([]epdgCandidate, 0, len(resolved))
	selected := make(map[string]struct{}, 2)
	appendCandidate := func(candidate epdgCandidate) {
		key := candidate.Family + ":" + candidate.IP.String()
		if _, ok := selected[key]; ok {
			return
		}
		selected[key] = struct{}{}
		ordered = append(ordered, candidate)
	}
	appendCandidate(resolved[0])
	for _, candidate := range resolved[1:] {
		if candidate.Family != resolved[0].Family {
			appendCandidate(candidate)
			break
		}
	}
	for _, candidate := range resolved[1:] {
		appendCandidate(candidate)
	}
	if len(ordered) > limit {
		ordered = ordered[:limit]
	}
	for idx := range ordered {
		ordered[idx].Index = idx + 1
		ordered[idx].Total = len(ordered)
	}
	return ordered
}

func retryableSWUCandidateError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errSWuConnectJoinTimeout) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	switch classifyTunnelFailure(err) {
	case "tunnel_ike_timeout", "tunnel_network_failed":
		return true
	default:
		return false
	}
}
