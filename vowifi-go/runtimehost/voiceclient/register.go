package voiceclient

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"

	"github.com/1239t/vowifi-go/runtimehost/simauth"
)

// maxChallengeRounds bounds the REGISTER challenge/retry loop: RFC 3310's
// sync-failure/auts resync is exactly one extra round trip (old-nonce auts
// response, then a fresh challenge), so an initial 401/407 plus up to two
// challenge rounds covers both "the normal case" and "one resync" without
// looping indefinitely against a misbehaving server.
const maxChallengeRounds = 2

// registerTransactionTimeout matches SimAdmin's LIVE_IMS_REGISTER_READ_TIMEOUT (8s)
// with margin for SWu userspace TCP setup.
const registerTransactionTimeout = 12 * time.Second

// registerDialTimeout caps the full variant/retry REGISTER sweep so a silent
// P-CSCF cannot hold IMS dial (and the SWu tunnel) for many minutes.
const registerDialTimeout = 90 * time.Second

const maxRegisterTimeoutRetries = 2

// registerWithResync sends REGISTER, answers a 401/407 with an IMS-AKA
// digest response (runtimehost/simauth), and re-answers a second challenge
// if the first attempt was itself a sync-failure/auts response -- the exact
// flow validated end-to-end in spike/sipspike/resync.
func (c *Client) registerWithResync(ctx context.Context) error {
	variants := c.registerVariants()
	var lastErr error
	for idx, profile := range variants {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.registerProfile = profile.Normalized()
		c.applyRegisterVariantIdentity(c.registerProfile)
		logger.Info("IMS REGISTER sending initial request",
			logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
			logger.String("pcscf", c.cfg.PCSCFAddr),
			logger.String("transport", c.cfg.transportNetwork()),
			logger.Int("variant", idx+1),
			logger.Int("variant_total", len(variants)),
			logger.String("register_profile", c.registerProfile.ContactFeatures),
			logger.Bool("cellular_network_info", c.registerProfile.IncludeCellularNetwork),
			logger.String("initial_auth_mode", c.registerProfile.InitialAuthorization))
		err := c.registerOnce(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRegisterVariantRetryable(err) || idx+1 >= len(variants) {
			return err
		}
		logger.Info("IMS REGISTER variant failed, trying next",
			logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
			logger.Int("variant", idx+1),
			logger.String("error", err.Error()))
	}
	return lastErr
}

func (c *Client) registerVariants() []RegisterProfile {
	if variants := registerVariantsForProfile(c.cfg.RegisterProfile.Normalized()); len(variants) > 0 {
		return variants
	}
	switch registerProfileForConfig(c.cfg).ContactFeatures {
	case "ims_features":
		return gbEERegisterVariants()
	default:
		return []RegisterProfile{c.registerProfile}
	}
}

func (c *Client) applyRegisterVariantIdentity(profile RegisterProfile) {
	imsi := strings.TrimSpace(c.cfg.IMSI)
	if imsi == "" {
		imsi = imsiFromSIPIdentity(c.cfg.PublicURI, c.cfg.PrivateID)
	}
	shape := strings.TrimSpace(profile.AuthorizationIdentity)
	if shape == "" || shape == "private_id" {
		if eap := strings.TrimSpace(c.cfg.EAPPrivateID); eap != "" {
			c.cfg.PrivateID = eap
		} else {
			c.cfg.PrivateID = c.basePrivateID
		}
		c.cfg.PublicURI = c.basePublicURI
		return
	}
	privateID, publicURI := BuildIMSIdentity(imsi, c.cfg.Realm, c.cfg.HomeDomain, shape)
	if privateID == "" || publicURI == "" {
		return
	}
	c.cfg.PrivateID = privateID
	c.cfg.PublicURI = publicURI
}

func imsiFromSIPIdentity(publicURI, privateID string) string {
	for _, candidate := range []string{publicURI, privateID} {
		candidate = strings.TrimSpace(candidate)
		if strings.HasPrefix(strings.ToLower(candidate), "sip:") {
			candidate = candidate[4:]
		}
		if idx := strings.Index(candidate, "@"); idx > 0 {
			user := strings.TrimSpace(candidate[:idx])
			user = strings.TrimPrefix(user, "0")
			if user != "" {
				return user
			}
		}
	}
	return ""
}

func (c *Client) registerOnce(ctx context.Context) error {
	var lastErr error
	for attempt := 0; attempt < maxRegisterTimeoutRetries; attempt++ {
		if attempt > 0 {
			logger.Warn("IMS REGISTER retrying after timeout",
				logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
				logger.Int("attempt", attempt+1),
				logger.Int("attempt_total", maxRegisterTimeoutRetries))
		}
		err := c.registerOnceAttempt(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRegisterTransactionTimeout(err) || attempt+1 >= maxRegisterTimeoutRetries {
			return err
		}
	}
	return lastErr
}

func (c *Client) registerOnceAttempt(ctx context.Context) error {
	req, err := c.newRequest(sip.REGISTER, c.cfg.PCSCFAddr, true)
	if err != nil {
		return err
	}

	res, err := c.doRegisterTransaction(ctx, req, sipgo.ClientRequestRegisterBuild)
	if err != nil {
		return fmt.Errorf("initial REGISTER: %w", err)
	}
	logger.Info("IMS REGISTER received response",
		logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
		logger.Int("status", res.StatusCode),
		logger.String("reason", res.Reason))
	if res.StatusCode == 423 {
		res, req, err = c.retryRegisterAfterIntervalTooBrief(ctx, res)
		if err != nil {
			return fmt.Errorf("interval-too-brief retry: %w", err)
		}
		logger.Info("IMS REGISTER received interval retry response",
			logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
			logger.Int("status", res.StatusCode),
			logger.String("reason", res.Reason))
	}

	for round := 0; round < maxChallengeRounds && (res.StatusCode == 401 || res.StatusCode == 407); round++ {
		logger.Info("IMS REGISTER answering challenge",
			logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
			logger.Int("round", round+1),
			logger.Int("status", res.StatusCode))
		res, req, err = c.answerChallenge(ctx, req, res)
		if err != nil {
			return fmt.Errorf("challenge round %d: %w", round+1, err)
		}
		logger.Info("IMS REGISTER received challenged response",
			logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
			logger.Int("round", round+1),
			logger.Int("status", res.StatusCode),
			logger.String("reason", res.Reason))
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("unexpected final REGISTER response: %d %s", res.StatusCode, res.Reason)
	}
	logger.Info("IMS REGISTER completed",
		logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
		logger.Int("status", res.StatusCode))
	return nil
}

func isRegisterVariantRetryable(err error) bool {
	if err == nil {
		return false
	}
	if isRegisterTransactionTimeout(err) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, " 403 ") ||
		strings.Contains(msg, " 401 ") ||
		strings.Contains(msg, " 407 ") ||
		strings.Contains(msg, " 480 ") ||
		strings.Contains(msg, " 503 ")
}

func isRegisterTransactionTimeout(err error) bool {
	if err == nil {
		return false
	}
	if err == context.DeadlineExceeded {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timer_b timed out") ||
		strings.Contains(msg, "timer_f timed out") ||
		strings.Contains(msg, "transaction timeout") ||
		strings.Contains(msg, "transaction ended without a response") ||
		strings.Contains(msg, "context deadline exceeded")
}

func (c *Client) retryRegisterAfterIntervalTooBrief(ctx context.Context, prevRes *sip.Response) (*sip.Response, *sip.Request, error) {
	expires := 3600
	if h := prevRes.GetHeader("Min-Expires"); h != nil {
		if v, err := strconv.Atoi(strings.TrimSpace(h.Value())); err == nil && v > expires {
			expires = v
		}
	}
	c.cfg.RegisterExpiry = time.Duration(expires) * time.Second
	logger.Info("IMS REGISTER retrying with larger Expires",
		logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
		logger.Int("expires", expires))
	req, err := c.newRequest(sip.REGISTER, c.cfg.PCSCFAddr, false)
	if err != nil {
		return nil, nil, err
	}
	res, err := c.doRegisterTransaction(ctx, req, sipgo.ClientRequestRegisterBuild)
	if err != nil {
		return nil, nil, err
	}
	return res, req, nil
}

// answerChallenge parses a 401/407's WWW-Authenticate, computes the IMS-AKA
// response via simauth (success or sync-failure, whichever the SIM
// reports), and resends. Returns the response received and the request
// actually sent, so a caller doing a second round clones from the latest
// sent request (matching the CSeq-chaining pattern from
// spike/sipspike/resync) rather than the original.
func (c *Client) answerChallenge(ctx context.Context, prevReq *sip.Request, prevRes *sip.Response) (*sip.Response, *sip.Request, error) {
	chal, err := c.selectDigestChallenge(prevRes)
	if err != nil {
		return nil, nil, err
	}

	result, err := simauth.ComputeDigest(c.cfg.AKA, chal, digest.Options{
		Method:   prevReq.Method.String(),
		URI:      prevReq.Recipient.Host,
		Username: c.cfg.PrivateID,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("simauth.ComputeDigest: %w", err)
	}

	newReq := prevReq.Clone()
	newReq.RemoveHeader("Via")
	newReq.RemoveHeader("Authorization")
	newReq.AppendHeader(sip.NewHeader("Authorization", result.Header))
	if securityServer := prevRes.GetHeader("Security-Server"); securityServer != nil {
		newReq.RemoveHeader("Security-Verify")
		newReq.AppendHeader(sip.NewHeader("Security-Verify", securityServer.Value()))
	}

	res, err := c.doRegisterTransaction(ctx, newReq, sipgo.ClientRequestIncreaseCSEQ, sipgo.ClientRequestAddVia)
	if err != nil {
		return nil, nil, err
	}
	return res, newReq, nil
}

func (c *Client) selectDigestChallenge(prevRes *sip.Response) (*digest.Challenge, error) {
	headers := prevRes.GetHeaders("WWW-Authenticate")
	if len(headers) == 0 && prevRes.StatusCode == sip.StatusProxyAuthRequired {
		headers = prevRes.GetHeaders("Proxy-Authenticate")
	}
	if len(headers) == 0 {
		return nil, fmt.Errorf("%d response with no authenticate header", prevRes.StatusCode)
	}

	var best *digest.Challenge
	bestScore := -1 << 30
	for _, header := range headers {
		for _, raw := range splitDigestChallenges(header.Value()) {
			chal, err := digest.ParseChallenge(raw)
			if err != nil {
				continue
			}
			score := c.scoreDigestChallenge(chal)
			logger.Info("IMS REGISTER challenge candidate",
				logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
				logger.String("realm", chal.Realm),
				logger.String("algorithm", chal.Algorithm),
				logger.Int("nonce_len", decodedNonceLen(chal.Nonce)),
				logger.Int("score", score))
			if best == nil || score > bestScore {
				best = chal
				bestScore = score
			}
		}
	}
	if best == nil {
		return nil, fmt.Errorf("parse challenge: no usable digest challenge found")
	}
	logger.Info("IMS REGISTER selected challenge",
		logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
		logger.String("realm", best.Realm),
		logger.String("algorithm", best.Algorithm),
		logger.Int("nonce_len", decodedNonceLen(best.Nonce)),
		logger.Int("score", bestScore))
	return best, nil
}

func splitDigestChallenges(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	lower := strings.ToLower(trimmed)
	var starts []int
	for idx := 0; ; {
		pos := strings.Index(lower[idx:], "digest ")
		if pos < 0 {
			break
		}
		starts = append(starts, idx+pos)
		idx += pos + len("digest ")
	}
	if len(starts) <= 1 {
		return []string{strings.Trim(trimmed, " ,")}
	}
	out := make([]string, 0, len(starts))
	for i, start := range starts {
		end := len(trimmed)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		part := strings.Trim(trimmed[start:end], " ,")
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (c *Client) scoreDigestChallenge(chal *digest.Challenge) int {
	if chal == nil {
		return -1
	}
	score := 0
	if strings.EqualFold(strings.TrimSpace(chal.Realm), strings.TrimSpace(c.cfg.Realm)) {
		score += 100
	}
	switch {
	case strings.EqualFold(chal.Algorithm, "AKAv1-MD5"):
		score += 40
	case strings.EqualFold(chal.Algorithm, "AKAv2-MD5"):
		score += 35
	case strings.EqualFold(chal.Algorithm, "MD5"):
		score += 10
	}
	nonceLen := decodedNonceLen(chal.Nonce)
	if nonceLen >= 32 {
		score += 20
	} else if nonceLen > 0 {
		score -= 20
	}
	return score
}

func decodedNonceLen(nonce string) int {
	if decoded, err := decodeDigestNonce(nonce); err == nil {
		return len(decoded)
	}
	return 0
}

func decodeDigestNonce(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("empty nonce")
	}
	if len(trimmed)%2 == 0 && isASCIIHex(trimmed) {
		return hex.DecodeString(trimmed)
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return decoded, nil
	}
	padded := trimmed
	for len(padded)%4 != 0 {
		padded += "="
	}
	if decoded, err := base64.StdEncoding.DecodeString(padded); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(padded); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("decode nonce failed")
}

func isASCIIHex(value string) bool {
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}

// reregisterLoop keeps the registration alive at half the requested expiry.
// Best-effort: a failed re-register is silently retried on the next tick
// rather than surfaced anywhere -- Client has no logger or event stream of
// its own yet (unlike engine/swu.Session), a real implementation would want
// one. Flagged as a known simplification, not an oversight.
func (c *Client) reregisterLoop() {
	defer close(c.stopDone)

	interval := c.cfg.registerExpiry() / 2
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = c.registerWithResync(ctx)
			cancel()
		}
	}
}

func (c *Client) doRegisterTransaction(ctx context.Context, req *sip.Request, opts ...sipgo.ClientRequestOption) (*sip.Response, error) {
	txCtx, cancel := context.WithTimeout(ctx, registerTransactionTimeout)
	defer cancel()
	return c.doTransaction(txCtx, req, opts...)
}

func (c *Client) doTransaction(ctx context.Context, req *sip.Request, opts ...sipgo.ClientRequestOption) (*sip.Response, error) {
	if c.secure != nil {
		return c.secure.RoundTrip(ctx, req)
	}
	tx, err := c.client.TransactionRequest(ctx, req, opts...)
	if err != nil {
		return nil, err
	}
	var terminateOnce sync.Once
	terminate := func() { terminateOnce.Do(func() { tx.Terminate() }) }
	defer terminate()

	select {
	case <-tx.Done():
		if err := tx.Err(); err != nil {
			return nil, fmt.Errorf("transaction ended: %w", err)
		}
		return nil, fmt.Errorf("transaction ended without a response")
	case res := <-tx.Responses():
		return res, nil
	case <-ctx.Done():
		terminate()
		return nil, ctx.Err()
	}
}
