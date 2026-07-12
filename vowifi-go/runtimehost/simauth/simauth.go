// Package simauth computes RFC 3310 "Digest AKAv1-MD5" responses for IMS
// SIP authentication (P-CSCF/S-CSCF challenges to SIP REGISTER and other
// requests), using the same sim.AKAProvider that already authenticates the
// SWu tunnel's EAP-AKA exchange (runtimehost.Start already extracts one
// from StartRequest.SIM for exactly that). A real UE does two independent
// AKA runs per VoWiFi call setup -- one for the ePDG (EAP-AKA), one for the
// P-CSCF/S-CSCF (this package) -- against separate RAND/AUTN vectors from
// the same HSS/USIM; there's no new "source" for the provider, it's the
// same one, called again.
//
// The algorithm here was verified against the actual RFC 3310 text rather
// than reconstructed from memory:
//   - nonce = base64(RAND(16) || AUTN(16) [|| server data])
//   - success: HA1 = MD5(username:realm:RES) using the raw RES octets as
//     the password -- HA2/response otherwise identical to plain RFC 2617
//   - sync failure: client responds using an EMPTY password, and appends
//     an auts="<base64 AUTS>" directive (RFC 3310 S3.4); the server is
//     expected to resync and reissue a fresh challenge, not accept this
//     attempt -- driving that retry loop is the caller's job, this package
//     computes one round's response.
//
// icholy/digest (sipgo's digest dependency) only recognizes a fixed
// algorithm whitelist ("", "MD5", "SHA-256", "SHA-512", "SHA-512-256") and
// rejects "AKAv1-MD5" outright, so the math runs with Algorithm forced to
// "MD5" (an equivalence RFC 3310 itself states: "the Digest AKA operation
// is identical to the Digest operation in RFC 2617") while the wire-visible
// algorithm label is restored before the header is emitted.
package simauth

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/icholy/digest"

	"github.com/1239t/vowifi-go/engine/sim"
)

// randAUTNLen is the fixed length of each of RAND and AUTN per 3GPP AKA.
const randAUTNLen = 16

// Result is one round's outcome of computing an IMS-AKA digest response.
type Result struct {
	// Header is the full Authorization header value, including the
	// "Digest " prefix -- ready to send as-is.
	Header string

	// SyncFailure is true when the SIM reported a sequence-number mismatch:
	// Header carries the empty-password response plus an auts= directive,
	// and the caller should expect the server to respond with a fresh
	// challenge rather than accept this attempt.
	SyncFailure bool
}

// ComputeDigest runs one round of RFC 3310 Digest AKAv1-MD5: decodes
// RAND/AUTN out of chal.Nonce, asks provider to compute AKA, and builds the
// resulting Authorization header value -- either a normal AKA-derived
// response, or (on sim.ErrSyncFailure) the empty-password + auts= resync
// response.
//
// opts.Password is overwritten; callers only need to supply
// Method/URI/Username/Count/Cnonce as usual for icholy/digest.
func ComputeDigest(provider sim.AKAProvider, chal *digest.Challenge, opts digest.Options) (Result, error) {
	wireAlgorithm := chal.Algorithm
	if wireAlgorithm == "" {
		wireAlgorithm = "AKAv1-MD5"
	}
	mathChal := *chal
	mathChal.Algorithm = "MD5"

	rawNonce, err := decodeNonceBytes(chal.Nonce)
	if err != nil {
		return Result{}, err
	}
	if strings.EqualFold(wireAlgorithm, "MD5") && len(rawNonce) < 2*randAUTNLen {
		opts.Password = ""
		cred, err := digest.Digest(&mathChal, opts)
		if err != nil {
			return Result{}, fmt.Errorf("simauth: compute plain digest: %w", err)
		}
		cred.Algorithm = wireAlgorithm
		return Result{Header: cred.String()}, nil
	}

	if provider == nil {
		return Result{}, errors.New("simauth: AKAProvider is required")
	}

	rand16, autn16, err := splitNonce(rawNonce)
	if err != nil {
		return Result{}, err
	}

	akaResult, akaErr := provider.CalculateAKA(rand16, autn16)

	switch {
	case akaErr == nil:
		opts.Password = string(akaResult.RES)
		cred, err := digest.Digest(&mathChal, opts)
		if err != nil {
			return Result{}, fmt.Errorf("simauth: compute digest: %w", err)
		}
		cred.Algorithm = wireAlgorithm
		return Result{Header: cred.String()}, nil

	case errors.Is(akaErr, sim.ErrSyncFailure):
		opts.Password = ""
		cred, err := digest.Digest(&mathChal, opts)
		if err != nil {
			return Result{}, fmt.Errorf("simauth: compute resync digest: %w", err)
		}
		cred.Algorithm = wireAlgorithm
		header := fmt.Sprintf(`%s, auts="%s"`, cred.String(),
			base64.StdEncoding.EncodeToString(akaResult.AUTS))
		return Result{Header: header, SyncFailure: true}, nil

	default:
		return Result{}, fmt.Errorf("simauth: CalculateAKA: %w", akaErr)
	}
}

func decodeNonceBytes(nonce string) ([]byte, error) {
	trimmed := strings.TrimSpace(nonce)
	if trimmed == "" {
		return nil, errors.New("simauth: empty nonce")
	}
	if len(trimmed)%2 == 0 && isASCIIHex(trimmed) {
		raw, err := hex.DecodeString(trimmed)
		if err == nil {
			return raw, nil
		}
	}
	raw, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		padded := trimmed
		for len(padded)%4 != 0 {
			padded += "="
		}
		raw, err = base64.StdEncoding.DecodeString(padded)
		if err != nil {
			return nil, fmt.Errorf("simauth: decode nonce: %w", err)
		}
	}
	return raw, nil
}

// splitNonce splits an RFC 3310 AKAv1-MD5 nonce
// (base64(RAND || AUTN [|| server data])) into its RAND/AUTN parts.
func splitNonce(raw []byte) (rand16, autn16 []byte, err error) {
	if len(raw) < 2*randAUTNLen {
		return nil, nil, fmt.Errorf("simauth: nonce too short for RAND||AUTN (%d bytes)", len(raw))
	}
	return raw[:randAUTNLen], raw[randAUTNLen : 2*randAUTNLen], nil
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
