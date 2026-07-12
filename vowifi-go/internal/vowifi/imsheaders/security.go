package imsheaders

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

// SecurityMechanism captures the cryptographic parameters of one ipsec-3gpp
// security offer.
type SecurityMechanism struct {
	Alg  string
	EAlg string
	Prot string
	Mode string
}

// SecurityOffer is one mechanism entry from Security-Server or Security-Verify.
type SecurityOffer struct {
	Mechanism string
	Q         float64
	SecurityMechanism
	SPIC  uint32
	SPIS  uint32
	PortC int
	PortS int
}

var (
	ErrEmptySecurityHeader      = errors.New("empty security header")
	ErrNoSecurityOffers         = errors.New("no security offers found")
	ErrNoMatchingSecurityOffer  = errors.New("no matching security-server offer")
	ErrIncompleteSecurityParams = errors.New("incomplete security-server parameters")
)

// ParseSecurityServer parses a Security-Server (or Security-Verify) header value
// into individual offers. Shared spi/port parameters on the final segment are
// propagated to every offer.
func ParseSecurityServer(value string) ([]SecurityOffer, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, ErrEmptySecurityHeader
	}

	segments := splitSecurityOffers(value)
	if len(segments) == 0 {
		return nil, ErrNoSecurityOffers
	}

	offers := make([]SecurityOffer, 0, len(segments))
	var shared struct {
		spic  uint32
		spis  uint32
		portC int
		portS int
		set   bool
	}

	for _, segment := range segments {
		offer, params, err := parseSecurityOfferSegment(segment)
		if err != nil {
			return nil, err
		}
		if params.set {
			shared = params
		}
		offers = append(offers, offer)
	}

	if shared.set {
		for i := range offers {
			offers[i].SPIC = shared.spic
			offers[i].SPIS = shared.spis
			offers[i].PortC = shared.portC
			offers[i].PortS = shared.portS
		}
	}

	return offers, nil
}

// SelectSecurityServerOffer picks the server offer used for IPSec installation.
// When strict is true the chosen offer must match one of the client mechanisms.
// Otherwise the highest-q offer with complete server parameters is returned.
func SelectSecurityServerOffer(offers []SecurityOffer, clientMechanisms []policy.IPSec3GPPSecurityMechanism, strict bool) (*SecurityOffer, error) {
	if len(offers) == 0 {
		return nil, ErrNoSecurityOffers
	}

	var (
		bestMatch   *SecurityOffer
		bestMatchQ  = -1.0
		bestAny     *SecurityOffer
		bestAnyQ    = -1.0
	)

	for i := range offers {
		offer := offers[i]
		if offerHasServerParams(offer) && offer.Q > bestAnyQ {
			copy := offer
			bestAny = &copy
			bestAnyQ = offer.Q
		}

		if !mechanismMatchesClient(offer.SecurityMechanism, clientMechanisms) {
			continue
		}
		if offer.Q > bestMatchQ {
			copy := offer
			bestMatch = &copy
			bestMatchQ = offer.Q
		}
	}

	if bestMatch != nil {
		if !offerHasServerParams(*bestMatch) {
			return nil, ErrIncompleteSecurityParams
		}
		return bestMatch, nil
	}
	if strict {
		return nil, ErrNoMatchingSecurityOffer
	}
	if bestAny == nil {
		return nil, ErrIncompleteSecurityParams
	}
	return bestAny, nil
}

// BuildSecurityVerify formats the Security-Verify header value for the chosen
// offer. Author captures echo the full Security-Server list; when only the
// selected offer is available we emit that mechanism with server parameters.
func BuildSecurityVerify(selected SecurityOffer) string {
	return formatSecurityOffer(selected, true)
}

// BuildSecurityVerifyEcho mirrors the full Security-Server offer list for the
// authenticated REGISTER round (author v1.1.2 sec-agree behavior).
func BuildSecurityVerifyEcho(offers []SecurityOffer) string {
	if len(offers) == 0 {
		return ""
	}
	parts := make([]string, 0, len(offers))
	for _, offer := range offers {
		parts = append(parts, formatSecurityOffer(offer, true))
	}
	return strings.Join(parts, ",")
}

func splitSecurityOffers(value string) []string {
	var (
		segments []string
		start    int
	)
	for i := 0; i < len(value); i++ {
		if value[i] != ',' {
			continue
		}
		if i+1 < len(value) && strings.HasPrefix(value[i+1:], "ipsec-3gpp") {
			segments = append(segments, strings.TrimSpace(value[start:i]))
			start = i + 1
		}
	}
	segments = append(segments, strings.TrimSpace(value[start:]))
	return segments
}

func parseSecurityOfferSegment(segment string) (SecurityOffer, struct {
	spic  uint32
	spis  uint32
	portC int
	portS int
	set   bool
}, error) {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return SecurityOffer{}, struct {
			spic  uint32
			spis  uint32
			portC int
			portS int
			set   bool
		}{}, ErrNoSecurityOffers
	}

	offer := SecurityOffer{}
	params := struct {
		spic  uint32
		spis  uint32
		portC int
		portS int
		set   bool
	}{}

	parts := strings.Split(segment, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "=") {
			offer.Mechanism = strings.TrimSpace(part)
			continue
		}

		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		val = strings.TrimSpace(val)

		switch key {
		case "q":
			q, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return offer, params, fmt.Errorf("parse security offer q: %w", err)
			}
			offer.Q = q
		case "alg":
			offer.Alg = val
		case "ealg":
			offer.EAlg = val
		case "prot":
			offer.Prot = val
		case "mod":
			offer.Mode = val
		case "spi-c":
			v, err := parseUint32(val)
			if err != nil {
				return offer, params, fmt.Errorf("parse spi-c: %w", err)
			}
			offer.SPIC = v
			params.spic = v
			params.set = true
		case "spi-s":
			v, err := parseUint32(val)
			if err != nil {
				return offer, params, fmt.Errorf("parse spi-s: %w", err)
			}
			offer.SPIS = v
			params.spis = v
			params.set = true
		case "port-c":
			v, err := strconv.Atoi(val)
			if err != nil {
				return offer, params, fmt.Errorf("parse port-c: %w", err)
			}
			offer.PortC = v
			params.portC = v
			params.set = true
		case "port-s":
			v, err := strconv.Atoi(val)
			if err != nil {
				return offer, params, fmt.Errorf("parse port-s: %w", err)
			}
			offer.PortS = v
			params.portS = v
			params.set = true
		}
	}

	if offer.Mechanism == "" {
		offer.Mechanism = "ipsec-3gpp"
	}
	if offer.Mode == "" {
		offer.Mode = "trans"
	}
	offer.EAlg = canonicalEAlg(offer.EAlg)
	return offer, params, nil
}

func formatSecurityOffer(offer SecurityOffer, includeServerParams bool) string {
	var b strings.Builder
	b.WriteString(offer.Mechanism)
	if offer.Q > 0 {
		fmt.Fprintf(&b, ";q=%s", formatQ(offer.Q))
	}
	if alg := strings.TrimSpace(offer.Alg); alg != "" {
		b.WriteString(";alg=")
		b.WriteString(alg)
	}
	if mode := strings.TrimSpace(offer.Mode); mode != "" {
		b.WriteString(";mod=")
		b.WriteString(mode)
	}
	if prot := strings.TrimSpace(offer.Prot); prot != "" {
		b.WriteString(";prot=")
		b.WriteString(prot)
	}
	if ealg := canonicalEAlg(offer.EAlg); ealg != "" && ealg != "null" {
		b.WriteString(";ealg=")
		b.WriteString(ealg)
	}
	if includeServerParams && offerHasServerParams(offer) {
		fmt.Fprintf(&b, ";spi-c=%d;spi-s=%d;port-c=%d;port-s=%d", offer.SPIC, offer.SPIS, offer.PortC, offer.PortS)
	}
	return b.String()
}

func mechanismMatchesClient(server SecurityMechanism, clientMechanisms []policy.IPSec3GPPSecurityMechanism) bool {
	if len(clientMechanisms) == 0 {
		clientMechanisms = policy.DefaultSecurityClientMechanisms()
	}
	serverAlg := strings.ToLower(strings.TrimSpace(server.Alg))
	serverEAlg := canonicalEAlg(server.EAlg)
	for _, client := range clientMechanisms {
		if strings.ToLower(strings.TrimSpace(client.Alg)) != serverAlg {
			continue
		}
		if canonicalEAlg(client.EAlg) != serverEAlg {
			continue
		}
		return true
	}
	return false
}

func offerHasServerParams(offer SecurityOffer) bool {
	return offer.SPIC != 0 && offer.SPIS != 0 && offer.PortC > 0 && offer.PortS > 0
}

func canonicalEAlg(ealg string) string {
	ealg = strings.TrimSpace(strings.ToLower(ealg))
	if ealg == "" || ealg == "null" {
		return "null"
	}
	return ealg
}

func formatQ(q float64) string {
	s := strconv.FormatFloat(q, 'f', -1, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s
}

func parseUint32(raw string) (uint32, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32)
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint32 {
		return 0, fmt.Errorf("value out of range: %s", raw)
	}
	return uint32(v), nil
}