package ipsec3gpp

import (
	"fmt"
	"strconv"
	"strings"
)

// SecurityMechanism is a parsed ipsec-3gpp offer from Security-Client/Server/Verify.
type SecurityMechanism struct {
	Alg   string
	EAlg  string
	Prot  string
	Mode  string
	SPIc  uint32
	SPIs  uint32
	PortC int
	PortS int
	Raw   string
}

// ParseSecurityMechanisms parses a comma-separated Security-Client or Security-Server header value.
func ParseSecurityMechanisms(header string) ([]SecurityMechanism, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, nil
	}
	parts := splitMechanisms(header)
	out := make([]SecurityMechanism, 0, len(parts))
	for _, part := range parts {
		mech, err := parseSecurityMechanism(part)
		if err != nil {
			return nil, err
		}
		out = append(out, mech)
	}
	return out, nil
}

// ParseSecurityMechanism parses a single ipsec-3gpp mechanism token.
func ParseSecurityMechanism(token string) (SecurityMechanism, error) {
	return parseSecurityMechanism(token)
}

// FormatSecurityMechanism renders an ipsec-3gpp mechanism for Security-Client/Verify headers.
func FormatSecurityMechanism(m SecurityMechanism) string {
	alg := canonicalAuthAlg(m.Alg)
	ealg := canonicalEncAlg(m.EAlg)
	prot := strings.TrimSpace(m.Prot)
	if prot == "" {
		prot = "esp"
	}
	mode := strings.TrimSpace(m.Mode)
	if mode == "" {
		mode = "trans"
	}
	return fmt.Sprintf(
		"ipsec-3gpp; alg=%s; ealg=%s; prot=%s; mod=%s; spi-c=%d; spi-s=%d; port-c=%d; port-s=%d",
		alg, ealg, prot, mode, m.SPIc, m.SPIs, m.PortC, m.PortS,
	)
}

// SelectSecurityMechanism returns the first mechanism that includes SPI and port assignments.
func SelectSecurityMechanism(mechanisms []SecurityMechanism) (SecurityMechanism, bool) {
	for _, mech := range mechanisms {
		if mech.SPIc != 0 && mech.SPIs != 0 && mech.PortC != 0 && mech.PortS != 0 {
			return mech, true
		}
	}
	return SecurityMechanism{}, false
}

func parseSecurityMechanism(raw string) (SecurityMechanism, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return SecurityMechanism{}, fmt.Errorf("ipsec3gpp: empty security mechanism")
	}
	mech := SecurityMechanism{Raw: raw}
	scheme, params, ok := strings.Cut(raw, ";")
	if !ok {
		scheme = raw
	}
	scheme = trimToken(strings.TrimPrefix(scheme, " "))
	if !strings.EqualFold(scheme, "ipsec-3gpp") {
		return SecurityMechanism{}, fmt.Errorf("ipsec3gpp: unsupported mechanism %q", scheme)
	}
	for _, param := range strings.Split(params, ";") {
		key, value, ok := strings.Cut(param, "=")
		if !ok {
			continue
		}
		key = normalizeMechanismToken(key)
		value = trimToken(value)
		switch key {
		case "alg":
			mech.Alg = canonicalAuthAlg(value)
		case "ealg":
			mech.EAlg = canonicalEncAlg(value)
		case "prot":
			mech.Prot = value
		case "mod", "mode":
			mech.Mode = value
		case "spi-c", "spi_c", "spic":
			v, err := parseUint32Param(value)
			if err != nil {
				return SecurityMechanism{}, fmt.Errorf("ipsec3gpp: invalid spi-c: %w", err)
			}
			mech.SPIc = v
		case "spi-s", "spi_s", "spis":
			v, err := parseUint32Param(value)
			if err != nil {
				return SecurityMechanism{}, fmt.Errorf("ipsec3gpp: invalid spi-s: %w", err)
			}
			mech.SPIs = v
		case "port-c", "port_c", "portc":
			v, err := strconv.Atoi(value)
			if err != nil {
				return SecurityMechanism{}, fmt.Errorf("ipsec3gpp: invalid port-c: %w", err)
			}
			mech.PortC = v
		case "port-s", "port_s", "ports":
			v, err := strconv.Atoi(value)
			if err != nil {
				return SecurityMechanism{}, fmt.Errorf("ipsec3gpp: invalid port-s: %w", err)
			}
			mech.PortS = v
		case "q":
			// preference weight; ignored for parsing
		default:
		}
	}
	return mech, nil
}

func splitMechanisms(header string) []string {
	var out []string
	var b strings.Builder
	depth := 0
	for _, r := range header {
		switch r {
		case '"':
			depth ^= 1
			b.WriteRune(r)
		case ',':
			if depth == 0 {
				if part := strings.TrimSpace(b.String()); part != "" {
					out = append(out, part)
				}
				b.Reset()
				continue
			}
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	if part := strings.TrimSpace(b.String()); part != "" {
		out = append(out, part)
	}
	return out
}

func parseUint32Param(value string) (uint32, error) {
	value = trimToken(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		v, err := strconv.ParseUint(value[2:], 16, 32)
		return uint32(v), err
	}
	v, err := strconv.ParseUint(value, 10, 32)
	return uint32(v), err
}

func normalizeMechanismToken(token string) string {
	token = trimToken(token)
	token = strings.ReplaceAll(token, "-", "")
	token = strings.ReplaceAll(token, "_", "")
	return strings.ToLower(token)
}

func trimToken(s string) string {
	return strings.Trim(strings.TrimSpace(s), "\"")
}

func canonicalAuthAlg(alg string) string {
	switch strings.ToLower(trimToken(alg)) {
	case "hmac-md5-96", "hmac_md5_96":
		return "hmac-md5-96"
	case "hmac-sha-1-96", "hmac_sha_1_96", "hmac-sha1-96":
		return "hmac-sha-1-96"
	default:
		return strings.ToLower(trimToken(alg))
	}
}

func canonicalEncAlg(ealg string) string {
	switch strings.ToLower(trimToken(ealg)) {
	case "des-ede3-cbc", "3des", "des_ede3_cbc":
		return "des-ede3-cbc"
	case "aes-cbc", "aes_cbc":
		return "aes-cbc"
	case "null":
		return "null"
	default:
		return strings.ToLower(trimToken(ealg))
	}
}