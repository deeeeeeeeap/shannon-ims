package imscore

import (
	"github.com/emiago/sipgo/sip"
)

// Bounds for the Warning classifier. Both are hard limits: the parser never
// scans or counts past them and reports "truncated" instead of guessing.
const (
	// registerWarningMaxValues bounds how many warning-values are counted.
	registerWarningMaxValues = 8
	// registerWarningMaxScanBytes bounds how many bytes of a single Warning
	// header value are inspected.
	registerWarningMaxScanBytes = 512
	// registerWarningMaxHeaders bounds how many Warning headers are inspected.
	registerWarningMaxHeaders = 8
)

// Closed enum for registerWarningMetadata.parseResult.
const (
	registerWarningParseAbsent      = "absent"
	registerWarningParseKnown       = "known"
	registerWarningParseNonstandard = "nonstandard"
	registerWarningParseMalformed   = "malformed"
	registerWarningParseAmbiguous   = "ambiguous"
	registerWarningParseTruncated   = "truncated"
)

// Closed enum for registerWarningMetadata.class.
const (
	registerWarningClassNetworkIncompatibility = "network_incompatibility"
	registerWarningClassBandwidth              = "bandwidth"
	registerWarningClassSessionDescription     = "session_description"
	registerWarningClassAvailability           = "availability"
	registerWarningClassMiscellaneous          = "miscellaneous"
	registerWarningClassUnknown                = "unknown"
)

// registerWarningMetadata is de-identified, finite metadata about the Warning
// headers of a SIP response.
//
// It deliberately carries no warn-agent, no warn-text, no header value, and no
// raw input. Every field is a bool, a bounded counter, or a closed enum, so the
// whole struct is safe for the strict diagnostics whitelist.
type registerWarningMetadata struct {
	present     bool
	count       int
	code        int
	class       string
	parseResult string
}

func absentRegisterWarningMetadata() registerWarningMetadata {
	return registerWarningMetadata{
		class:       registerWarningClassUnknown,
		parseResult: registerWarningParseAbsent,
	}
}

// classifyRegisterWarning extracts bounded Warning metadata from a response.
//
// It is pure: it does not mutate the response, log, or retain anything. A code
// is reported only when every counted warning-value is syntactically valid and
// they all agree on the same standard RFC 3261 warn-code. Anything else yields
// code 0 with a parse-result explaining why, so a caller can never act on a
// guessed code.
func classifyRegisterWarning(res *sip.Response) registerWarningMetadata {
	if res == nil {
		return absentRegisterWarningMetadata()
	}
	headers := res.GetHeaders("Warning")
	if len(headers) == 0 {
		return absentRegisterWarningMetadata()
	}

	out := registerWarningMetadata{
		present:     true,
		class:       registerWarningClassUnknown,
		parseResult: registerWarningParseKnown,
	}

	// clipped records that raw bytes were dropped by the scan bound. Once that
	// happens no syntax verdict on the affected header is trustworthy, so the
	// result must be attributed to truncation rather than to a malformed value.
	clipped := false
	// countBounded records that whole warning-values were left uninspected.
	countBounded := len(headers) > registerWarningMaxHeaders
	malformed := false
	nonstandard := false
	firstCode := 0
	ambiguous := false

	for headerIndex, header := range headers {
		if headerIndex >= registerWarningMaxHeaders {
			countBounded = true
			break
		}
		if header == nil {
			malformed = true
			continue
		}
		values, valuesTruncated, scanTruncated := splitRegisterWarningValues(header.Value())
		if scanTruncated {
			clipped = true
		}
		if valuesTruncated {
			countBounded = true
		}
		for _, value := range values {
			if out.count >= registerWarningMaxValues {
				countBounded = true
				break
			}
			out.count++
			code, ok := parseRegisterWarningCode(value)
			if !ok {
				malformed = true
				continue
			}
			if !isStandardRegisterWarningCode(code) {
				nonstandard = true
				continue
			}
			if firstCode == 0 {
				firstCode = code
				continue
			}
			if firstCode != code {
				ambiguous = true
			}
		}
		if out.count >= registerWarningMaxValues && headerIndex+1 < len(headers) {
			// Later headers are not inspected at all.
			countBounded = true
		}
	}

	if out.count == 0 {
		// Headers existed but yielded no inspectable warning-value.
		if clipped || countBounded {
			out.parseResult = registerWarningParseTruncated
			return out
		}
		out.parseResult = registerWarningParseMalformed
		return out
	}

	// Precedence is strictest first so a code is never emitted alongside any
	// unresolved condition. A clipped scan outranks every syntax verdict because
	// the bytes that would decide that verdict were discarded.
	switch {
	case clipped:
		out.parseResult = registerWarningParseTruncated
		return out
	case malformed:
		out.parseResult = registerWarningParseMalformed
		return out
	case ambiguous || (nonstandard && firstCode != 0):
		out.parseResult = registerWarningParseAmbiguous
		return out
	case nonstandard:
		out.parseResult = registerWarningParseNonstandard
		return out
	case countBounded:
		out.parseResult = registerWarningParseTruncated
		return out
	case firstCode == 0:
		out.parseResult = registerWarningParseMalformed
		return out
	}

	out.parseResult = registerWarningParseKnown
	out.code = firstCode
	out.class = registerWarningClass(firstCode)
	return out
}

// splitRegisterWarningValues splits a Warning header value on commas that are
// outside quoted warn-text. It returns bounded slices of the raw segments for
// syntax checking only; callers must not surface the segments.
func splitRegisterWarningValues(value string) (values []string, valuesTruncated bool, scanTruncated bool) {
	if len(value) > registerWarningMaxScanBytes {
		value = value[:registerWarningMaxScanBytes]
		scanTruncated = true
	}
	start := 0
	inQuotes := false
	escaped := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if inQuotes {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inQuotes = false
			}
			continue
		}
		switch c {
		case '"':
			inQuotes = true
		case ',':
			if len(values) >= registerWarningMaxValues+1 {
				return values, true, scanTruncated
			}
			values = append(values, value[start:i])
			start = i + 1
		}
	}
	if len(values) >= registerWarningMaxValues+1 {
		return values, true, scanTruncated
	}
	values = append(values, value[start:])
	if inQuotes || escaped {
		// An unterminated quote makes the tail unparseable; keep it as a
		// segment so the syntax check rejects it.
		scanTruncated = scanTruncated || false
	}
	return values, false, scanTruncated
}

// parseRegisterWarningCode validates one warning-value and returns its numeric
// warn-code. It requires the RFC 3261 shape: three digits, a warn-agent token,
// and a quoted warn-text, with nothing after the closing quote.
//
// The returned error condition is a bare bool on purpose: no diagnostic derived
// from the input is produced, so no fragment of the header can escape.
func parseRegisterWarningCode(value string) (int, bool) {
	i := 0
	n := len(value)
	skipSpace := func() {
		for i < n && (value[i] == ' ' || value[i] == '\t') {
			i++
		}
	}

	skipSpace()
	// warn-code: exactly three digits followed by whitespace.
	if n-i < 4 {
		return 0, false
	}
	code := 0
	for d := 0; d < 3; d++ {
		c := value[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		code = code*10 + int(c-'0')
		i++
	}
	if value[i] != ' ' && value[i] != '\t' {
		return 0, false
	}
	skipSpace()

	// warn-agent: a bare token, never quoted.
	agentStart := i
	for i < n && value[i] != ' ' && value[i] != '\t' {
		if value[i] == '"' {
			return 0, false
		}
		i++
	}
	if i == agentStart {
		return 0, false
	}
	skipSpace()

	// warn-text: a single quoted string that ends the value.
	if i >= n || value[i] != '"' {
		return 0, false
	}
	i++
	closed := false
	for i < n {
		c := value[i]
		if c == '\\' {
			i += 2
			continue
		}
		i++
		if c == '"' {
			closed = true
			break
		}
	}
	if !closed {
		return 0, false
	}
	skipSpace()
	if i != n {
		return 0, false
	}
	return code, true
}

func isStandardRegisterWarningCode(code int) bool {
	switch code {
	case 300, 301, 302, 303, 304, 305, 306, 307, 330, 331, 370, 399:
		return true
	default:
		return false
	}
}

func registerWarningClass(code int) string {
	switch code {
	case 300, 301, 302:
		return registerWarningClassNetworkIncompatibility
	case 303, 370:
		return registerWarningClassBandwidth
	case 304, 305, 306, 307:
		return registerWarningClassSessionDescription
	case 330, 331:
		return registerWarningClassAvailability
	case 399:
		return registerWarningClassMiscellaneous
	default:
		return registerWarningClassUnknown
	}
}

func canonicalRegisterWarningParseResult(value string) string {
	switch value {
	case registerWarningParseAbsent,
		registerWarningParseKnown,
		registerWarningParseNonstandard,
		registerWarningParseMalformed,
		registerWarningParseAmbiguous,
		registerWarningParseTruncated:
		return value
	default:
		return registerWarningParseAbsent
	}
}

func canonicalRegisterWarningClass(value string) string {
	switch value {
	case registerWarningClassNetworkIncompatibility,
		registerWarningClassBandwidth,
		registerWarningClassSessionDescription,
		registerWarningClassAvailability,
		registerWarningClassMiscellaneous:
		return value
	default:
		return registerWarningClassUnknown
	}
}

// canonicalRegisterWarningCode clamps a code to 0 or the standard allowlist so a
// non-standard or hostile value can never reach a diagnostic field.
func canonicalRegisterWarningCode(code int) int {
	if isStandardRegisterWarningCode(code) {
		return code
	}
	return 0
}

func boundRegisterWarningCount(count int) int {
	if count < 0 {
		return 0
	}
	if count > registerWarningMaxValues {
		return registerWarningMaxValues
	}
	return count
}
