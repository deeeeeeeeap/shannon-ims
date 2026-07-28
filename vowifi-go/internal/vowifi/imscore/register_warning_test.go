package imscore

import (
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
)

// synthetic warn-agent used by every case below. It is never returned, logged,
// or printed by the parser under test.
const syntheticWarnAgent = "synthetic.invalid:5060"

func syntheticWarningValue(code string) string {
	return code + " " + syntheticWarnAgent + ` "synthetic warn text"`
}

func newSyntheticWarningResponse(values ...string) *sip.Response {
	res := sip.NewResponse(sip.StatusForbidden, "Forbidden")
	for _, value := range values {
		res.AppendHeader(sip.NewHeader("Warning", value))
	}
	return res
}

var registerWarningParseResults = map[string]struct{}{
	"absent":      {},
	"known":       {},
	"nonstandard": {},
	"malformed":   {},
	"ambiguous":   {},
	"truncated":   {},
}

var registerWarningClasses = map[string]struct{}{
	"network_incompatibility": {},
	"bandwidth":               {},
	"session_description":     {},
	"availability":            {},
	"miscellaneous":           {},
	"unknown":                 {},
}

var registerWarningAllowedCodes = map[int]struct{}{
	0:   {},
	300: {}, 301: {}, 302: {}, 303: {},
	304: {}, 305: {}, 306: {}, 307: {},
	330: {}, 331: {}, 370: {}, 399: {},
}

// assertRegisterWarningMetadataIsBounded proves the result carries only finite,
// enumerated metadata. It never prints any part of the input header.
func assertRegisterWarningMetadataIsBounded(t *testing.T, got registerWarningMetadata) {
	t.Helper()
	if _, ok := registerWarningParseResults[got.parseResult]; !ok {
		t.Fatalf("parse_result is outside the closed enum")
	}
	if _, ok := registerWarningClasses[got.class]; !ok {
		t.Fatalf("class is outside the closed enum")
	}
	if _, ok := registerWarningAllowedCodes[got.code]; !ok {
		t.Fatalf("code %d is outside the standard allowlist", got.code)
	}
	if got.count < 0 || got.count > registerWarningMaxValues {
		t.Fatalf("count %d is outside the bound", got.count)
	}
	if got.code != 0 && got.parseResult != "known" {
		t.Fatalf("code was emitted for parse_result that is not known")
	}
	if got.class != "unknown" && got.code == 0 {
		t.Fatalf("class was emitted without an allowlisted code")
	}
	if !got.present && (got.count != 0 || got.code != 0) {
		t.Fatalf("absent Warning reported code or count")
	}
}

func TestClassifyRegisterWarningAcceptsEveryStandardCode(t *testing.T) {
	cases := []struct {
		code      int
		wantClass string
	}{
		{300, "network_incompatibility"},
		{301, "network_incompatibility"},
		{302, "network_incompatibility"},
		{303, "bandwidth"},
		{304, "session_description"},
		{305, "session_description"},
		{306, "session_description"},
		{307, "session_description"},
		{330, "availability"},
		{331, "availability"},
		{370, "bandwidth"},
		{399, "miscellaneous"},
	}
	for _, tc := range cases {
		res := newSyntheticWarningResponse(syntheticWarningValue(itoaWarningTestCode(tc.code)))
		got := classifyRegisterWarning(res)
		assertRegisterWarningMetadataIsBounded(t, got)
		if !got.present {
			t.Fatalf("standard code %d: warning_present = false", tc.code)
		}
		if got.count != 1 {
			t.Fatalf("standard code %d: warning_count = %d, want 1", tc.code, got.count)
		}
		if got.parseResult != "known" {
			t.Fatalf("standard code %d: parse_result = %q, want known", tc.code, got.parseResult)
		}
		if got.code != tc.code {
			t.Fatalf("standard code %d: warning_code = %d", tc.code, got.code)
		}
		if got.class != tc.wantClass {
			t.Fatalf("standard code %d: class = %q, want %q", tc.code, got.class, tc.wantClass)
		}
	}
}

func TestClassifyRegisterWarningReportsAbsentWithoutHeader(t *testing.T) {
	got := classifyRegisterWarning(sip.NewResponse(sip.StatusForbidden, "Forbidden"))
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.present {
		t.Fatal("missing Warning header reported present")
	}
	if got.parseResult != "absent" {
		t.Fatalf("parse_result = %q, want absent", got.parseResult)
	}
	if got.count != 0 || got.code != 0 || got.class != "unknown" {
		t.Fatal("absent Warning produced non-default metadata")
	}
}

func TestClassifyRegisterWarningReportsAbsentForNilResponse(t *testing.T) {
	got := classifyRegisterWarning(nil)
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.present || got.parseResult != "absent" {
		t.Fatal("nil response did not classify as absent")
	}
}

func TestClassifyRegisterWarningRejectsNonStandardCode(t *testing.T) {
	for _, code := range []string{"100", "199", "298", "308", "329", "398", "400", "499", "999"} {
		res := newSyntheticWarningResponse(syntheticWarningValue(code))
		got := classifyRegisterWarning(res)
		assertRegisterWarningMetadataIsBounded(t, got)
		if !got.present {
			t.Fatal("nonstandard code reported absent")
		}
		if got.parseResult != "nonstandard" {
			t.Fatalf("parse_result = %q, want nonstandard", got.parseResult)
		}
		if got.code != 0 {
			t.Fatalf("nonstandard code leaked a guessed warning_code = %d", got.code)
		}
		if got.class != "unknown" {
			t.Fatalf("class = %q, want unknown", got.class)
		}
	}
}

func TestClassifyRegisterWarningRejectsMalformedValues(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{name: "empty header", value: ""},
		{name: "whitespace only", value: "   "},
		{name: "code only", value: "399"},
		{name: "code and agent without text", value: "399 " + syntheticWarnAgent},
		{name: "two digit code", value: "39 " + syntheticWarnAgent + ` "synthetic"`},
		{name: "four digit code", value: "3990 " + syntheticWarnAgent + ` "synthetic"`},
		{name: "alphabetic code", value: "abc " + syntheticWarnAgent + ` "synthetic"`},
		{name: "signed code", value: "+99 " + syntheticWarnAgent + ` "synthetic"`},
		{name: "unquoted text", value: "399 " + syntheticWarnAgent + " synthetic"},
		{name: "unterminated quote", value: "399 " + syntheticWarnAgent + ` "synthetic`},
		{name: "trailing junk after text", value: "399 " + syntheticWarnAgent + ` "synthetic" junk`},
		{name: "quoted agent", value: `399 "` + syntheticWarnAgent + `" "synthetic"`},
		{name: "empty trailing value", value: `399 ` + syntheticWarnAgent + ` "synthetic",`},
		{name: "empty leading value", value: `,399 ` + syntheticWarnAgent + ` "synthetic"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyRegisterWarning(newSyntheticWarningResponse(tc.value))
			assertRegisterWarningMetadataIsBounded(t, got)
			if !got.present {
				t.Fatal("malformed Warning header reported absent")
			}
			if got.parseResult != "malformed" {
				t.Fatalf("parse_result = %q, want malformed", got.parseResult)
			}
			if got.code != 0 || got.class != "unknown" {
				t.Fatal("malformed Warning leaked a guessed code or class")
			}
		})
	}
}

func TestClassifyRegisterWarningCountsMultipleHeadersWithSameCode(t *testing.T) {
	res := newSyntheticWarningResponse(
		syntheticWarningValue("399"),
		syntheticWarningValue("399"),
		syntheticWarningValue("399"),
	)
	got := classifyRegisterWarning(res)
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.count != 3 {
		t.Fatalf("warning_count = %d, want 3", got.count)
	}
	if got.parseResult != "known" || got.code != 399 || got.class != "miscellaneous" {
		t.Fatal("repeated identical standard code was not classified as known")
	}
}

func TestClassifyRegisterWarningCountsMultipleValuesInOneHeader(t *testing.T) {
	value := syntheticWarningValue("370") + ", " + syntheticWarningValue("370")
	got := classifyRegisterWarning(newSyntheticWarningResponse(value))
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.count != 2 {
		t.Fatalf("warning_count = %d, want 2", got.count)
	}
	if got.parseResult != "known" || got.code != 370 || got.class != "bandwidth" {
		t.Fatal("comma separated identical codes were not classified as known")
	}
}

func TestClassifyRegisterWarningIgnoresCommasInsideQuotedText(t *testing.T) {
	value := `399 ` + syntheticWarnAgent + ` "synthetic, text, with, commas"`
	got := classifyRegisterWarning(newSyntheticWarningResponse(value))
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.count != 1 {
		t.Fatalf("warning_count = %d, want 1; quoted commas must not split values", got.count)
	}
	if got.parseResult != "known" || got.code != 399 {
		t.Fatal("quoted commas broke a single valid warning-value")
	}
}

func TestClassifyRegisterWarningIgnoresEscapedQuoteInsideQuotedText(t *testing.T) {
	value := `330 ` + syntheticWarnAgent + ` "synthetic \" quoted, text"`
	got := classifyRegisterWarning(newSyntheticWarningResponse(value))
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.count != 1 {
		t.Fatalf("warning_count = %d, want 1", got.count)
	}
	if got.parseResult != "known" || got.code != 330 || got.class != "availability" {
		t.Fatal("escaped quote broke a single valid warning-value")
	}
}

func TestClassifyRegisterWarningReportsAmbiguousForDistinctCodes(t *testing.T) {
	cases := [][]string{
		{syntheticWarningValue("300"), syntheticWarningValue("399")},
		{syntheticWarningValue("304") + ", " + syntheticWarningValue("305")},
		{syntheticWarningValue("399"), syntheticWarningValue("100")},
	}
	for _, values := range cases {
		got := classifyRegisterWarning(newSyntheticWarningResponse(values...))
		assertRegisterWarningMetadataIsBounded(t, got)
		if got.parseResult != "ambiguous" {
			t.Fatalf("parse_result = %q, want ambiguous", got.parseResult)
		}
		if got.code != 0 || got.class != "unknown" {
			t.Fatal("ambiguous Warning set leaked a guessed code")
		}
	}
}

func TestClassifyRegisterWarningTruncatesBeyondValueBound(t *testing.T) {
	values := make([]string, 0, registerWarningMaxValues+3)
	for i := 0; i < registerWarningMaxValues+3; i++ {
		values = append(values, syntheticWarningValue("399"))
	}
	got := classifyRegisterWarning(newSyntheticWarningResponse(values...))
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.parseResult != "truncated" {
		t.Fatalf("parse_result = %q, want truncated", got.parseResult)
	}
	if got.count != registerWarningMaxValues {
		t.Fatalf("warning_count = %d, want %d", got.count, registerWarningMaxValues)
	}
	if got.code != 0 || got.class != "unknown" {
		t.Fatal("truncated Warning set emitted a code")
	}
}

func TestClassifyRegisterWarningTruncatesBeyondValueBoundInSingleHeader(t *testing.T) {
	parts := make([]string, 0, registerWarningMaxValues+2)
	for i := 0; i < registerWarningMaxValues+2; i++ {
		parts = append(parts, syntheticWarningValue("399"))
	}
	got := classifyRegisterWarning(newSyntheticWarningResponse(strings.Join(parts, ", ")))
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.parseResult != "truncated" {
		t.Fatalf("parse_result = %q, want truncated", got.parseResult)
	}
	if got.count != registerWarningMaxValues {
		t.Fatalf("warning_count = %d, want %d", got.count, registerWarningMaxValues)
	}
}

func TestClassifyRegisterWarningTruncatesOversizedInput(t *testing.T) {
	oversized := "399 " + syntheticWarnAgent + ` "` + strings.Repeat("s", registerWarningMaxScanBytes+64) + `"`
	got := classifyRegisterWarning(newSyntheticWarningResponse(oversized))
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.parseResult != "truncated" {
		t.Fatalf("parse_result = %q, want truncated", got.parseResult)
	}
	if got.code != 0 {
		t.Fatal("oversized Warning input emitted a code")
	}
}

func TestClassifyRegisterWarningTruncatesHostileRepeatedCommas(t *testing.T) {
	hostile := strings.Repeat(",", registerWarningMaxScanBytes+16)
	got := classifyRegisterWarning(newSyntheticWarningResponse(hostile))
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.parseResult != "truncated" && got.parseResult != "malformed" {
		t.Fatalf("parse_result = %q, want truncated or malformed", got.parseResult)
	}
	if got.code != 0 {
		t.Fatal("hostile Warning input emitted a code")
	}
}

func TestClassifyRegisterWarningTruncatesExcessiveHeaderCount(t *testing.T) {
	values := make([]string, 0, registerWarningMaxValues*2)
	for i := 0; i < registerWarningMaxValues*2; i++ {
		values = append(values, syntheticWarningValue("300"))
	}
	got := classifyRegisterWarning(newSyntheticWarningResponse(values...))
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.parseResult != "truncated" {
		t.Fatalf("parse_result = %q, want truncated", got.parseResult)
	}
	if got.code != 0 {
		t.Fatal("excessive Warning header count emitted a code")
	}
}

func TestClassifyRegisterWarningMalformedTakesPrecedenceOverStandardCode(t *testing.T) {
	value := syntheticWarningValue("399") + ", 39 " + syntheticWarnAgent + ` "synthetic"`
	got := classifyRegisterWarning(newSyntheticWarningResponse(value))
	assertRegisterWarningMetadataIsBounded(t, got)
	if got.parseResult != "malformed" {
		t.Fatalf("parse_result = %q, want malformed", got.parseResult)
	}
	if got.code != 0 {
		t.Fatal("a malformed sibling value still emitted a code")
	}
}

func TestClassifyRegisterWarningIsPureAndRepeatable(t *testing.T) {
	res := newSyntheticWarningResponse(syntheticWarningValue("399"))
	first := classifyRegisterWarning(res)
	second := classifyRegisterWarning(res)
	if first != second {
		t.Fatal("classifyRegisterWarning is not repeatable for the same response")
	}
	if len(res.GetHeaders("Warning")) != 1 {
		t.Fatal("classifyRegisterWarning mutated the response headers")
	}
}

func itoaWarningTestCode(code int) string {
	digits := [3]byte{
		byte('0' + (code/100)%10),
		byte('0' + (code/10)%10),
		byte('0' + code%10),
	}
	return string(digits[:])
}
