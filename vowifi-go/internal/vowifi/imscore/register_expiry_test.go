package imscore

import (
	"strconv"
	"testing"

	"github.com/emiago/sipgo/sip"
)

func TestRegisterExpiryUsesTheRegisteredBinding(t *testing.T) {
	const own = "<sip:fixture@192.0.2.10:5062;transport=tcp>"
	const other = "<sip:other@192.0.2.11:5062;transport=tcp>"
	maxExpiry := uint64(^uint(0) >> 1)
	if maxExpiry > 1<<32-1 {
		maxExpiry = 1<<32 - 1
	}
	for _, test := range []struct {
		name     string
		contacts []string
		global   string
		want     int
	}{
		{"contact_only", []string{own + ";expires=60"}, "", 60},
		{"contact_overrides_global", []string{own + ";expires=60"}, "3600", 60},
		{"other_binding_first", []string{other + ";expires=3600", own + ";expires=60"}, "", 60},
		{"combined_contacts", []string{other + ";expires=3600, " + own + ";expires=60"}, "", 60},
		{"global_fallback", []string{own}, "120", 120},
		{"expired_binding", []string{own + ";expires=0"}, "3600", 0},
		{"absent_binding", []string{other + ";expires=60"}, "3600", 0},
		{"missing_contact", nil, "3600", 0},
		{"missing_expiry", []string{own}, "", 0},
		{"malformed_expiry", []string{own + ";expires=invalid"}, "3600", 0},
		{"maximum_expiry", []string{own + ";expires=" + strconv.FormatUint(maxExpiry, 10)}, "", int(maxExpiry)},
		{"overflow_expiry", []string{own + ";expires=" + strconv.FormatUint(maxExpiry+1, 10)}, "", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := sip.NewRequest(sip.REGISTER, sip.Uri{Scheme: "sip", Host: "example.invalid"})
			request.AppendHeader(sip.NewHeader("Contact", own+";expires=3600"))
			response := sip.NewResponse(200, "OK")
			for _, value := range test.contacts {
				response.AppendHeader(sip.NewHeader("Contact", value))
			}
			if test.global != "" {
				response.AppendHeader(sip.NewHeader("Expires", test.global))
			}
			result, err := finalizeRegisterSuccess(Config{}, registerState{}, response, request)
			if test.want == 0 {
				if err == nil {
					t.Fatal("response without a live local binding was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.expiresSeconds != test.want {
				t.Fatalf("expiry=%d want=%d", result.expiresSeconds, test.want)
			}
		})
	}
}
