package imscore

import (
	"fmt"
	"strings"

	"github.com/emiago/sipgo/sip"
)

var vodafoneInitialRegisterRawHeaderOrder = []string{
	"Via",
	"Max-Forwards",
	"From",
	"To",
	"Call-ID",
	"CSeq",
	"Contact",
	"Expires",
	"Supported",
	"Authorization",
	"Security-Client",
	"Require",
	"Proxy-Require",
	"User-Agent",
	"Content-Length",
}

var vodafoneProtectedRegisterRawHeaderOrder = []string{
	"Via",
	"Max-Forwards",
	"From",
	"To",
	"Call-ID",
	"CSeq",
	"Contact",
	"Expires",
	"Supported",
	"Authorization",
	"Security-Client",
	"Security-Verify",
	"Require",
	"Proxy-Require",
	"User-Agent",
	"Content-Length",
}

func buildVodafoneInitialRegisterPayload(req *sip.Request) ([]byte, error) {
	return buildVodafoneRegisterPayload(req, vodafoneInitialRegisterRawHeaderOrder, "initial")
}

func buildVodafoneProtectedRegisterPayload(req *sip.Request) ([]byte, error) {
	return buildVodafoneRegisterPayload(req, vodafoneProtectedRegisterRawHeaderOrder, "protected")
}

func buildVodafoneRegisterPayload(req *sip.Request, headerOrder []string, profile string) ([]byte, error) {
	if req == nil || req.Method != sip.REGISTER {
		return nil, fmt.Errorf("imscore: Vodafone %s REGISTER request unavailable", profile)
	}
	if len(req.Body()) != 0 {
		return nil, fmt.Errorf("imscore: Vodafone %s REGISTER body must be empty", profile)
	}
	requestURI := strings.TrimSpace(req.Recipient.String())
	if requestURI == "" || strings.ContainsAny(requestURI, "\r\n") {
		return nil, fmt.Errorf("imscore: invalid Vodafone %s REGISTER URI", profile)
	}

	allowed := make(map[string]struct{}, len(headerOrder))
	for _, name := range headerOrder {
		allowed[strings.ToLower(name)] = struct{}{}
	}
	for _, header := range req.Headers() {
		if header == nil {
			continue
		}
		if _, ok := allowed[strings.ToLower(strings.TrimSpace(header.Name()))]; !ok {
			return nil, fmt.Errorf("imscore: unsupported Vodafone %s REGISTER header %q", profile, header.Name())
		}
	}

	var payload strings.Builder
	payload.Grow(len(req.String()))
	payload.WriteString("REGISTER ")
	payload.WriteString(requestURI)
	payload.WriteString(" SIP/2.0\r\n")
	for _, name := range headerOrder {
		for _, header := range req.GetHeaders(name) {
			value := strings.TrimSpace(header.Value())
			if strings.ContainsAny(value, "\r\n") {
				return nil, fmt.Errorf("imscore: invalid Vodafone %s REGISTER %s value", profile, name)
			}
			payload.WriteString(name)
			payload.WriteString(": ")
			payload.WriteString(value)
			payload.WriteString("\r\n")
		}
	}
	payload.WriteString("\r\n")
	return []byte(payload.String()), nil
}
