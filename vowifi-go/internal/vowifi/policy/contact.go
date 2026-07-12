package policy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const IMSMmtelICSIRef = `urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel`

// ContactBuildInput carries runtime values for IMS REGISTER Contact headers.
type ContactBuildInput struct {
	IMSI               string
	PublicURI          string
	LocalIP            net.IP
	LocalPort          int
	Transport          string
	SIPInstanceURN     string
	RegisterExpirySecs int
}

// BuildIMSContactHeader renders Contact per carrier contact_param_order.
func BuildIMSContactHeader(tmpl IMSRegisterTemplate, input ContactBuildInput) string {
	user := strings.TrimSpace(input.IMSI)
	if idx := strings.Index(input.PublicURI, ":"); idx >= 0 {
		rest := input.PublicURI[idx+1:]
		if at := strings.Index(rest, "@"); at > 0 {
			user = rest[:at]
		}
	}
	port := input.LocalPort
	if port <= 0 {
		port = 5060
	}
	transport := strings.ToLower(strings.TrimSpace(input.Transport))
	if transport == "" {
		transport = "tcp"
	}
	local := fmt.Sprintf("sip:%s@%s;transport=%s",
		user,
		net.JoinHostPort(input.LocalIP.String(), strconv.Itoa(port)),
		transport,
	)

	order := tmpl.ContactParamOrder
	if len(order) == 0 {
		order = DefaultGiffgaffTemplate().ContactParamOrder
	}

	b := strings.Builder{}
	b.WriteString("<")
	b.WriteString(local)
	b.WriteString(">")
	for _, param := range order {
		appendContactParam(&b, param, input)
	}
	expires := input.RegisterExpirySecs
	if expires <= 0 {
		expires = 3600
	}
	b.WriteString(";expires=")
	b.WriteString(strconv.Itoa(expires))
	return b.String()
}

func appendContactParam(b *strings.Builder, name string, input ContactBuildInput) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "access_type":
		b.WriteString(`;+g.3gpp.accesstype="IEEE-802.11"`)
	case "sip_instance":
		if urn := strings.TrimSpace(input.SIPInstanceURN); urn != "" {
			b.WriteString(`;+sip.instance="<`)
			b.WriteString(urn)
			b.WriteString(`>"`)
		}
	case "reg_id":
		b.WriteString(";reg-id=1")
	case "audio":
		b.WriteString(";audio")
	case "smsip":
		b.WriteString(";+g.3gpp.smsip")
	case "icsi_ref":
		b.WriteString(`;+g.3gpp.icsi-ref="`)
		b.WriteString(IMSMmtelICSIRef)
		b.WriteString(`"`)
	case "mid_call":
		b.WriteString(";+g.3gpp.mid-call")
	case "srvcc_alerting":
		b.WriteString(";+g.3gpp.srvcc-alerting")
	case "ps2cs_srvcc_orig_pre_alerting":
		b.WriteString(";+g.3gpp.ps2cs-srvcc-orig-pre-alerting")
	}
}
