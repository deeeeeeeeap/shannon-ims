package policy

import (
	"net"
	"strings"
	"testing"
)

func TestBuildIMSContactHeaderGiffgaffOrder(t *testing.T) {
	tmpl := DefaultGiffgaffTemplate()
	got := BuildIMSContactHeader(tmpl, ContactBuildInput{
		IMSI:               "001010000000001",
		PublicURI:          "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
		LocalIP:            net.ParseIP("2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646"),
		LocalPort:          5060,
		SIPInstanceURN:     "urn:gsma:imei:8612345-678901-2",
		RegisterExpirySecs: 3600,
	})
	for _, want := range []string{
		`+g.3gpp.accesstype="IEEE-802.11"`,
		`+sip.instance="<urn:gsma:imei:8612345-678901-2>"`,
		";audio",
		"+g.3gpp.smsip",
		`+g.3gpp.icsi-ref="`,
		"expires=3600",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("contact %q missing %q", got, want)
		}
	}
	for _, unwanted := range []string{
		"+g.3gpp.mid-call",
		"+g.3gpp.srvcc-alerting",
		"+g.3gpp.ps2cs-srvcc-orig-pre-alerting",
	} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("contact %q should not include %q", got, unwanted)
		}
	}
	access := strings.Index(got, `+g.3gpp.accesstype`)
	audio := strings.Index(got, ";audio")
	icsi := strings.Index(got, `+g.3gpp.icsi-ref`)
	instance := strings.Index(got, `+sip.instance`)
	if access < 0 || audio < 0 || icsi < 0 || instance < 0 || !(access < audio && audio < icsi && icsi < instance) {
		t.Fatalf("param order wrong: %q", got)
	}
}