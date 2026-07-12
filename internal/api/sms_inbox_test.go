package api

import "testing"

func TestSMSInboxIMSIDefaultsToCachedValueWithoutLiveRead(t *testing.T) {
	source := &smsIMSIProbe{cached: " 001010000000001 "}

	got := smsInboxIMSI(source, false)

	if got != "001010000000001" {
		t.Fatalf("smsInboxIMSI() = %q, want cached IMSI", got)
	}
	if source.liveCalls != 0 {
		t.Fatalf("GetIMSI live calls = %d, want 0", source.liveCalls)
	}
}

func TestSMSInboxIMSIAllowsLiveFallbackOnlyOnExplicitRefresh(t *testing.T) {
	source := &smsIMSIProbe{live: " 001010000000002 "}

	if got := smsInboxIMSI(source, false); got != "" {
		t.Fatalf("smsInboxIMSI(no refresh) = %q, want empty cached value", got)
	}
	if source.liveCalls != 0 {
		t.Fatalf("GetIMSI live calls without refresh = %d, want 0", source.liveCalls)
	}

	if got := smsInboxIMSI(source, true); got != "001010000000002" {
		t.Fatalf("smsInboxIMSI(refresh) = %q, want live fallback", got)
	}
	if source.liveCalls != 1 {
		t.Fatalf("GetIMSI live calls with refresh = %d, want 1", source.liveCalls)
	}
}

type smsIMSIProbe struct {
	cached    string
	live      string
	liveCalls int
}

func (p *smsIMSIProbe) GetCachedIMSI() string {
	return p.cached
}

func (p *smsIMSIProbe) GetIMSI() string {
	p.liveCalls++
	return p.live
}
