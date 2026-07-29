package smscodec

import "testing"

func TestBuildSubmitTPDUsRequestsStatusReportOnlyWhenEnabled(t *testing.T) {
	defaultTPDUs, _, err := BuildSubmitTPDUsWithOptions("55501", "synthetic", SubmitOptions{})
	if err != nil {
		t.Fatalf("BuildSubmitTPDUsWithOptions(default): %v", err)
	}
	requestedTPDUs, _, err := BuildSubmitTPDUsWithOptions("55501", "synthetic", SubmitOptions{RequestStatusReport: true})
	if err != nil {
		t.Fatalf("BuildSubmitTPDUsWithOptions(status report): %v", err)
	}
	if len(defaultTPDUs) != 1 || len(requestedTPDUs) != 1 {
		t.Fatalf("unexpected TPDU counts: default=%d requested=%d", len(defaultTPDUs), len(requestedTPDUs))
	}
	if defaultTPDUs[0][0]&0x20 != 0 {
		t.Fatal("default SMS-SUBMIT unexpectedly requests a status report")
	}
	if requestedTPDUs[0][0]&0x20 == 0 {
		t.Fatal("status-report-enabled SMS-SUBMIT has TP-SRR=0")
	}
}
