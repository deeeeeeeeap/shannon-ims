package ipsec3gpp

import "testing"

func TestReplayWindowAccept(t *testing.T) {
	w := NewReplayWindow(64)
	if !w.Accept(10) {
		t.Fatal("expected first packet accepted")
	}
	if !w.Accept(11) {
		t.Fatal("expected next packet accepted")
	}
	if w.Accept(10) {
		t.Fatal("expected duplicate rejected")
	}
	if !w.Accept(9) {
		t.Fatal("expected in-window older packet accepted")
	}
	stats := w.Snapshot()
	if stats.Accepted != 3 || stats.Duplicate != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestReplayWindowRejectsZeroBeforeInitialization(t *testing.T) {
	w := NewReplayWindow(64)
	if w.Accept(0) {
		t.Fatal("ESP sequence zero must always be rejected")
	}
	if !w.Accept(1) {
		t.Fatal("valid first ESP sequence must remain acceptable after zero rejection")
	}

	stats := w.Snapshot()
	if stats.Accepted != 1 || stats.TooOld != 1 || stats.Duplicate != 0 {
		t.Fatalf("unexpected stats after zero rejection: %+v", stats)
	}
}
