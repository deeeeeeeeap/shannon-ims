package updater

import (
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
)

type updateNetworkProbe struct {
	called atomic.Bool
}

func (p *updateNetworkProbe) RoundTrip(*http.Request) (*http.Response, error) {
	p.called.Store(true)
	return nil, errors.New("unexpected updater network access")
}

func TestApplyUpdateFailsClosedWithoutSignedReleaseMetadata(t *testing.T) {
	probe := &updateNetworkProbe{}
	originalTransport := http.DefaultTransport
	http.DefaultTransport = probe
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	err := ApplyUpdate()
	if !errors.Is(err, ErrAutomaticUpdateDisabled) {
		t.Fatalf("ApplyUpdate() error = %v, want ErrAutomaticUpdateDisabled", err)
	}
	if probe.called.Load() {
		t.Fatal("ApplyUpdate() accessed the network while automatic updates are disabled")
	}
}

func TestCheckUpdateReportsDisabledWithoutNetwork(t *testing.T) {
	probe := &updateNetworkProbe{}
	originalTransport := http.DefaultTransport
	http.DefaultTransport = probe
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	info, err := CheckUpdate()
	if err != nil {
		t.Fatalf("CheckUpdate() error = %v, want disabled status", err)
	}
	if info.Enabled {
		t.Fatal("CheckUpdate() enabled automatic updates without signed metadata")
	}
	if info.HasUpdate {
		t.Fatal("CheckUpdate() reported an update while automatic updates are disabled")
	}
	if info.Reason == "" {
		t.Fatal("CheckUpdate() disabled status is missing a reason")
	}
	if probe.called.Load() {
		t.Fatal("CheckUpdate() accessed the network while automatic updates are disabled")
	}
}
