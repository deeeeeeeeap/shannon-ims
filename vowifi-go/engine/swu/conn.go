package swu

// vici connection shape for one device's SWu tunnel. Field derivation is
// documented in spike/vicispike/MAPPING.md; this is the production version
// of that spike's config.go, plus CACerts (found missing there).

type localAuth struct {
	Auth  string `vici:"auth"`
	EAPID string `vici:"eap_id"`
	ID    string `vici:"id"`
}

type remoteAuth struct {
	Auth    string   `vici:"auth"`
	ID      string   `vici:"id"`
	CACerts []string `vici:"cacerts"`
}

type childSA struct {
	ESPProposals []string `vici:"esp_proposals"`
	LocalTS      []string `vici:"local_ts"`
	RemoteTS     []string `vici:"remote_ts"`
	Mode         string   `vici:"mode"`
	StartAction  string   `vici:"start_action"`
}

type viciConn struct {
	Version     string             `vici:"version"`
	RemoteAddrs []string           `vici:"remote_addrs"`
	Proposals   []string           `vici:"proposals"`
	Vips        []string           `vici:"vips"`
	Encap       string             `vici:"encap"`
	Mobike      string             `vici:"mobike"`
	DPDDelay    string             `vici:"dpd_delay"`
	SendCertreq string             `vici:"send_certreq"`
	Local1      localAuth          `vici:"local-1"`
	Remote1     remoteAuth         `vici:"remote-1"`
	Children    map[string]childSA `vici:"children"`
}

// childName is fixed, not derived from Config: every SWu connection has
// exactly one child carrying all IMS traffic.
const childName = "ims"

func buildViciConn(cfg Config) *viciConn {
	mobike := "no"
	if cfg.EnableMOBIKE {
		mobike = "yes"
	}
	return &viciConn{
		Version:     "2",
		RemoteAddrs: []string{cfg.EPDGAddr},
		Proposals:   []string{"default"},
		Vips:        []string{"0.0.0.0"},
		Encap:       "yes", // force NAT-T/UDP-4500; most UEs are behind NAT anyway
		Mobike:      mobike,
		DPDDelay:    "30s",
		// A CERTREQ is sent per configured cacert (charon's default
		// send_certreq behavior) -- purely a hint to the responder about
		// which chain to send, not needed for validation (that's done
		// against CACerts regardless of what the responder chooses to
		// send). With CACerts defaulting to the whole system trust store
		// (see runtimehost.systemCACertPaths), that's 100+ CERTREQ
		// payloads, ballooning IKE_AUTH's first packet enough to not
		// survive some real network paths intact -- found by actually
		// running this against a real ePDG (through a relay), where
		// IKE_SA_INIT (small) got a real response but IKE_AUTH with the
		// full CERTREQ list never did, retrying indefinitely.
		SendCertreq: "no",
		Local1: localAuth{
			Auth:  "eap-aka",
			EAPID: cfg.Identity,
			ID:    cfg.Identity,
		},
		Remote1: remoteAuth{
			Auth:    "pubkey",
			ID:      "%any",
			CACerts: cfg.CACerts,
		},
		Children: map[string]childSA{
			childName: {
				ESPProposals: []string{"default"},
				LocalTS:      []string{"dynamic"}, // the negotiated vip
				RemoteTS:     []string{"0.0.0.0/0", "::/0"},
				Mode:         "tunnel",
				StartAction:  "none", // Manager drives initiate/terminate explicitly
			},
		},
	}
}

// connNameFor is the vici connection name and the akabridge-facing prefix
// disambiguator; must be unique per device since one charon serves all of
// them concurrently.
func connNameFor(deviceID string) string {
	return "vohive-swu-" + deviceID
}
