package imscore

import (
	"net"
	"strings"
	"testing"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

// Realm feeds the RFC 3310 Digest AKA Authorization header. RFC 3310 section 4
// shows realm as a populated directive of the credentials, so an empty realm
// would put a syntactically present but semantically void parameter on the
// wire. IMPI and IMPU are already rejected when empty; realm must be too.

func setupRealmTestIMSConfig(realm string) IMSConfig {
	return IMSConfig{
		Registrar:       "192.0.2.10:5060",
		PCSCF:           "192.0.2.10:5060",
		Domain:          "ims.mnc001.mcc001.3gppnetwork.org",
		Realm:           realm,
		IMPI:            "subscriber@ims.mnc001.mcc001.3gppnetwork.org",
		IMPU:            "sip:subscriber@ims.mnc001.mcc001.3gppnetwork.org",
		CarrierBehavior: policy.Default3GPPBehavior(),
	}
}

func setupRealmTestInput() StartSessionInput {
	return StartSessionInput{
		LocalIP: net.ParseIP("192.0.2.2"),
		AKA:     fixedAKA{res: []byte{1}, ck: []byte{2}, ik: []byte{3}},
	}
}

func TestSetupServiceRequiresIMSRealm(t *testing.T) {
	for _, realm := range []string{"", "   ", "\t"} {
		svc, err := SetupService(setupRealmTestIMSConfig(realm), nil, setupRealmTestInput())
		if err == nil {
			t.Fatal("SetupService accepted an empty IMS realm")
		}
		if svc != nil {
			t.Fatal("SetupService returned a service despite an empty IMS realm")
		}
		if !strings.Contains(err.Error(), "realm") {
			t.Fatalf("error does not identify the realm requirement: %v", err)
		}
	}
}

func TestSetupServiceAcceptsPopulatedIMSRealm(t *testing.T) {
	_, err := SetupService(setupRealmTestIMSConfig("ims.mnc001.mcc001.3gppnetwork.org"), nil, setupRealmTestInput())
	if err != nil && strings.Contains(err.Error(), "realm") {
		t.Fatalf("populated realm was rejected: %v", err)
	}
}

func TestDialRequiresIMSRealm(t *testing.T) {
	cfg := Config{
		AKA:             fixedAKA{res: []byte{1}, ck: []byte{2}, ik: []byte{3}},
		LocalIP:         net.ParseIP("192.0.2.2"),
		PCSCFAddr:       "192.0.2.10:5060",
		PrivateID:       "subscriber@ims.mnc001.mcc001.3gppnetwork.org",
		PublicURI:       "sip:subscriber@ims.mnc001.mcc001.3gppnetwork.org",
		HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
		Realm:           "",
		CarrierBehavior: policy.Default3GPPBehavior(),
	}
	svc, err := Dial(nil, cfg)
	if err == nil {
		t.Fatal("Dial accepted an empty IMS realm")
	}
	if svc != nil {
		t.Fatal("Dial returned a service despite an empty IMS realm")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "realm") {
		t.Fatalf("error does not identify the realm requirement: %v", err)
	}
}

// buildInitialAuthorization is the wire-format invariant: no reachable mode may
// emit an empty realm directive.
func TestBuildInitialAuthorizationNeverEmitsEmptyRealm(t *testing.T) {
	cfg := Config{
		HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
		Realm:           "ims.mnc001.mcc001.3gppnetwork.org",
		PrivateID:       "subscriber@ims.mnc001.mcc001.3gppnetwork.org",
		CarrierBehavior: policy.Default3GPPBehavior(),
	}
	for _, mode := range []string{"", "aka_empty", "aka_zero_response_uri_first", "aka_empty_uri_first"} {
		got := buildInitialAuthorization(cfg, mode)
		if got == "" {
			continue
		}
		if strings.Contains(got, `realm=""`) {
			t.Fatalf("mode %q emitted an empty realm directive", mode)
		}
		if !strings.Contains(got, `realm="ims.mnc001.mcc001.3gppnetwork.org"`) {
			t.Fatalf("mode %q did not carry the configured realm", mode)
		}
	}
}
