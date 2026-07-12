package simauth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/icholy/digest"

	"github.com/1239t/vowifi-go/engine/sim"
)

var (
	testRAND     = bytesOf(0xAA, randAUTNLen)
	testAUTN     = bytesOf(0xBB, randAUTNLen)
	testRES      = []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	unsyncedRAND = bytesOf(0xCC, randAUTNLen)
	unsyncedAUTN = bytesOf(0xDD, randAUTNLen)
	testAUTS     = bytesOf(0xEE, 14)
)

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// fakeProvider simulates a SIM that recognizes exactly two challenges: one
// that succeeds, one that's out of sync.
type fakeProvider struct{}

func (fakeProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	switch {
	case string(rand16) == string(testRAND) && string(autn16) == string(testAUTN):
		return sim.AKAResult{RES: testRES, CK: bytesOf(0x21, 16), IK: bytesOf(0x22, 16)}, nil
	case string(rand16) == string(unsyncedRAND) && string(autn16) == string(unsyncedAUTN):
		return sim.AKAResult{AUTS: testAUTS}, sim.ErrSyncFailure
	default:
		return sim.AKAResult{}, errors.New("fakeProvider: unrecognized RAND/AUTN")
	}
}

func nonceFor(randBytes, autnBytes []byte) string {
	return base64.StdEncoding.EncodeToString(append(append([]byte{}, randBytes...), autnBytes...))
}

func TestComputeDigestSuccess(t *testing.T) {
	chal := &digest.Challenge{
		Realm:     "ims.example.org",
		Nonce:     nonceFor(testRAND, testAUTN),
		Opaque:    "opaque-value",
		Algorithm: "AKAv1-MD5",
	}
	opts := digest.Options{
		Method:   "REGISTER",
		URI:      "sip:ims.example.org",
		Username: "0123456789012345@ims.mnc001.mcc001.3gppnetwork.org",
	}

	result, err := ComputeDigest(fakeProvider{}, chal, opts)
	if err != nil {
		t.Fatalf("ComputeDigest() error = %v", err)
	}
	if result.SyncFailure {
		t.Fatal("SyncFailure = true, want false for a recognized challenge")
	}
	if !strings.HasPrefix(result.Header, "Digest ") {
		t.Fatalf("Header = %q, want it to start with %q", result.Header, "Digest ")
	}
	if !strings.Contains(result.Header, `algorithm=AKAv1-MD5`) {
		t.Fatalf("Header = %q, want the wire algorithm restored to AKAv1-MD5", result.Header)
	}

	// Independently recompute the expected response the way the network
	// side would (raw RES bytes as the password, math done as plain MD5) and check
	// the header's response= matches byte for byte.
	mathChal := *chal
	mathChal.Algorithm = "MD5"
	want, err := digest.Digest(&mathChal, digest.Options{
		Method:   opts.Method,
		URI:      opts.URI,
		Username: opts.Username,
		Password: string(testRES),
	})
	if err != nil {
		t.Fatalf("reference digest.Digest() error = %v", err)
	}
	if !strings.Contains(result.Header, `response="`+want.Response+`"`) {
		t.Fatalf("Header = %q, does not contain expected response=%q", result.Header, want.Response)
	}
}

func TestComputeDigestSyncFailure(t *testing.T) {
	chal := &digest.Challenge{
		Realm:     "ims.example.org",
		Nonce:     nonceFor(unsyncedRAND, unsyncedAUTN),
		Opaque:    "opaque-value",
		Algorithm: "AKAv1-MD5",
	}
	opts := digest.Options{
		Method:   "REGISTER",
		URI:      "sip:ims.example.org",
		Username: "0123456789012345@ims.mnc001.mcc001.3gppnetwork.org",
	}

	result, err := ComputeDigest(fakeProvider{}, chal, opts)
	if err != nil {
		t.Fatalf("ComputeDigest() error = %v", err)
	}
	if !result.SyncFailure {
		t.Fatal("SyncFailure = false, want true for the out-of-sync challenge")
	}

	wantAuts := `auts="` + base64.StdEncoding.EncodeToString(testAUTS) + `"`
	if !strings.Contains(result.Header, wantAuts) {
		t.Fatalf("Header = %q, want it to contain %q", result.Header, wantAuts)
	}

	// RFC 3310 S3.4: the response for a resync attempt must be computed
	// with an EMPTY password, not silently reusing a stale RES.
	mathChal := *chal
	mathChal.Algorithm = "MD5"
	want, err := digest.Digest(&mathChal, digest.Options{
		Method:   opts.Method,
		URI:      opts.URI,
		Username: opts.Username,
		Password: "",
	})
	if err != nil {
		t.Fatalf("reference digest.Digest() error = %v", err)
	}
	if !strings.Contains(result.Header, `response="`+want.Response+`"`) {
		t.Fatalf("Header = %q, does not contain expected empty-password response=%q", result.Header, want.Response)
	}
}

func TestComputeDigestProviderError(t *testing.T) {
	chal := &digest.Challenge{
		Realm:     "ims.example.org",
		Nonce:     nonceFor(bytesOf(0xFF, randAUTNLen), bytesOf(0xFE, randAUTNLen)), // unrecognized by fakeProvider
		Algorithm: "AKAv1-MD5",
	}
	_, err := ComputeDigest(fakeProvider{}, chal, digest.Options{Method: "REGISTER", URI: "sip:ims.example.org"})
	if err == nil {
		t.Fatal("ComputeDigest() error = nil, want an error for a provider that rejects the challenge")
	}
}

func TestComputeDigestMalformedNonce(t *testing.T) {
	for name, nonce := range map[string]string{
		"not base64": "not-valid-base64!!!",
		"too short":  base64.StdEncoding.EncodeToString(bytesOf(0x01, 10)),
	} {
		t.Run(name, func(t *testing.T) {
			chal := &digest.Challenge{Realm: "ims.example.org", Nonce: nonce, Algorithm: "AKAv1-MD5"}
			_, err := ComputeDigest(fakeProvider{}, chal, digest.Options{Method: "REGISTER", URI: "sip:ims.example.org"})
			if err == nil {
				t.Fatal("ComputeDigest() error = nil, want an error for a malformed nonce")
			}
		})
	}
}

func TestComputeDigestNilProvider(t *testing.T) {
	chal := &digest.Challenge{Realm: "ims.example.org", Nonce: nonceFor(testRAND, testAUTN), Algorithm: "AKAv1-MD5"}
	_, err := ComputeDigest(nil, chal, digest.Options{Method: "REGISTER", URI: "sip:ims.example.org"})
	if err == nil {
		t.Fatal("ComputeDigest() error = nil, want an error for a nil provider")
	}
}
