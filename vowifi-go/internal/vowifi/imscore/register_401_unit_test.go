package imscore

import (
	"encoding/base64"
	"encoding/hex"
	"net"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"

	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

// fixedAKA returns deterministic RES/CK/IK for offline replay.
type fixedAKA struct {
	res, ck, ik []byte
}

func (f fixedAKA) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	_ = rand16
	_ = autn16
	return sim.AKAResult{RES: f.res, CK: f.ck, IK: f.ik}, nil
}

func TestDecodeChallengeNonceAcceptsHexRANDAUTN(t *testing.T) {
	// 16-byte RAND || 16-byte AUTN as hex (common in some stacks / logs).
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	nonce := hex.EncodeToString(raw)
	got, err := decodeChallengeNonce(nonce)
	if err != nil {
		t.Fatalf("hex nonce decode: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("hex nonce len = %d, want 32", len(got))
	}
	if !bytesEqual(got, raw) {
		t.Fatalf("hex nonce mismatch")
	}
}

func TestDecodeChallengeNonceAcceptsBase64RANDAUTN(t *testing.T) {
	// RFC 3310 / common IMS: nonce is base64(RAND||AUTN).
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(0xA0 + i)
	}
	nonce := base64.StdEncoding.EncodeToString(raw)
	got, err := decodeChallengeNonce(nonce)
	if err != nil {
		t.Fatalf("base64 nonce decode failed (expected pass after fix or fail before): %v", err)
	}
	if !bytesEqual(got, raw) {
		t.Fatalf("base64 nonce mismatch")
	}
}

func TestDecodeChallengeNonceRejectsInvalid(t *testing.T) {
	if _, err := decodeChallengeNonce(""); err == nil {
		t.Fatal("empty nonce should fail")
	}
	if _, err := decodeChallengeNonce("not-hex-or-base64!!!"); err == nil {
		t.Fatal("garbage nonce should fail")
	}
	// Too short after decode.
	short := base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	raw, err := decodeChallengeNonce(short)
	if err != nil {
		// ok if decoder rejects
		return
	}
	if len(raw) >= 32 {
		t.Fatalf("short nonce decoded to %d bytes, want <32 or error", len(raw))
	}
}

func TestComputeAKAAuthDigestURIMatchesRequestURI(t *testing.T) {
	home := "ims.mnc015.mcc234.3gppnetwork.org"
	cfg := Config{
		HomeDomain: home,
		Realm:      home,
		PrivateID:  "fake.impi@ims.mnc015.mcc234.3gppnetwork.org",
		PublicURI:  "sip:fake.impu@ims.mnc015.mcc234.3gppnetwork.org",
		LocalIP:    net.ParseIP("10.0.0.2"),
		PCSCFAddr:  "10.0.0.3:5060",
		Template:   policy.VodafoneUKTemplate(),
		AKA: fixedAKA{
			res: bytesRepeat(0x11, 8),
			ck:  bytesRepeat(0x22, 16),
			ik:  bytesRepeat(0x33, 16),
		},
	}

	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	nonce := hex.EncodeToString(raw)
	chal := &digest.Challenge{
		Realm:     home,
		Nonce:     nonce,
		Algorithm: "AKAv1-MD5",
		QOP:       []string{"auth"},
	}

	req, err := buildRegisterRequest(cfg, registerState{spiC: 10, spiS: 11, portC: 5062, portS: 5063}, true, initialRegisterVariants(cfg)[0])
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}

	_, authHeader, _, err := computeAKAAuth(cfg, chal, req)
	if err != nil {
		t.Fatalf("computeAKAAuth: %v", err)
	}

	// Capture actual Authorization; Digest uri must match full Request-URI.
	wantURI := "sip:" + home
	if !strings.Contains(authHeader, `uri="`+wantURI+`"`) && !strings.Contains(authHeader, `uri=`+wantURI) {
		t.Fatalf("Authorization = %q\nwant Digest uri %q (full Request-URI), not host-only", authHeader, wantURI)
	}
	if strings.Contains(authHeader, `uri="`+home+`"`) {
		t.Fatalf("Authorization uses host-only uri %q; want %q", home, wantURI)
	}
}

func TestSelectDigestChallenge401And407(t *testing.T) {
	cfg := Config{}
	res401 := sip.NewResponse(sip.StatusUnauthorized, "Unauthorized")
	res401.AppendHeader(sip.NewHeader("WWW-Authenticate", `Digest realm="ims.example", nonce="aa", algorithm=AKAv1-MD5`))
	chal, err := selectDigestChallenge(cfg, res401)
	if err != nil || chal == nil {
		t.Fatalf("401 WWW-Authenticate: %v", err)
	}

	res407 := sip.NewResponse(sip.StatusProxyAuthRequired, "Proxy Authentication Required")
	res407.AppendHeader(sip.NewHeader("Proxy-Authenticate", `Digest realm="ims.example", nonce="bb", algorithm=AKAv1-MD5`))
	chal, err = selectDigestChallenge(cfg, res407)
	if err != nil || chal == nil {
		t.Fatalf("407 Proxy-Authenticate: %v", err)
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
