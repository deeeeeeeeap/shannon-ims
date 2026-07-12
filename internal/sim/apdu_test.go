package sim

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	swusim "github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/runtimehost/simauth"
	"github.com/icholy/digest"
)

type parsedAKAProvider struct {
	result AKAResult
	err    error
}

func (p parsedAKAProvider) CalculateAKA(rand16, autn16 []byte) (swusim.AKAResult, error) {
	_ = rand16
	_ = autn16
	return p.result, p.err
}

func TestParseUSIMAuthResponseSyncFailureReturnsErrWithAUTS(t *testing.T) {
	syncToken := make([]byte, 14)
	for i := range syncToken {
		syncToken[i] = byte(i + 1)
	}

	response := append([]byte{0xDC, byte(len(syncToken))}, syncToken...)
	response = append(response, 0x90, 0x00)

	result, err := ParseUSIMAuthResponse("test-device", response)

	if !errors.Is(err, swusim.ErrSyncFailure) {
		t.Fatalf("err = %v, want ErrSyncFailure", err)
	}
	if !bytes.Equal(result.AUTS, syncToken) {
		t.Fatalf("AUTS mismatch: got_len=%d want_len=%d", len(result.AUTS), len(syncToken))
	}
	if len(result.RES) != 0 || len(result.CK) != 0 || len(result.IK) != 0 {
		t.Fatalf(
			"success material must be empty: res_len=%d ck_len=%d ik_len=%d",
			len(result.RES),
			len(result.CK),
			len(result.IK),
		)
	}
}

func TestParsedSyncFailureBuildsAUTSResyncAuthorization(t *testing.T) {
	syncToken := make([]byte, 14)
	for i := range syncToken {
		syncToken[i] = byte(i + 1)
	}
	response := append([]byte{0xDC, byte(len(syncToken))}, syncToken...)
	response = append(response, 0x90, 0x00)

	akaResult, akaErr := ParseUSIMAuthResponse("test-device", response)
	challengeBytes := make([]byte, 32)
	for i := range challengeBytes {
		challengeBytes[i] = byte(i + 33)
	}
	result, err := simauth.ComputeDigest(
		parsedAKAProvider{result: akaResult, err: akaErr},
		&digest.Challenge{
			Realm:     "ims.example.invalid",
			Nonce:     base64.StdEncoding.EncodeToString(challengeBytes),
			Algorithm: "AKAv1-MD5",
		},
		digest.Options{
			Method:   "REGISTER",
			URI:      "sip:ims.example.invalid",
			Username: "test-private-id",
		},
	)
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	if !result.SyncFailure {
		t.Fatal("SyncFailure = false, want true")
	}
	if !strings.Contains(strings.ToLower(result.Header), "auts=") {
		t.Fatal("resync Authorization is missing auts directive")
	}
}
