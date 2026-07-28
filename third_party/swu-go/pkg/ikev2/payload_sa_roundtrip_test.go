package ikev2

import "testing"

func TestPayloadSARoundTrip(t *testing.T) {
	prop := NewProposal(1, ProtoIKE, nil)
	prop.AddTransform(TransformTypeEncr, ENCR_AES_CBC, 256)
	prop.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_256, 0)
	prop.AddTransform(TransformTypeDH, MODP_2048_bit, 0)

	orig := &EncryptedPayloadSA{
		Proposals: []*Proposal{prop},
	}

	enc, err := orig.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	dec, err := DecodePayloadSA(enc)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if len(dec.Proposals) != 1 {
		t.Fatalf("proposal count mismatch: got %d", len(dec.Proposals))
	}
	if len(dec.Proposals[0].Transforms) != 3 {
		t.Fatalf("transform count mismatch: got %d", len(dec.Proposals[0].Transforms))
	}

	got := dec.Proposals[0].Transforms[0]
	if got.Type != TransformTypeEncr || got.ID != ENCR_AES_CBC {
		t.Fatalf("encr transform mismatch: %v/%v", got.Type, got.ID)
	}
	if len(got.Attributes) != 1 {
		t.Fatalf("encr attr count mismatch: got %d", len(got.Attributes))
	}
	if got.Attributes[0].Type != AttributeKeyLength || got.Attributes[0].Val != 256 {
		t.Fatalf("key length attr mismatch: type=%d val=%d", got.Attributes[0].Type, got.Attributes[0].Val)
	}
}
