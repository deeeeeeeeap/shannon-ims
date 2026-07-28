package swu

import (
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestPrepareIKERekeyRequestUsesNegotiatedGroup15(t *testing.T) {
	negotiatedDH, err := crypto.NewDiffieHellman(15)
	if err != nil {
		t.Fatalf("create negotiated DH: %v", err)
	}
	session := &Session{
		DH:        negotiatedDH,
		ikeEncrID: uint16(ikev2.ENCR_AES_GCM_16),
		ikeIsAEAD: true,
	}

	attempt, err := session.prepareIKERekeyRequest()
	if err != nil {
		t.Fatalf("prepareIKERekeyRequest() failed: %v", err)
	}
	if attempt.dh.Group != 15 {
		t.Fatalf("generated DH group = %d, want 15", attempt.dh.Group)
	}

	var proposalGroup, keGroup ikev2.AlgorithmType
	for _, payload := range attempt.payloads {
		switch typed := payload.(type) {
		case *ikev2.EncryptedPayloadSA:
			if len(typed.Proposals) != 1 {
				t.Fatalf("proposal count = %d, want 1", len(typed.Proposals))
			}
			for _, transform := range typed.Proposals[0].Transforms {
				if transform.Type == ikev2.TransformTypeDH {
					proposalGroup = transform.ID
				}
			}
		case *ikev2.EncryptedPayloadKE:
			keGroup = typed.DHGroup
			if len(typed.KEData) != 384 {
				t.Fatalf("KE length = %d, want 384", len(typed.KEData))
			}
		}
	}
	if proposalGroup != ikev2.MODP_3072_bit || keGroup != ikev2.MODP_3072_bit {
		t.Fatalf("rekey groups proposal=%d KE=%d, want 15/15", proposalGroup, keGroup)
	}
}

func TestPrepareIKERekeyRequestKeepsNegotiatedGroup14(t *testing.T) {
	negotiatedDH, err := crypto.NewDiffieHellman(14)
	if err != nil {
		t.Fatalf("create negotiated DH: %v", err)
	}
	session := &Session{
		DH:        negotiatedDH,
		ikeEncrID: uint16(ikev2.ENCR_AES_GCM_16),
		ikeIsAEAD: true,
	}
	attempt, err := session.prepareIKERekeyRequest()
	if err != nil {
		t.Fatalf("prepareIKERekeyRequest() failed: %v", err)
	}
	if attempt.dh.Group != 14 {
		t.Fatalf("generated DH group = %d, want 14", attempt.dh.Group)
	}
	for _, payload := range attempt.payloads {
		if ke, ok := payload.(*ikev2.EncryptedPayloadKE); ok {
			if ke.DHGroup != ikev2.MODP_2048_bit || len(ke.KEData) != 256 {
				t.Fatalf("group 14 KE metadata = group %d length %d", ke.DHGroup, len(ke.KEData))
			}
			return
		}
	}
	t.Fatal("rekey request contains no KE payload")
}

func TestPreparePeerIKERekeyDHUsesNegotiatedGroup15(t *testing.T) {
	negotiatedDH, err := crypto.NewDiffieHellman(15)
	if err != nil {
		t.Fatalf("create negotiated DH: %v", err)
	}
	peerDH, err := crypto.NewDiffieHellman(15)
	if err != nil {
		t.Fatalf("create peer DH: %v", err)
	}
	if err := peerDH.GenerateKey(); err != nil {
		t.Fatalf("generate peer DH: %v", err)
	}
	proposal := ikev2.NewProposal(1, ikev2.ProtoIKE, make([]byte, 8))
	proposal.AddTransform(ikev2.TransformTypeDH, ikev2.MODP_3072_bit, 0)
	session := &Session{DH: negotiatedDH}

	responseDH, group, err := session.preparePeerIKERekeyDH(
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{proposal}},
		&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_3072_bit, KEData: peerDH.PublicKeyBytes()},
	)
	if err != nil {
		t.Fatalf("preparePeerIKERekeyDH() failed: %v", err)
	}
	if group != ikev2.MODP_3072_bit || responseDH.Group != 15 {
		t.Fatalf("peer rekey groups selected=%d generated=%d, want 15/15", group, responseDH.Group)
	}
	if len(responseDH.SharedKey) != 384 {
		t.Fatalf("peer rekey shared secret length = %d, want 384", len(responseDH.SharedKey))
	}
}

func TestValidateIKERekeyResponseDHMatchesProposalKEAndGeneratedGroup(t *testing.T) {
	initiatorDH, err := crypto.NewDiffieHellman(15)
	if err != nil {
		t.Fatalf("create initiator DH: %v", err)
	}
	peerDH, err := crypto.NewDiffieHellman(15)
	if err != nil {
		t.Fatalf("create peer DH: %v", err)
	}
	if err := peerDH.GenerateKey(); err != nil {
		t.Fatalf("generate peer DH: %v", err)
	}
	proposal := ikev2.NewProposal(1, ikev2.ProtoIKE, make([]byte, 8))
	proposal.AddTransform(ikev2.TransformTypeDH, ikev2.MODP_3072_bit, 0)
	responseSA := &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{proposal}}
	responseKE := &ikev2.EncryptedPayloadKE{
		DHGroup: ikev2.MODP_3072_bit,
		KEData:  peerDH.PublicKeyBytes(),
	}
	if err := validateIKERekeyResponseDH(initiatorDH, responseSA, responseKE); err != nil {
		t.Fatalf("validateIKERekeyResponseDH() failed: %v", err)
	}

	responseKE.DHGroup = ikev2.MODP_2048_bit
	if err := validateIKERekeyResponseDH(initiatorDH, responseSA, responseKE); err == nil {
		t.Fatal("validateIKERekeyResponseDH() accepted a mismatched KE group")
	}
}
