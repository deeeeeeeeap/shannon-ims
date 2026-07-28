package swu

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
)

type ikeRekeyRequest struct {
	payloads []ikev2.Payload
	nonce    []byte
	dh       *crypto.DiffieHellman
	spiI     uint64
}

func (s *Session) prepareIKERekeyRequest() (*ikeRekeyRequest, error) {
	if s.DH == nil {
		return nil, errors.New("IKE SA has no negotiated DH group")
	}
	group := ikev2.AlgorithmType(s.DH.Group)
	if group != ikev2.MODP_2048_bit && group != ikev2.MODP_3072_bit {
		return nil, fmt.Errorf("unsupported negotiated IKE DH group %d", group)
	}

	newNonce, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("generate IKE rekey nonce: %w", err)
	}
	newDH, err := crypto.NewDiffieHellman(uint16(group))
	if err != nil {
		return nil, fmt.Errorf("create IKE rekey DH: %w", err)
	}
	if err := newDH.GenerateKey(); err != nil {
		return nil, fmt.Errorf("generate IKE rekey DH: %w", err)
	}

	newSPIiBytes := make([]byte, 8)
	if _, err := rand.Read(newSPIiBytes); err != nil {
		return nil, fmt.Errorf("generate IKE rekey SPI: %w", err)
	}
	newSPIi := binary.BigEndian.Uint64(newSPIiBytes)

	proposal := ikev2.NewProposal(1, ikev2.ProtoIKE, newSPIiBytes)
	proposal.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.AlgorithmType(s.ikeEncrID), 128)
	if !s.ikeIsAEAD {
		proposal.AddTransform(ikev2.TransformTypeInteg, ikev2.AlgorithmType(s.ikeIntegID), 0)
	}
	proposal.AddTransform(ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA2_256, 0)
	proposal.AddTransform(ikev2.TransformTypeDH, group, 0)

	payloads := []ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{proposal}},
		&ikev2.EncryptedPayloadNonce{NonceData: newNonce},
		&ikev2.EncryptedPayloadKE{DHGroup: group, KEData: newDH.PublicKeyBytes()},
	}
	return &ikeRekeyRequest{
		payloads: payloads,
		nonce:    newNonce,
		dh:       newDH,
		spiI:     newSPIi,
	}, nil
}

func (s *Session) preparePeerIKERekeyDH(
	requestSA *ikev2.EncryptedPayloadSA,
	requestKE *ikev2.EncryptedPayloadKE,
) (*crypto.DiffieHellman, ikev2.AlgorithmType, error) {
	if s.DH == nil {
		return nil, 0, errors.New("IKE SA has no negotiated DH group")
	}
	if requestSA == nil || len(requestSA.Proposals) != 1 || requestKE == nil {
		return nil, 0, errors.New("invalid peer IKE rekey DH payloads")
	}
	proposal := requestSA.Proposals[0]
	if proposal.ProtocolID != ikev2.ProtoIKE {
		return nil, 0, errors.New("invalid peer IKE rekey protocol")
	}
	var group ikev2.AlgorithmType
	for _, transform := range proposal.Transforms {
		if transform.Type != ikev2.TransformTypeDH {
			continue
		}
		if group != 0 {
			return nil, 0, errors.New("peer IKE rekey selected multiple DH groups")
		}
		group = transform.ID
	}
	if group == 0 || requestKE.DHGroup != group || uint16(group) != s.DH.Group {
		return nil, 0, errors.New("peer IKE rekey DH selection mismatch")
	}
	if group != ikev2.MODP_2048_bit && group != ikev2.MODP_3072_bit {
		return nil, 0, fmt.Errorf("unsupported peer IKE rekey DH group %d", group)
	}

	responseDH, err := crypto.NewDiffieHellman(uint16(group))
	if err != nil {
		return nil, 0, fmt.Errorf("create peer IKE rekey DH: %w", err)
	}
	if err := responseDH.GenerateKey(); err != nil {
		return nil, 0, fmt.Errorf("generate peer IKE rekey DH: %w", err)
	}
	if _, err := responseDH.ComputeSharedSecret(requestKE.KEData); err != nil {
		return nil, 0, fmt.Errorf("compute peer IKE rekey DH: %w", err)
	}
	return responseDH, group, nil
}

func validateIKERekeyResponseDH(
	generatedDH *crypto.DiffieHellman,
	responseSA *ikev2.EncryptedPayloadSA,
	responseKE *ikev2.EncryptedPayloadKE,
) error {
	if generatedDH == nil || responseSA == nil || len(responseSA.Proposals) != 1 || responseKE == nil {
		return errors.New("invalid IKE rekey DH response payloads")
	}
	proposal := responseSA.Proposals[0]
	if proposal.ProtocolID != ikev2.ProtoIKE {
		return errors.New("invalid IKE rekey response protocol")
	}
	var proposalGroup ikev2.AlgorithmType
	for _, transform := range proposal.Transforms {
		if transform.Type != ikev2.TransformTypeDH {
			continue
		}
		if proposalGroup != 0 {
			return errors.New("IKE rekey response selected multiple DH groups")
		}
		proposalGroup = transform.ID
	}
	if proposalGroup == 0 || responseKE.DHGroup != proposalGroup || uint16(proposalGroup) != generatedDH.Group {
		return errors.New("IKE rekey response DH selection mismatch")
	}
	return nil
}
