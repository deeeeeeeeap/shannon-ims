package ikev2

// EAP 载荷 (RFC 7296 3.16 节)
type EncryptedPayloadEAP struct {
	EAPMessage []byte
}

func (p *EncryptedPayloadEAP) Type() PayloadType { return EAP }

func (p *EncryptedPayloadEAP) Encode() ([]byte, error) {
	return p.EAPMessage, nil
}

func DecodePayloadEAP(data []byte) (*EncryptedPayloadEAP, error) {
	return &EncryptedPayloadEAP{EAPMessage: data}, nil
}
