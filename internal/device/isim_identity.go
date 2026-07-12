package device

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/1239t/vowifi-go/runtimehost/identity"
)

const fallbackISIMAID = "A0000000871004FFFFFFFF89000000"

type isimIdentityAPDUAccess interface {
	ResolveLogicalChannelAID(app string, fallbackAID string) (aid string, source string, err error)
	OpenLogicalChannel(aid string) (int, error)
	CloseLogicalChannel(channel int) error
	TransmitAPDU(channel int, command string) (string, error)
}

type isimAPDUResponse struct {
	data     []byte
	sw1, sw2 byte
}

func readISIMIdentity(access isimIdentityAPDUAccess) (out identity.Identity, retErr error) {
	if access == nil {
		return identity.Identity{}, fmt.Errorf("ISIM identity access unavailable")
	}
	aid, _, err := access.ResolveLogicalChannelAID("isim", fallbackISIMAID)
	if err != nil {
		return identity.Identity{}, fmt.Errorf("resolve ISIM AID: %w", err)
	}
	channel, err := access.OpenLogicalChannel(aid)
	if err != nil {
		return identity.Identity{}, fmt.Errorf("open ISIM logical channel: %w", err)
	}
	defer func() {
		if err := access.CloseLogicalChannel(channel); retErr == nil && err != nil {
			retErr = fmt.Errorf("close ISIM logical channel: %w", err)
		}
	}()

	var readFailures int
	if raw, err := readISIMTransparentEF(access, channel, 0x6f02); err == nil {
		out.IMPI, err = decodeISIMIdentityTLV80(raw)
		if err != nil {
			return identity.Identity{}, fmt.Errorf("decode EF_IMPI: %w", err)
		}
	} else {
		readFailures++
	}
	if raw, err := readISIMTransparentEF(access, channel, 0x6f03); err == nil {
		out.Domain, err = decodeISIMIdentityTLV80(raw)
		if err != nil {
			return identity.Identity{}, fmt.Errorf("decode EF_DOMAIN: %w", err)
		}
	} else {
		readFailures++
	}
	if records, err := readISIMRecordEF(access, channel, 0x6f04, 8); err == nil {
		for _, raw := range records {
			impu, err := decodeISIMIdentityTLV80(raw)
			if err != nil {
				return identity.Identity{}, fmt.Errorf("decode EF_IMPU: %w", err)
			}
			if impu != "" {
				out.IMPU = append(out.IMPU, impu)
			}
		}
	} else {
		readFailures++
	}

	if out.IMPI == "" && out.Domain == "" && len(out.IMPU) == 0 && readFailures > 0 {
		return identity.Identity{}, fmt.Errorf("ISIM identity files unavailable")
	}
	return out, nil
}

func readISIMTransparentEF(access isimIdentityAPDUAccess, channel int, fileID uint16) ([]byte, error) {
	if err := selectISIMEF(access, channel, fileID); err != nil {
		return nil, err
	}
	res, err := transmitISIMAPDU(access, channel, "00B0000000")
	if err != nil {
		return nil, err
	}
	if !isISIMAPDUSuccess(res.sw1, res.sw2) {
		return nil, fmt.Errorf("READ BINARY %04X failed: %02X%02X", fileID, res.sw1, res.sw2)
	}
	return res.data, nil
}

func readISIMRecordEF(access isimIdentityAPDUAccess, channel int, fileID uint16, maxRecords int) ([][]byte, error) {
	if err := selectISIMEF(access, channel, fileID); err != nil {
		return nil, err
	}
	var records [][]byte
	for record := 1; record <= maxRecords; record++ {
		res, err := transmitISIMAPDU(access, channel, fmt.Sprintf("00B2%02X0400", record))
		if err != nil {
			return nil, err
		}
		if (res.sw1 == 0x6a && res.sw2 == 0x83) || (res.sw1 == 0x6a && res.sw2 == 0x82) {
			break
		}
		if !isISIMAPDUSuccess(res.sw1, res.sw2) {
			return nil, fmt.Errorf("READ RECORD %04X/%d failed: %02X%02X", fileID, record, res.sw1, res.sw2)
		}
		records = append(records, append([]byte(nil), res.data...))
	}
	return records, nil
}

func selectISIMEF(access isimIdentityAPDUAccess, channel int, fileID uint16) error {
	res, err := transmitISIMAPDU(access, channel, fmt.Sprintf("00A4000402%04X00", fileID))
	if err != nil {
		return err
	}
	if !isISIMAPDUSuccess(res.sw1, res.sw2) {
		return fmt.Errorf("SELECT EF %04X failed: %02X%02X", fileID, res.sw1, res.sw2)
	}
	return nil
}

func transmitISIMAPDU(access isimIdentityAPDUAccess, channel int, command string) (isimAPDUResponse, error) {
	command = strings.ToUpper(strings.TrimSpace(command))
	res, err := transmitISIMAPDUOnce(access, channel, command)
	if err != nil {
		return isimAPDUResponse{}, err
	}
	if res.sw1 == 0x6c {
		if len(command) < 2 {
			return isimAPDUResponse{}, fmt.Errorf("invalid APDU for 6C retry")
		}
		command = command[:len(command)-2] + fmt.Sprintf("%02X", res.sw2)
		res, err = transmitISIMAPDUOnce(access, channel, command)
		if err != nil {
			return isimAPDUResponse{}, err
		}
	}
	data := append([]byte(nil), res.data...)
	for followups := 0; (res.sw1 == 0x61 || res.sw1 == 0x9f) && followups < 8; followups++ {
		res, err = transmitISIMAPDUOnce(access, channel, fmt.Sprintf("00C00000%02X", res.sw2))
		if err != nil {
			return isimAPDUResponse{}, err
		}
		data = append(data, res.data...)
	}
	res.data = data
	return res, nil
}

func transmitISIMAPDUOnce(access isimIdentityAPDUAccess, channel int, command string) (isimAPDUResponse, error) {
	hexResponse, err := access.TransmitAPDU(channel, command)
	if err != nil {
		return isimAPDUResponse{}, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(hexResponse))
	if err != nil {
		return isimAPDUResponse{}, fmt.Errorf("decode APDU response: %w", err)
	}
	if len(raw) < 2 {
		return isimAPDUResponse{}, fmt.Errorf("APDU response too short")
	}
	return isimAPDUResponse{
		data: append([]byte(nil), raw[:len(raw)-2]...),
		sw1:  raw[len(raw)-2],
		sw2:  raw[len(raw)-1],
	}, nil
}

func isISIMAPDUSuccess(sw1, sw2 byte) bool {
	return (sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x62 || sw1 == 0x63
}

func decodeISIMIdentityTLV80(raw []byte) (string, error) {
	data := append([]byte(nil), raw...)
	if len(data) >= 2 && data[0] == 0x80 {
		length, offset, err := decodeISIMBERLength(data[1:])
		if err != nil {
			return "", err
		}
		start := 1 + offset
		if length < 0 || start+length > len(data) {
			return "", fmt.Errorf("ISIM identity TLV length %d exceeds payload %d", length, len(data)-start)
		}
		data = data[start : start+length]
	}
	for len(data) > 0 && (data[len(data)-1] == 0xff || data[len(data)-1] == 0x00) {
		data = data[:len(data)-1]
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf("ISIM identity is not valid UTF-8")
	}
	return strings.TrimSpace(string(data)), nil
}

func decodeISIMBERLength(raw []byte) (length int, consumed int, err error) {
	if len(raw) == 0 {
		return 0, 0, fmt.Errorf("ISIM identity TLV missing length")
	}
	if raw[0]&0x80 == 0 {
		return int(raw[0]), 1, nil
	}
	count := int(raw[0] & 0x7f)
	if count == 0 || count > 2 || len(raw) < 1+count {
		return 0, 0, fmt.Errorf("unsupported ISIM identity TLV length encoding")
	}
	length = 0
	for _, b := range raw[1 : 1+count] {
		length = length<<8 | int(b)
	}
	return length, 1 + count, nil
}
