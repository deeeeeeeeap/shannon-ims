package ikev2

import (
	"crypto/sha1"
	"encoding/binary"
)

// CalculateNATDetectionHash 计算 NAT 检测哈希值
// RFC 7296 2.23: SHA-1(SPIi | SPIr | IP | Port)
func CalculateNATDetectionHash(spiI, spiR uint64, ip []byte, port uint16) []byte {
	h := sha1.New()

	// 写入 SPI 值
	spiBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(spiBytes[0:8], spiI)
	binary.BigEndian.PutUint64(spiBytes[8:16], spiR)
	h.Write(spiBytes)

	// 写入 IP 地址 (4 或 16 字节)
	h.Write(ip)

	// 写入端口
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	h.Write(portBytes)

	return h.Sum(nil)
}

// CreateNATDetectionNotify 创建 NAT 检测通知载荷
func CreateNATDetectionNotify(notifyType uint16, hash []byte) *EncryptedPayloadNotify {
	return &EncryptedPayloadNotify{
		ProtocolID: ProtoIKE,
		SPI:        nil,
		NotifyType: notifyType,
		NotifyData: hash,
	}
}
