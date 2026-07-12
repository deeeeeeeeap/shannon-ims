// Package cscall 实现 CS 域蜂窝来电 → SIP/RTP 桥接
package cscall

// G.711 μ-law 编解码 (ITU-T G.711)
// 纯 Go 查表实现，零依赖，用于 PCM 16-bit ↔ 8-bit μ-law 转换

// LinearToUlaw 将 16-bit 线性 PCM 样本转换为 8-bit μ-law
func LinearToUlaw(sample int16) byte {
	// μ-law 压缩算法
	const (
		bias   = 0x84 // 132
		clip   = 32635
		maxVal = 0x1FFF
	)

	sign := (sample >> 8) & 0x80
	if sign != 0 {
		sample = -sample
	}
	if sample > clip {
		sample = clip
	}
	sample += bias

	// 查找指数段
	exponent := 7
	for mask := int16(0x4000); (sample&mask) == 0 && exponent > 0; exponent-- {
		mask >>= 1
	}

	// 组合尾数 (mantissa)
	mantissa := (sample >> (exponent + 3)) & 0x0F
	ulawByte := byte(sign) | byte(exponent<<4) | byte(mantissa)

	return ^ulawByte // 按位取反
}

// UlawToLinear 将 8-bit μ-law 转换为 16-bit 线性 PCM 样本
func UlawToLinear(ulaw byte) int16 {
	ulaw = ^ulaw
	sign := int16(ulaw & 0x80)
	exponent := int16((ulaw >> 4) & 0x07)
	mantissa := int16(ulaw & 0x0F)

	sample := (mantissa<<3 + 0x84) << (exponent + 2)
	sample -= 0x84 << 2 // 去除 bias

	if sign != 0 {
		sample = -sample
	}
	return sample
}

// EncodePCMToUlaw 批量将 PCM S16_LE 数据编码为 μ-law
// pcm: 输入的原始 PCM 数据 (每 2 字节一个 sample, little-endian)
// 返回: 编码后的 μ-law 数据 (每 1 字节一个 sample)
func EncodePCMToUlaw(pcm []byte) []byte {
	numSamples := len(pcm) / 2
	out := make([]byte, numSamples)
	for i := 0; i < numSamples; i++ {
		// S16_LE: 低字节在前
		sample := int16(pcm[i*2]) | int16(pcm[i*2+1])<<8
		out[i] = LinearToUlaw(sample)
	}
	return out
}

// DecodeUlawToPCM 批量将 μ-law 数据解码为 PCM S16_LE
// ulaw: 输入的 μ-law 数据
// 返回: 解码后的 PCM 数据 (每 sample 2 字节, little-endian)
func DecodeUlawToPCM(ulaw []byte) []byte {
	out := make([]byte, len(ulaw)*2)
	for i, u := range ulaw {
		sample := UlawToLinear(u)
		out[i*2] = byte(sample)
		out[i*2+1] = byte(sample >> 8)
	}
	return out
}
