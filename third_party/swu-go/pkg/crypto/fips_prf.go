package crypto

import (
	"encoding/binary"
	"math/bits"
)

type FIPS1862PRFSHA1 struct {
	xkey [20]byte
}

func NewFIPS1862PRFSHA1(key []byte) *FIPS1862PRFSHA1 {
	p := &FIPS1862PRFSHA1{}
	if len(key) >= len(p.xkey) {
		copy(p.xkey[:], key[len(key)-len(p.xkey):])
	} else {
		copy(p.xkey[len(p.xkey)-len(key):], key)
	}
	return p
}

func (p *FIPS1862PRFSHA1) Bytes(seed []byte, outLen int) []byte {
	if outLen <= 0 {
		return nil
	}
	out := make([]byte, 0, outLen)
	for len(out) < outLen {
		block := p.block(seed)
		need := outLen - len(out)
		if need >= len(block) {
			out = append(out, block...)
		} else {
			out = append(out, block[:need]...)
		}
	}
	return out
}

func (p *FIPS1862PRFSHA1) block(seed []byte) []byte {
	var xseed [20]byte
	if len(seed) >= len(xseed) {
		copy(xseed[:], seed[len(seed)-len(xseed):])
	} else if len(seed) > 0 {
		copy(xseed[len(xseed)-len(seed):], seed)
	}

	out := make([]byte, 40)
	var one [20]byte
	one[19] = 1

	for i := 0; i < 2; i++ {
		var xval [20]byte
		addMod20(p.xkey[:], xseed[:], xval[:])

		var buf [64]byte
		copy(buf[:20], xval[:])
		sum := keyedSHA1StateAfterBlock(buf[:])
		copy(out[i*20:(i+1)*20], sum[:])

		var tmp [20]byte
		addMod20(p.xkey[:], sum[:], tmp[:])
		addMod20(tmp[:], one[:], p.xkey[:])
	}
	return out
}

func addMod20(a []byte, b []byte, dst []byte) {
	carry := 0
	for i := 19; i >= 0; i-- {
		s := int(a[i]) + int(b[i]) + carry
		dst[i] = byte(s & 0xff)
		carry = s >> 8
	}
}

func keyedSHA1StateAfterBlock(block64 []byte) [20]byte {
	h0 := uint32(0x67452301)
	h1 := uint32(0xEFCDAB89)
	h2 := uint32(0x98BADCFE)
	h3 := uint32(0x10325476)
	h4 := uint32(0xC3D2E1F0)

	var w [80]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block64[i*4 : i*4+4])
	}
	for i := 16; i < 80; i++ {
		w[i] = bits.RotateLeft32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
	}

	a, b, c, d, e := h0, h1, h2, h3, h4
	for i := 0; i < 80; i++ {
		var f, k uint32
		switch {
		case i < 20:
			f = (b & c) | ((^b) & d)
			k = 0x5A827999
		case i < 40:
			f = b ^ c ^ d
			k = 0x6ED9EBA1
		case i < 60:
			f = (b & c) | (b & d) | (c & d)
			k = 0x8F1BBCDC
		default:
			f = b ^ c ^ d
			k = 0xCA62C1D6
		}
		t := bits.RotateLeft32(a, 5) + f + e + k + w[i]
		e = d
		d = c
		c = bits.RotateLeft32(b, 30)
		b = a
		a = t
	}

	h0 += a
	h1 += b
	h2 += c
	h3 += d
	h4 += e

	var out [20]byte
	binary.BigEndian.PutUint32(out[0:4], h0)
	binary.BigEndian.PutUint32(out[4:8], h1)
	binary.BigEndian.PutUint32(out[8:12], h2)
	binary.BigEndian.PutUint32(out[12:16], h3)
	binary.BigEndian.PutUint32(out[16:20], h4)
	return out
}
