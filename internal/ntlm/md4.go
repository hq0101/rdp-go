package ntlm

import (
	"encoding/binary"
	"math/bits"
)

// md4sum implements RFC 1320 solely for the NTLM password hash. It must not
// be used as a general-purpose cryptographic hash.
func md4sum(p []byte) [16]byte {
	size := uint64(len(p)) * 8
	b := append([]byte{}, p...)
	b = append(b, 0x80)
	for len(b)%64 != 56 {
		b = append(b, 0)
	}
	b = binary.LittleEndian.AppendUint64(b, size)
	h := [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}
	for len(b) > 0 {
		var x [16]uint32
		for i := range x {
			x[i] = binary.LittleEndian.Uint32(b[i*4:])
		}
		a, c0, c, d := h[0], h[1], h[2], h[3]
		v := [4]uint32{a, c0, c, d}
		for round := 0; round < 3; round++ {
			for j := 0; j < 16; j++ {
				i := (4 - j%4) % 4
				u, w, z := v[(i+1)%4], v[(i+2)%4], v[(i+3)%4]
				k, s, add := j, []int{3, 7, 11, 19}[j%4], uint32(0)
				f := (u & w) | (^u & z)
				if round == 1 {
					k = (j%4)*4 + j/4
					s = []int{3, 5, 9, 13}[j%4]
					add = 0x5a827999
					f = (u & w) | (u & z) | (w & z)
				}
				if round == 2 {
					k = []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}[j]
					s = []int{3, 9, 11, 15}[j%4]
					add = 0x6ed9eba1
					f = u ^ w ^ z
				}
				v[i] = bits.RotateLeft32(v[i]+f+x[k]+add, s)
			}
		}
		for i := range h {
			h[i] += v[i]
		}
		b = b[64:]
	}
	var out [16]byte
	for i, v := range h {
		binary.LittleEndian.PutUint32(out[i*4:], v)
	}
	return out
}
