package krbcrypto

import "crypto/cipher"

// The internal CTS functions receive a validated AES cipher and >=16 bytes.
// Kerberos always prepends a full confounder, even for an empty message.
// CBC-CS3 swaps the last two blocks even when the length is block-aligned.
func encryptCTS(block cipher.Block, iv [16]byte, plain []byte) ([]byte, [16]byte) {
	out := make([]byte, len(plain))
	if len(plain) == 16 {
		for i := range iv {
			iv[i] ^= plain[i]
		}
		block.Encrypt(out, iv[:])
		copy(iv[:], out)
		return out, iv
	}
	last := (len(plain) - 1) / 16 * 16
	var tmp [16]byte
	defer clear(tmp[:])
	for offset := 0; offset < last; offset += 16 {
		for i := range tmp {
			tmp[i] = plain[offset+i] ^ iv[i]
		}
		block.Encrypt(out[offset:offset+16], tmp[:])
		copy(iv[:], out[offset:offset+16])
	}
	// iv is the penultimate block; steal its prefix for the final fragment.
	copy(out[last:], iv[:])
	copy(tmp[:], iv[:])
	for i, b := range plain[last:] {
		tmp[i] ^= b
	}
	block.Encrypt(out[last-16:last], tmp[:])
	copy(iv[:], out[last-16:last])
	return out, iv
}

func decryptCTS(block cipher.Block, iv [16]byte, sealed []byte) ([]byte, [16]byte) {
	out := make([]byte, len(sealed))
	if len(sealed) == 16 {
		block.Decrypt(out, sealed)
		for i := range iv {
			out[i] ^= iv[i]
		}
		copy(iv[:], sealed)
		return out, iv
	}
	last := (len(sealed) - 1) / 16 * 16
	var tmp [16]byte
	defer clear(tmp[:])
	for offset := 0; offset < last-16; offset += 16 {
		block.Decrypt(tmp[:], sealed[offset:offset+16])
		for i := range tmp {
			out[offset+i] = tmp[i] ^ iv[i]
		}
		copy(iv[:], sealed[offset:offset+16])
	}
	var next [16]byte
	copy(next[:], sealed[last-16:last])
	block.Decrypt(tmp[:], next[:])
	// Recover missing suffix of the stolen block from decrypted zero padding.
	for i, b := range sealed[last:] {
		out[last+i] = tmp[i] ^ b
		tmp[i] = b
	}
	block.Decrypt(out[last-16:last], tmp[:])
	for i := range iv {
		out[last-16+i] ^= iv[i]
	}
	return out, next
}
