package krbcrypto

import (
	"context"
	"crypto/aes"
	"crypto/hmac"
	"encoding/binary"
	"unicode/utf8"
)

const (
	// MaxIterations is the default KDC-provided PBKDF2 work limit. Zero on the
	// wire means 2^32, not zero work or a default; it exceeds this limit.
	MaxIterations    uint32 = 1 << 20
	MaxPasswordBytes        = 1 << 16
	MaxSaltBytes            = 1 << 16
)

// StringToKey uses KDC-selected salt and opaque parameters. Nil parameters mean
// the profile default; a present empty field is malformed. A zero workLimit uses
// MaxIterations. Callers may lower the limit but cannot exceed the hard ceiling.
// Password is valid UTF-8 and is not normalized; salt is an opaque octet string.
// The caller must authenticate the KDC reply before trusting a derived key.
func StringToKey(ctx context.Context, e Enctype, password string, salt, params []byte, workLimit uint32) (*Key, error) {
	p, err := e.profile()
	if err != nil || ctx == nil {
		return nil, ErrInvalid
	}
	if len(password) > MaxPasswordBytes || len(salt) > MaxSaltBytes {
		return nil, ErrLimit
	}
	if !utf8.ValidString(password) {
		return nil, ErrInvalid
	}
	iterations := p.iterations
	if params != nil {
		if len(params) != 4 {
			return nil, ErrInvalid
		}
		iterations = binary.BigEndian.Uint32(params)
	}
	if workLimit == 0 {
		workLimit = MaxIterations
	}
	if workLimit > MaxIterations || iterations == 0 || iterations > workLimit {
		return nil, ErrLimit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var inputSalt []byte
	if p.sha2 {
		inputSalt = append(append([]byte(p.name), 0), salt...)
	} else {
		inputSalt = append([]byte(nil), salt...)
	}
	defer clear(inputSalt)
	pass := []byte(password)
	defer clear(pass)
	seed, err := pbkdf2(ctx, p, pass, inputSalt, iterations)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	var value []byte
	if p.sha2 {
		value = kdfSHA2(p, seed, []byte("kerberos"), p.keySize)
	} else {
		value = deriveAES(seed, []byte("kerberos"))
	}
	if err := ctx.Err(); err != nil {
		clear(value)
		return nil, err
	}
	return &Key{material: &keyMaterial{typeID: e, value: value}}, nil
}

// A cancellable PBKDF2 using standard-library HMAC. Work is checked every 256
// iterations, including block boundaries; no partial key escapes cancellation.
func pbkdf2(ctx context.Context, p profile, password, salt []byte, iterations uint32) ([]byte, error) {
	h := hmac.New(p.hash, password)
	out := make([]byte, 0, p.keySize+h.Size())
	defer clear(out[:cap(out)])
	var counter [4]byte
	u := make([]byte, 0, h.Size())
	defer clear(u[:cap(u)])
	t := make([]byte, h.Size())
	defer clear(t)
	for block := uint32(1); len(out) < p.keySize; block++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h.Reset()
		h.Write(salt)
		binary.BigEndian.PutUint32(counter[:], block)
		h.Write(counter[:])
		u = h.Sum(u[:0])
		copy(t, u)
		for i := uint32(1); i < iterations; i++ {
			if i&255 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			h.Reset()
			h.Write(u)
			u = h.Sum(u[:0])
			for j, b := range u {
				t[j] ^= b
			}
		}
		out = append(out, t...)
	}
	return append([]byte(nil), out[:p.keySize]...), nil
}

func kdfSHA2(p profile, key, label []byte, size int) []byte {
	var bits [4]byte
	binary.BigEndian.PutUint32(bits[:], uint32(size*8))
	sum := mac(p, key, []byte{0, 0, 0, 1}, label, []byte{0}, bits[:])
	defer clear(sum)
	return append([]byte(nil), sum[:size]...)
}

func deriveAES(key, constant []byte) []byte {
	block, _ := aes.NewCipher(key) // only validated 128/256-bit keys reach here
	seed := nFold(constant, 16)
	defer clear(seed)
	out := make([]byte, 0, len(key))
	for len(out) < len(key) {
		block.Encrypt(seed, seed)
		out = append(out, seed...)
	}
	return out[:len(key)]
}

// nFold operates only on fixed derivation constants, not untrusted network
// lengths. Repeated copies rotate right by 13 bits; big-endian chunks are added
// with end-around carry. Tests also exercise the RFC's non-AES output widths.
func nFold(input []byte, size int) []byte {
	a, b := len(input), size
	for b != 0 {
		a, b = b, a%b
	}
	length := len(input) / a * size
	result := make([]byte, size)
	chunk := make([]byte, size)
	defer clear(chunk)
	bits := len(input) * 8
	for offset := 0; offset < length; offset++ {
		rotation := 13 * (offset / len(input)) % bits
		var value byte
		for bit := 0; bit < 8; bit++ {
			index := (offset%len(input)*8 + bit - rotation + bits) % bits
			value = value<<1 | (input[index/8]>>uint(7-index%8))&1
		}
		chunk[offset%size] = value
		if offset%size != size-1 {
			continue
		}
		carry := 0
		for i := size - 1; i >= 0; i-- {
			v := int(result[i]) + int(chunk[i]) + carry
			result[i] = byte(v)
			carry = v >> 8
		}
		for carry != 0 {
			for i := size - 1; i >= 0; i-- {
				v := int(result[i]) + carry
				result[i] = byte(v)
				carry = v >> 8
			}
		}
	}
	return result
}
