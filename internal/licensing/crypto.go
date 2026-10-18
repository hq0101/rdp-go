package licensing

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"math/big"
	"slices"
)

// These legacy primitives are required by MS-RDPELE, even inside TLS. They do
// not replace TLS authentication or provide a general-purpose crypto API.
type keys struct {
	redacted
	mac, encryption [16]byte
}

// Go's FIPS-only policy is fixed at process startup. Check before deriving any
// MD5 material; otherwise those primitives can panic instead of returning errors.
func cryptoAvailable() error {
	var key [16]byte
	c, err := rc4.NewCipher(key[:])
	if err != nil {
		return ErrCrypto
	}
	c.Reset()
	return nil
}

func derive(premaster [48]byte, client, server [32]byte) keys {
	salted := func(secret, label, first, second []byte) []byte {
		h := sha1.New()
		h.Write(label)
		h.Write(secret)
		h.Write(first)
		h.Write(second)
		middle := h.Sum(nil)
		defer clear(middle)
		m := md5.New()
		m.Write(secret)
		m.Write(middle)
		return m.Sum(nil)
	}
	var master, session [48]byte
	defer clear(master[:])
	defer clear(session[:])
	defer clear(premaster[:])
	for i, label := range []string{"A", "BB", "CCC"} {
		b := salted(premaster[:], []byte(label), client[:], server[:])
		copy(master[i*16:], b)
		clear(b)
	}
	for i, label := range []string{"A", "BB", "CCC"} {
		b := salted(master[:], []byte(label), server[:], client[:])
		copy(session[i*16:], b)
		clear(b)
	}
	var k keys
	copy(k.mac[:], session[:16])
	m := md5.New()
	m.Write(session[16:32])
	m.Write(client[:])
	m.Write(server[:])
	copy(k.encryption[:], m.Sum(nil))
	return k
}
func (k *keys) clear() { clear(k.mac[:]); clear(k.encryption[:]) }
func (k *keys) checksum(parts ...[]byte) [16]byte {
	var n uint32
	for _, p := range parts {
		n += uint32(len(p))
	}
	h := sha1.New()
	h.Write(k.mac[:])
	h.Write(bytes.Repeat([]byte{0x36}, 40))
	h.Write(binary.LittleEndian.AppendUint32(nil, n))
	for _, p := range parts {
		h.Write(p)
	}
	digest := h.Sum(nil)
	defer clear(digest)
	m := md5.New()
	m.Write(k.mac[:])
	m.Write(bytes.Repeat([]byte{0x5c}, 48))
	m.Write(digest)
	var out [16]byte
	copy(out[:], m.Sum(nil))
	return out
}
func (k *keys) crypt(b []byte) []byte {
	c, _ := rc4.NewCipher(k.encryption[:])
	defer c.Reset()
	out := make([]byte, len(b))
	c.XORKeyStream(out, b)
	return out
}
func (k *keys) open(b []byte, mac [16]byte) ([]byte, error) {
	out := k.crypt(b)
	want := k.checksum(out)
	if subtle.ConstantTimeCompare(mac[:], want[:]) != 1 {
		clear(out)
		return nil, ErrMAC
	}
	return out, nil
}

// RDP uses raw little-endian RSA, not PKCS#1 v1.5 or OAEP, followed by eight
// zero wire-padding bytes. Restrict public exponent and modulus work before Exp.
func encryptPremaster(key *rsa.PublicKey, secret [48]byte) ([]byte, error) {
	defer clear(secret[:])
	if !validRSA(key) {
		return nil, ErrKey
	}
	slices.Reverse(secret[:])
	plain := new(big.Int).SetBytes(secret[:])
	defer clear(plain.Bits())
	n := new(big.Int).Set(key.N)
	exponent := big.NewInt(int64(key.E))
	out := new(big.Int).Exp(plain, exponent, n)
	defer clear(out.Bits())
	b := make([]byte, (key.N.BitLen()+7)/8+8)
	out.FillBytes(b[:len(b)-8])
	slices.Reverse(b[:len(b)-8])
	return b, nil
}
