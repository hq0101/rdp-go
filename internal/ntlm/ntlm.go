// Package ntlm implements NTLMv2 for CredSSP (extended session security,
// 128-bit keys, MIC and signing/sealing) and a separate TLS-protected HTTP profile.
package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	unicodeFlag   uint32 = 1
	requestTarget uint32 = 4
	sign          uint32 = 0x10
	seal          uint32 = 0x20
	ntlmFlag      uint32 = 0x200
	alwaysSign    uint32 = 0x8000
	extended      uint32 = 0x80000
	targetInfo    uint32 = 0x800000
	versionFlag   uint32 = 0x2000000
	key128        uint32 = 0x20000000
	keyExchange   uint32 = 0x40000000
	required             = unicodeFlag | sign | seal | ntlmFlag | extended | targetInfo | key128
	offered              = required | requestTarget | alwaysSign | versionFlag | keyExchange
)

var ErrInvalid = errors.New("ntlm: invalid or unsupported message")

type Credentials struct{ Username, Domain, Password string }

func (Credentials) String() string   { return "[redacted credentials]" }
func (Credentials) GoString() string { return "[redacted credentials]" }

func (c Credentials) Validate() error {
	if c.Username == "" {
		return errors.New("ntlm: username is required")
	}
	for _, s := range []string{c.Username, c.Domain, c.Password} {
		if !utf8.ValidString(s) || strings.ContainsRune(s, 0) || len(UTF16(s)) > 4096 {
			return errors.New("ntlm: invalid or oversized credentials")
		}
	}
	return nil
}

func UTF16(s string) []byte {
	var b []byte
	for _, v := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, v)
	}
	return b
}
func mac(key []byte, parts ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
func responseKey(c Credentials) []byte {
	h := md4sum(UTF16(c.Password))
	return mac(h[:], UTF16(strings.ToUpper(c.Username)+c.Domain))
}

func Negotiate() []byte {
	b := make([]byte, 40)
	copy(b, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], offered)
	copy(b[32:], []byte{10, 0, 0, 0, 0, 0, 0, 15})
	return b
}

type pair struct {
	id    uint16
	value []byte
}
type Challenge struct {
	http    bool
	httpMIC bool
	raw     []byte
	flags   uint32
	nonce   [8]byte
	pairs   []pair
}

func securityBuffer(b []byte, offset, min int) ([]byte, error) {
	if offset < 0 || offset+8 > len(b) {
		return nil, ErrInvalid
	}
	n := uint64(binary.LittleEndian.Uint16(b[offset:]))
	p := uint64(binary.LittleEndian.Uint32(b[offset+4:]))
	if n == 0 {
		return nil, nil
	}
	if p < uint64(min) || p+n > uint64(len(b)) {
		return nil, ErrInvalid
	}
	return b[p : p+n], nil
}

func ParseChallenge(b []byte) (*Challenge, error) {
	return parseChallenge(b, required, true, false)
}

func parseChallenge(b []byte, requiredFlags uint32, requireNames, httpProfile bool) (*Challenge, error) {
	if len(b) < 48 || len(b) > 65536 || !bytes.Equal(b[:8], []byte("NTLMSSP\x00")) || binary.LittleEndian.Uint32(b[8:]) != 2 {
		return nil, ErrInvalid
	}
	c := &Challenge{http: httpProfile, raw: append([]byte{}, b...), flags: binary.LittleEndian.Uint32(b[20:])}
	if c.flags&requiredFlags != requiredFlags {
		return nil, fmt.Errorf("%w: required NTLMv2 security flags absent", ErrInvalid)
	}
	min := 48
	if c.flags&versionFlag != 0 {
		min = 56
	}
	if len(b) < min {
		return nil, ErrInvalid
	}
	if _, err := securityBuffer(b, 12, min); err != nil {
		return nil, err
	}
	copy(c.nonce[:], b[24:32])
	av, err := securityBuffer(c.raw, 40, min)
	if err != nil {
		return nil, err
	}
	seen := map[uint16]bool{}
	for len(av) >= 4 {
		id, n := binary.LittleEndian.Uint16(av), int(binary.LittleEndian.Uint16(av[2:]))
		av = av[4:]
		if n > len(av) || seen[id] {
			return nil, ErrInvalid
		}
		seen[id] = true
		if id == 0 {
			if n != 0 || len(av) != 0 || (requireNames && (!seen[1] || !seen[2])) {
				return nil, ErrInvalid
			}
			return c, nil
		}
		if (id == 6 && n != 4) || (id == 7 && n != 8) || (id == 10 && n != 16) || ((id <= 5 || id == 9) && n%2 != 0) {
			return nil, ErrInvalid
		}
		c.pairs = append(c.pairs, pair{id, av[:n]})
		av = av[n:]
	}
	return nil, ErrInvalid
}

// Authenticate creates the Type 3 token and the client's session security state.
// channelBinding must be the 16-byte GSS channel-binding hash derived from TLS.
func Authenticate(c Credentials, negotiate []byte, challenge *Challenge, target string, channelBinding []byte) ([]byte, *Security, error) {
	if err := c.Validate(); err != nil {
		return nil, nil, err
	}
	if challenge == nil || challenge.http || !bytes.Equal(negotiate, Negotiate()) || len(channelBinding) != 16 {
		return nil, nil, ErrInvalid
	}
	if !utf8.ValidString(target) || strings.ContainsRune(target, 0) || len(UTF16(target)) > 4096 {
		return nil, nil, ErrInvalid
	}
	var nonce [8]byte
	var exported [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(exported[:]); err != nil {
		return nil, nil, err
	}
	return authenticate(c, negotiate, challenge, target, channelBinding, nonce, exported, time.Now())
}

func authenticate(c Credentials, neg []byte, ch *Challenge, target string, cb []byte, nonce [8]byte, exported [16]byte, now time.Time) ([]byte, *Security, error) {
	return authenticateProfile(c, neg, ch, target, cb, nonce, exported, now, offered, true)
}

func authenticateProfile(c Credentials, neg []byte, ch *Challenge, target string, cb []byte, nonce [8]byte, exported [16]byte, now time.Time, offer uint32, protect bool) ([]byte, *Security, error) {
	chosen := ch.flags & offer
	var av []byte
	var timestamp []byte
	flags := uint32(2)
	for _, p := range ch.pairs {
		switch p.id {
		case 6:
			flags |= binary.LittleEndian.Uint32(p.value)
			continue
		case 7:
			timestamp = p.value
		case 9, 10:
			continue
		}
		av = appendPair(av, p.id, p.value)
	}
	av = appendPair(av, 6, binary.LittleEndian.AppendUint32(nil, flags))
	av = appendPair(av, 9, UTF16(target))
	av = appendPair(av, 10, cb)
	av = append(av, 0, 0, 0, 0)
	if len(av) > 60000 {
		return nil, nil, ErrInvalid
	}
	hasTime := timestamp != nil
	if !hasTime {
		timestamp = binary.LittleEndian.AppendUint64(nil, uint64(now.Unix()+11644473600)*10000000+uint64(now.Nanosecond()/100))
	}
	blob := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	blob = append(blob, timestamp...)
	blob = append(blob, nonce[:]...)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, av...)
	blob = append(blob, 0, 0, 0, 0)
	key := responseKey(c)
	proof := mac(key, ch.nonce[:], blob)
	nt := append(append([]byte{}, proof...), blob...)
	lm := make([]byte, 24)
	if !hasTime {
		copy(lm, mac(key, ch.nonce[:], nonce[:]))
		copy(lm[16:], nonce[:])
	}
	base := mac(key, proof)
	var encryptedKey []byte
	if chosen&keyExchange != 0 && chosen&(sign|seal) != 0 {
		cipher, _ := rc4.NewCipher(base)
		encryptedKey = make([]byte, 16)
		cipher.XORKeyStream(encryptedKey, exported[:])
	} else {
		copy(exported[:], base)
	}
	b := make([]byte, 88)
	copy(b, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 3)
	fields := [][]byte{lm, nt, UTF16(c.Domain), UTF16(c.Username), nil, encryptedKey}
	for i, p := range fields {
		off := 12 + i*8
		binary.LittleEndian.PutUint16(b[off:], uint16(len(p)))
		binary.LittleEndian.PutUint16(b[off+2:], uint16(len(p)))
		binary.LittleEndian.PutUint32(b[off+4:], uint32(len(b)))
		b = append(b, p...)
	}
	binary.LittleEndian.PutUint32(b[60:], chosen)
	if chosen&versionFlag != 0 {
		copy(b[64:], []byte{10, 0, 0, 0, 0, 0, 0, 15})
	}
	copy(b[72:88], mac(exported[:], neg, ch.raw, b))
	var security *Security
	if protect {
		security = NewSecurity(exported, chosen&keyExchange != 0)
	}
	clear(key)
	clear(base)
	clear(exported[:])
	return b, security, nil
}

func appendPair(b []byte, id uint16, v []byte) []byte {
	b = binary.LittleEndian.AppendUint16(b, id)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}
