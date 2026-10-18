// Package krbcrypto provides bounded AES message protection for the forthcoming
// Kerberos client. It implements RFC 3961/3962 and RFC 8009 key derivation,
// encryption and keyed checksums; it does not acquire or authenticate tickets.
package krbcrypto

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"sync"
)

type Enctype int32

const (
	AES128SHA1   Enctype = 17
	AES256SHA1   Enctype = 18
	AES128SHA256 Enctype = 19
	AES256SHA384 Enctype = 20
	// MaxMessage bounds plaintext, checksum input and ciphertext allocations.
	MaxMessage = 16 << 20
)

var (
	ErrInvalid   = errors.New("kerberos crypto: invalid type, key, usage or parameters")
	ErrLimit     = errors.New("kerberos crypto: resource limit exceeded")
	ErrIntegrity = errors.New("kerberos crypto: integrity verification failed")
)

type profile struct {
	keySize, macSize int
	sumType          int32
	name             string
	hash             func() hash.Hash
	sha2             bool
	iterations       uint32
}

func (e Enctype) profile() (profile, error) {
	switch e {
	case AES128SHA1:
		return profile{16, 12, 15, "aes128-cts-hmac-sha1-96", sha1.New, false, 4096}, nil
	case AES256SHA1:
		return profile{32, 12, 16, "aes256-cts-hmac-sha1-96", sha1.New, false, 4096}, nil
	case AES128SHA256:
		return profile{16, 16, 19, "aes128-cts-hmac-sha256-128", sha256.New, true, 32768}, nil
	case AES256SHA384:
		return profile{32, 24, 20, "aes256-cts-hmac-sha384-192", sha512.New384, true, 32768}, nil
	default:
		return profile{}, ErrInvalid
	}
}

// Key owns a copy of key material. Copies of Key share the same lifetime.
// Operations and Clear may run concurrently; Clear waits for in-flight users.
type Key struct{ material *keyMaterial }

type keyMaterial struct {
	mu     sync.RWMutex
	typeID Enctype
	value  []byte
}

func (Key) String() string   { return "[redacted Kerberos key]" }
func (Key) GoString() string { return "[redacted Kerberos key]" }

func NewKey(e Enctype, value []byte) (*Key, error) {
	p, err := e.profile()
	if err != nil || len(value) != p.keySize {
		return nil, ErrInvalid
	}
	return &Key{material: &keyMaterial{typeID: e, value: append([]byte(nil), value...)}}, nil
}

func (k *Key) Type() Enctype {
	if k == nil || k.material == nil {
		return 0
	}
	return k.material.typeID
}

// Bytes returns an owned secret copy, for encoding session/subkeys. Callers must
// clear it when no longer needed; neither logging nor String exposes this data.
func (k *Key) Bytes() []byte {
	if k == nil || k.material == nil {
		return nil
	}
	k.material.mu.RLock()
	defer k.material.mu.RUnlock()
	return append([]byte(nil), k.material.value...)
}

// Clear invalidates this key and best-effort clears its owned bytes. It cannot
// erase copies retained by the caller or the Go crypto/runtime internals.
func (k *Key) Clear() {
	if k == nil || k.material == nil {
		return
	}
	k.material.mu.Lock()
	defer k.material.mu.Unlock()
	clear(k.material.value)
	k.material.value = nil
}

func (k *Key) checked(usage uint32, length int) (profile, error) {
	p, err := k.material.typeID.profile()
	if err != nil || len(k.material.value) != p.keySize || usage == 0 {
		return profile{}, ErrInvalid
	}
	if length > MaxMessage {
		return profile{}, ErrLimit
	}
	return p, nil
}

// Encrypt protects one independent Kerberos message, using a fresh random
// confounder and the initial all-zero cipher state. It does not carry an IV
// between messages. Replay and sequence validation belong to the protocol layer.
func (k *Key) Encrypt(usage uint32, plaintext []byte) ([]byte, error) {
	return k.encrypt(usage, plaintext, rand.Reader)
}

func (k *Key) encrypt(usage uint32, plaintext []byte, random io.Reader) ([]byte, error) {
	if k == nil || k.material == nil {
		return nil, ErrInvalid
	}
	k.material.mu.RLock()
	defer k.material.mu.RUnlock()
	p, err := k.checked(usage, len(plaintext))
	if err != nil {
		return nil, err
	}
	var confounder [aes.BlockSize]byte
	defer clear(confounder[:])
	if _, err = io.ReadFull(random, confounder[:]); err != nil {
		return nil, err
	}
	plain := make([]byte, aes.BlockSize+len(plaintext))
	defer clear(plain)
	copy(plain, confounder[:])
	copy(plain[aes.BlockSize:], plaintext)
	ke := p.derive(k.material.value, usage, 0xaa)
	defer clear(ke)
	ki := p.derive(k.material.value, usage, 0x55)
	defer clear(ki)
	block, err := aes.NewCipher(ke)
	if err != nil {
		return nil, err
	}
	sealed, _ := encryptCTS(block, [aes.BlockSize]byte{}, plain)
	var sum []byte
	if p.sha2 {
		var iv [aes.BlockSize]byte
		sum = mac(p, ki, iv[:], sealed)
	} else {
		sum = mac(p, ki, plain)
	}
	defer clear(sum)
	return append(sealed, sum[:p.macSize]...), nil
}

// Decrypt returns no plaintext on an invalid size, key usage, key or tag. The
// SHA-2 profiles authenticate before decryption; SHA-1 authenticates a private
// temporary plaintext and clears it on every return. Input buffers are untouched.
func (k *Key) Decrypt(usage uint32, ciphertext []byte) ([]byte, error) {
	if k == nil || k.material == nil {
		return nil, ErrInvalid
	}
	k.material.mu.RLock()
	defer k.material.mu.RUnlock()
	p, err := k.checked(usage, 0)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize+p.macSize {
		return nil, ErrIntegrity
	}
	if len(ciphertext) > MaxMessage+aes.BlockSize+p.macSize {
		return nil, ErrLimit
	}
	sealed, tag := ciphertext[:len(ciphertext)-p.macSize], ciphertext[len(ciphertext)-p.macSize:]
	ki := p.derive(k.material.value, usage, 0x55)
	defer clear(ki)
	if p.sha2 {
		var iv [aes.BlockSize]byte
		sum := mac(p, ki, iv[:], sealed)
		valid := hmac.Equal(tag, sum[:p.macSize])
		clear(sum)
		if !valid {
			return nil, ErrIntegrity
		}
	}
	ke := p.derive(k.material.value, usage, 0xaa)
	defer clear(ke)
	block, err := aes.NewCipher(ke)
	if err != nil {
		return nil, err
	}
	plain, _ := decryptCTS(block, [aes.BlockSize]byte{}, sealed)
	defer clear(plain)
	if !p.sha2 {
		sum := mac(p, ki, plain)
		valid := hmac.Equal(tag, sum[:p.macSize])
		clear(sum)
		if !valid {
			return nil, ErrIntegrity
		}
	}
	out := make([]byte, len(plain)-aes.BlockSize)
	copy(out, plain[aes.BlockSize:])
	return out, nil
}

func (k *Key) ChecksumType() int32 {
	if k == nil || k.material == nil {
		return 0
	}
	p, _ := k.material.typeID.profile()
	return p.sumType
}

func (k *Key) Checksum(usage uint32, data []byte) ([]byte, error) {
	if k == nil || k.material == nil {
		return nil, ErrInvalid
	}
	k.material.mu.RLock()
	defer k.material.mu.RUnlock()
	p, err := k.checked(usage, len(data))
	if err != nil {
		return nil, err
	}
	kc := p.derive(k.material.value, usage, 0x99)
	defer clear(kc)
	sum := mac(p, kc, data)
	defer clear(sum)
	return append([]byte(nil), sum[:p.macSize]...), nil
}

func (k *Key) VerifyChecksum(usage uint32, data, signature []byte) error {
	sum, err := k.Checksum(usage, data)
	if err != nil {
		return err
	}
	defer clear(sum)
	if !hmac.Equal(sum, signature) {
		return ErrIntegrity
	}
	return nil
}

func mac(p profile, key []byte, parts ...[]byte) []byte {
	h := hmac.New(p.hash, key)
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

func (p profile) derive(key []byte, usage uint32, purpose byte) []byte {
	var label [5]byte
	binary.BigEndian.PutUint32(label[:], usage)
	label[4] = purpose
	if !p.sha2 {
		return deriveAES(key, label[:])
	}
	size := p.keySize
	if purpose != 0xaa {
		size = p.macSize
	}
	return kdfSHA2(p, key, label[:], size)
}
