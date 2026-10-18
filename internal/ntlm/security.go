package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
)

type direction struct {
	signing  [16]byte
	cipher   *rc4.Cipher
	sequence uint32
}

// Security is connection-oriented, stateful and not safe for concurrent calls.
type Security struct {
	send, recv           direction
	exchange             bool
	failed               bool
	sentMIC, verifiedMIC bool
}

// MechListMIC signs the DER mechanism list for SPNEGO, before application data.
// MS-SPNG 3.3.5.1 requires retaining the RC4 state for the first sealed message.
// The signature consumes sequence zero; only the RC4 stream state is restored.
func (s *Security) MechListMIC(list []byte) ([]byte, error) {
	if s.failed || s.sentMIC || s.send.sequence != 0 {
		return nil, ErrInvalid
	}
	s.sentMIC = true
	s.send.sequence++
	return s.mechanismSignature(s.send, list), nil
}

// VerifyMechListMIC fails the security context on an invalid/repeated signature.
// It must precede Unseal; it advances the sequence but preserves the RC4 stream.
func (s *Security) VerifyMechListMIC(list, signature []byte) error {
	if s.failed || s.verifiedMIC || s.recv.sequence != 0 || !hmac.Equal(signature, s.mechanismSignature(s.recv, list)) {
		s.failed = true
		return errors.New("ntlm: mechanism list signature verification failed")
	}
	s.verifiedMIC = true
	s.recv.sequence++
	return nil
}

func (s *Security) mechanismSignature(d direction, list []byte) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b, 1)
	checksum := mac(d.signing[:], b[12:], list)[:8]
	if s.exchange {
		copyCipher := *d.cipher
		copyCipher.XORKeyStream(checksum, checksum)
		copyCipher.Reset()
	}
	copy(b[4:12], checksum)
	return b
}

func derive(key [16]byte, magic string) [16]byte {
	b := append(append([]byte{}, key[:]...), []byte("session key to "+magic+" magic constant\x00")...)
	return md5.Sum(b)
}
func NewSecurity(key [16]byte, exchange bool) *Security {
	makeDirection := func(prefix string) direction {
		sealKey := derive(key, prefix+" sealing key")
		cipher, _ := rc4.NewCipher(sealKey[:])
		return direction{signing: derive(key, prefix+" signing key"), cipher: cipher}
	}
	return &Security{send: makeDirection("client-to-server"), recv: makeDirection("server-to-client"), exchange: exchange}
}

func (s *Security) Seal(p []byte) ([]byte, error) {
	if s.failed || s.send.sequence == ^uint32(0) {
		return nil, errors.New("ntlm: unusable security context")
	}
	d := &s.send
	seq := binary.LittleEndian.AppendUint32(nil, d.sequence)
	checksum := mac(d.signing[:], seq, p)[:8]
	out := make([]byte, 16+len(p))
	binary.LittleEndian.PutUint32(out, 1)
	d.cipher.XORKeyStream(out[16:], p)
	if s.exchange {
		d.cipher.XORKeyStream(checksum, checksum)
	}
	copy(out[4:12], checksum)
	copy(out[12:16], seq)
	d.sequence++
	return out, nil
}

func (s *Security) Unseal(b []byte) ([]byte, error) {
	if s.failed {
		return nil, errors.New("ntlm: unusable security context")
	}
	d := &s.recv
	if len(b) < 16 || binary.LittleEndian.Uint32(b) != 1 || binary.LittleEndian.Uint32(b[12:]) != d.sequence || d.sequence == ^uint32(0) {
		s.failed = true
		return nil, ErrInvalid
	}
	p := make([]byte, len(b)-16)
	d.cipher.XORKeyStream(p, b[16:])
	checksum := mac(d.signing[:], b[12:16], p)[:8]
	if s.exchange {
		d.cipher.XORKeyStream(checksum, checksum)
	}
	if !hmac.Equal(checksum, b[4:12]) {
		s.failed = true
		clear(p)
		return nil, errors.New("ntlm: signature verification failed")
	}
	d.sequence++
	return p, nil
}
