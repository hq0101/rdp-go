package ntlm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf8"
)

// SPNEGO requests integrity for mechListMIC (RFC4178 section3). TLS still
// protects HTTP data. No NTLM sealing or key exchange is offered. The signing
// key is derived from the complete NTLMv2 session key; 128-bit sealing flags
// do not determine the signing-key derivation (MS-NLMP 3.4.5.2).
const httpMICOffered = httpOffered | sign

func NegotiateHTTPMIC() []byte {
	b := NegotiateHTTP()
	binary.LittleEndian.PutUint32(b[12:], httpMICOffered)
	return b
}

func ParseHTTPMICChallenge(b []byte) (*Challenge, error) {
	c, err := parseChallenge(b, httpRequired|sign, true, true)
	if err != nil {
		return nil, err
	}
	if c.flags&(seal|keyExchange) != 0 {
		return nil, ErrInvalid
	}
	c.httpMIC = true
	return c, nil
}

// HTTPMICSecurity exposes only SPNEGO list MICs, never HTTP payload sealing.
// It is serial, single-exchange state. Close erases retained derived keys and
// permanently disables this context. Raw HTTP and CredSSP use separate profiles.
type HTTPMICSecurity struct{ security *Security }

func (s *HTTPMICSecurity) MechListMIC(list []byte) ([]byte, error) {
	if s == nil || s.security == nil {
		return nil, ErrInvalid
	}
	return s.security.MechListMIC(list)
}
func (s *HTTPMICSecurity) VerifyMechListMIC(list, mic []byte) error {
	if s == nil || s.security == nil {
		return ErrInvalid
	}
	return s.security.VerifyMechListMIC(list, mic)
}
func (s *HTTPMICSecurity) Close() {
	if s == nil || s.security == nil {
		return
	}
	x := s.security
	clear(x.send.signing[:])
	clear(x.recv.signing[:])
	if x.send.cipher != nil {
		x.send.cipher.Reset()
	}
	if x.recv.cipher != nil {
		x.recv.cipher.Reset()
	}
	x.failed = true
	s.security = nil
}
func (*HTTPMICSecurity) String() string   { return "ntlm.HTTPMICSecurity{private keys}" }
func (*HTTPMICSecurity) GoString() string { return "ntlm.HTTPMICSecurity{private keys}" }

func AuthenticateHTTPMIC(c Credentials, negotiate []byte, ch *Challenge, target string, cb []byte) ([]byte, *HTTPMICSecurity, error) {
	if err := c.Validate(); err != nil {
		return nil, nil, err
	}
	if ch == nil || !ch.http || !ch.httpMIC || !bytes.Equal(negotiate, NegotiateHTTPMIC()) || len(cb) != 16 {
		return nil, nil, ErrInvalid
	}
	if target == "" || !utf8.ValidString(target) || strings.ContainsRune(target, 0) || len(UTF16(target)) > 4096 {
		return nil, nil, ErrInvalid
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}
	b, s, err := authenticateProfile(c, negotiate, ch, target, cb, nonce, [16]byte{}, time.Now(), httpMICOffered, true)
	if err != nil {
		return nil, nil, err
	}
	return b, &HTTPMICSecurity{security: s}, nil
}
