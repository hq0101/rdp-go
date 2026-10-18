package ntlm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf8"
)

// The HTTP profile uses verified TLS for confidentiality and integrity. Do not
// negotiate NTLM signing/sealing or key exchange; still use NTLMv2, target info,
// a transcript MIC and TLS channel binding. CredSSP's required flags are intact.
const httpRequired = unicodeFlag | ntlmFlag | extended | targetInfo
const httpOffered = httpRequired | requestTarget | alwaysSign | versionFlag

func NegotiateHTTP() []byte {
	b := Negotiate()
	binary.LittleEndian.PutUint32(b[12:], httpOffered)
	return b
}

func ParseHTTPChallenge(b []byte) (*Challenge, error) {
	c, err := parseChallenge(b, httpRequired, false, true)
	if err != nil {
		return nil, err
	}
	// A server must not select unoffered message protection. Other server-only
	// or informational flags are intersected with the explicit client offer.
	if c.flags&(sign|seal|keyExchange) != 0 {
		return nil, ErrInvalid
	}
	return c, nil
}

// AuthenticateHTTP requires an authenticated TLS connection at the caller.
// target is its HTTP SPN; cb is the 16-byte tls-server-end-point GSS binding hash.
// It returns only a Type 3 token, never an NTLM message-protection context.
func AuthenticateHTTP(c Credentials, negotiate []byte, ch *Challenge, target string, cb []byte) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if ch == nil || !ch.http || ch.httpMIC || !bytes.Equal(negotiate, NegotiateHTTP()) || len(cb) != 16 {
		return nil, ErrInvalid
	}
	if target == "" || !utf8.ValidString(target) || strings.ContainsRune(target, 0) || len(UTF16(target)) > 4096 {
		return nil, ErrInvalid
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	b, _, err := authenticateProfile(c, negotiate, ch, target, cb, nonce, [16]byte{}, time.Now(), httpOffered, false)
	return b, err
}
