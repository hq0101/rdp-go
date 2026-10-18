package pdu

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf16"
)

// RedirectionPDU is an Enhanced Security Server Redirection share-control type.
// Its version is zero, unlike the normal version-one share-control PDUs.
const RedirectionPDU uint16 = 10

type RedirectionFlags uint32

const (
	RedirectTargetAddress       RedirectionFlags = 0x0001
	RedirectLoadBalanceInfo     RedirectionFlags = 0x0002
	RedirectUsername            RedirectionFlags = 0x0004
	RedirectDomain              RedirectionFlags = 0x0008
	RedirectPassword            RedirectionFlags = 0x0010
	RedirectDontStoreUsername   RedirectionFlags = 0x0020
	RedirectSmartcard           RedirectionFlags = 0x0040
	RedirectInformationOnly     RedirectionFlags = 0x0080
	RedirectTargetFQDN          RedirectionFlags = 0x0100
	RedirectTargetNetBIOS       RedirectionFlags = 0x0200
	RedirectTargetAddresses     RedirectionFlags = 0x0800
	RedirectTSVURL              RedirectionFlags = 0x1000
	RedirectServerTSVCapable    RedirectionFlags = 0x2000
	RedirectPasswordPKEncrypted RedirectionFlags = 0x4000
	RedirectGUID                RedirectionFlags = 0x8000
	RedirectCertificate         RedirectionFlags = 0x10000
)

var ErrRedirectionCleared = errors.New("rdp: redirection material has been cleared")

// RedirectionInfo contains metadata only. Flags distinguish absent fields from
// present empty fields. Addresses/names are server assertions, not authorization
// to connect or to trust a different TLS identity. Passwords and routing tokens
// are only available through the explicit Field method on Redirection.
type RedirectionInfo struct {
	SessionID                                           uint32
	Flags                                               RedirectionFlags
	TargetAddress, TargetFQDN, TargetNetBIOS            string
	Username, Domain                                    string
	TargetAddresses                                     []string
	LoadBalanceInfoLength, PasswordLength, TSVURLLength int
}

// Redirection owns potentially confidential server data. Value copies share
// its lifetime. Clear invalidates them and erases owned wire buffers. Metadata
// strings and copies returned to callers cannot be erased by the library.
// Methods are safe concurrently. Neither parsing nor access makes connections.
type Redirection struct{ state *redirectionState }
type redirectionState struct {
	mu     sync.RWMutex
	raw    []byte
	info   RedirectionInfo
	fields map[RedirectionFlags][]byte
}

func (Redirection) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "[redacted server redirection]")
}
func (Redirection) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted server redirection]"`), nil
}

func (r *Redirection) Clear() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.raw)
	s.raw = nil
	s.fields = nil
	s.info = RedirectionInfo{}
}
func (r *Redirection) Info() (RedirectionInfo, error) {
	if r == nil || r.state == nil {
		return RedirectionInfo{}, ErrRedirectionCleared
	}
	s := r.state
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.raw == nil {
		return RedirectionInfo{}, ErrRedirectionCleared
	}
	i := s.info
	i.TargetAddresses = append([]string(nil), i.TargetAddresses...)
	return i, nil
}

// Field returns an owned copy of one optional wire field, including Unicode
// terminators. A present empty value is distinguished by Info.Flags. Password
// bytes are preserved exactly, including legacy opaque server cookies; never
// assume they are a password string or send them as CredSSP credentials.
// LoadBalanceInfo is opaque and may be sent before TLS as an X.224 routing token
// only when the caller's redirection policy authorizes that destination.
func (r *Redirection) Field(flag RedirectionFlags) ([]byte, error) {
	if r == nil || r.state == nil {
		return nil, ErrRedirectionCleared
	}
	s := r.state
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.raw == nil {
		return nil, ErrRedirectionCleared
	}
	if !redirectionField(flag) {
		return nil, ErrInvalid
	}
	b := s.fields[flag]
	if b == nil {
		return nil, nil
	}
	return append([]byte{}, b...), nil
}

var redirectionFields = [...]RedirectionFlags{RedirectTargetAddress, RedirectLoadBalanceInfo, RedirectUsername, RedirectDomain, RedirectPassword, RedirectTargetFQDN, RedirectTargetNetBIOS, RedirectTSVURL, RedirectGUID, RedirectCertificate, RedirectTargetAddresses}

func redirectionField(flag RedirectionFlags) bool {
	for _, v := range redirectionFields {
		if flag == v {
			return true
		}
	}
	return false
}

// ParseRedirection consumes the body of a version-zero enhanced-security share,
// including two ignored pad bytes and at most one optional trailing pad byte.
// The caller must receive it through verified external security (normally TLS).
func ParseRedirection(s Share) (*Redirection, error) {
	if s.Type != RedirectionPDU || len(s.Body) < 14 {
		return nil, ErrInvalid
	}
	b := s.Body[2:]
	n := int(binary.LittleEndian.Uint16(b[2:]))
	if n < 12 || n > len(b) || len(b)-n > 1 {
		return nil, ErrInvalid
	}
	return ParseRedirectionPacket(b[:n])
}

// ParseRedirectionPacket parses the inner RDP_SERVER_REDIRECTION_PACKET. It
// owns a copy, bounds all fields to its 16-bit packet length, and does not erase
// the caller's buffer. Unknown flags and malformed nested lengths are rejected.
func ParseRedirectionPacket(b []byte) (result *Redirection, err error) {
	if len(b) < 12 || len(b) > 65535 || binary.LittleEndian.Uint16(b) != 0x400 || int(binary.LittleEndian.Uint16(b[2:])) != len(b) {
		return nil, ErrInvalid
	}
	flags := RedirectionFlags(binary.LittleEndian.Uint32(b[8:]))
	if flags & ^RedirectionFlags(0x1fbff) != 0 {
		return nil, ErrInvalid
	}
	if flags&RedirectPasswordPKEncrypted != 0 && flags&RedirectPassword == 0 {
		return nil, ErrInvalid
	}
	if flags&RedirectDontStoreUsername != 0 && flags&RedirectUsername == 0 {
		return nil, ErrInvalid
	}
	raw := append([]byte(nil), b...)
	defer func() {
		if err != nil {
			clear(raw)
		}
	}()
	s := &redirectionState{raw: raw, info: RedirectionInfo{SessionID: binary.LittleEndian.Uint32(raw[4:]), Flags: flags}, fields: map[RedirectionFlags][]byte{}}
	input := raw[12:]
	for _, flag := range redirectionFields {
		if flags&flag == 0 {
			continue
		}
		value, e := redirectBytes(&input)
		if e != nil {
			return nil, e
		}
		s.fields[flag] = value
	}
	if len(input) != 0 && len(input) != 8 {
		return nil, ErrInvalid
	}
	for _, pair := range []struct {
		flag RedirectionFlags
		dst  *string
	}{{RedirectTargetAddress, &s.info.TargetAddress}, {RedirectUsername, &s.info.Username}, {RedirectDomain, &s.info.Domain}, {RedirectTargetFQDN, &s.info.TargetFQDN}, {RedirectTargetNetBIOS, &s.info.TargetNetBIOS}} {
		if flags&pair.flag != 0 {
			v, e := redirectUnicode(s.fields[pair.flag], true, 8192)
			if e != nil {
				return nil, e
			}
			*pair.dst = v
		}
	}
	if flags&RedirectTargetAddresses != 0 {
		addresses := s.fields[RedirectTargetAddresses]
		if len(addresses) < 4 {
			return nil, ErrInvalid
		}
		count := uint64(binary.LittleEndian.Uint32(addresses))
		addresses = addresses[4:]
		// Each entry needs a length and at least a UTF-16 terminator. The count
		// is bounded by the authenticated packet, never by an untrusted allocation.
		if count > uint64(len(addresses)/6) {
			return nil, ErrInvalid
		}
		for range count {
			value, e := redirectBytes(&addresses)
			if e != nil {
				return nil, e
			}
			name, e := redirectUnicode(value, true, 8192)
			if e != nil || name == "" {
				return nil, ErrInvalid
			}
			s.info.TargetAddresses = append(s.info.TargetAddresses, name)
		}
		if len(addresses) != 0 {
			return nil, ErrInvalid
		}
	}
	s.info.PasswordLength = len(s.fields[RedirectPassword])
	s.info.LoadBalanceInfoLength = len(s.fields[RedirectLoadBalanceInfo])
	s.info.TSVURLLength = len(s.fields[RedirectTSVURL])
	return &Redirection{state: s}, nil
}

func redirectBytes(b *[]byte) ([]byte, error) {
	if len(*b) < 4 {
		return nil, ErrInvalid
	}
	n := uint64(binary.LittleEndian.Uint32(*b))
	*b = (*b)[4:]
	if n > uint64(len(*b)) {
		return nil, ErrInvalid
	}
	v := (*b)[:int(n)]
	*b = (*b)[int(n):]
	return v, nil
}
func redirectUnicode(b []byte, terminated bool, limit int) (string, error) {
	if len(b) > limit || len(b)%2 != 0 {
		return "", ErrInvalid
	}
	if len(b) >= 2 && b[len(b)-2] == 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-2]
	} else if terminated {
		return "", ErrInvalid
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i:])
		if v == 0 {
			return "", ErrInvalid
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+2 >= len(b) {
				return "", ErrInvalid
			}
			next := binary.LittleEndian.Uint16(b[i+2:])
			if next < 0xdc00 || next > 0xdfff {
				return "", ErrInvalid
			}
			u = append(u, v, next)
			i += 2
		} else if v >= 0xdc00 && v <= 0xdfff {
			return "", ErrInvalid
		} else {
			u = append(u, v)
		}
	}
	return string(utf16.Decode(u)), nil
}

// GUID returns the decoded 16-byte GUID. CertificateDER returns the DER in a
// base64/Unicode certificate container. Neither method establishes trust.
func (r *Redirection) GUID() ([16]byte, error) {
	var guid [16]byte
	b, err := r.Field(RedirectGUID)
	if err != nil {
		return guid, err
	}
	defer clear(b)
	text, err := redirectUnicode(b, false, 65535)
	if err != nil {
		return guid, err
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	defer clear(decoded)
	if err != nil || len(decoded) != 16 {
		return guid, ErrInvalid
	}
	copy(guid[:], decoded)
	return guid, nil
}

// CertificateDER extracts a single certificate element and skips other bounded
// metadata. It does not import a root, configure a pin, or change TLS policy.
func (r *Redirection) CertificateDER() ([]byte, error) {
	b, err := r.Field(RedirectCertificate)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	text, err := redirectUnicode(b, false, 65535)
	if err != nil {
		return nil, err
	}
	container, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(container)
	var cert []byte
	input := container
	for len(input) > 0 {
		if len(input) < 12 {
			return nil, ErrInvalid
		}
		typ, encoding := binary.LittleEndian.Uint32(input), binary.LittleEndian.Uint32(input[4:])
		input = input[8:]
		element, e := redirectBytes(&input)
		if e != nil {
			return nil, e
		}
		if typ == 32 && encoding == 1 {
			if cert != nil || len(element) == 0 {
				return nil, ErrInvalid
			}
			cert = element
		}
	}
	if cert == nil {
		return nil, ErrInvalid
	}
	return append([]byte(nil), cert...), nil
}
