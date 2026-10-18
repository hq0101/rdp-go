// Package rdstls implements the version-one authentication exchange inside an
// already authenticated TLS stream. It neither dials nor changes trust policy.
package rdstls

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var ErrInvalid = errors.New("rdstls: invalid or unsupported message")

// AuthenticationError preserves the server's numeric result, including unknown
// errors. Zero is never returned as an error. It contains no credential data.
type AuthenticationError struct{ Code uint32 }

func (e *AuthenticationError) Error() string {
	return fmt.Sprintf("rdstls: authentication rejected (0x%08x)", e.Code)
}

func unicode(b []byte, maximum int, empty bool) bool {
	if len(b) < 2 || len(b) > maximum || len(b)%2 != 0 || b[len(b)-2] != 0 || b[len(b)-1] != 0 || !empty && len(b) == 2 {
		return false
	}
	for i := 0; i < len(b)-2; i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 || u >= 0xdc00 && u <= 0xdfff {
			return false
		}
		if u >= 0xd800 && u <= 0xdbff {
			i += 2
			if i >= len(b)-2 {
				return false
			}
			v := binary.LittleEndian.Uint16(b[i:])
			if v < 0xdc00 || v > 0xdfff {
				return false
			}
		}
	}
	return true
}

func validGUID(b []byte) bool {
	if len(b) == 50 && b[48] == 0 && b[49] == 0 {
		b = b[:48]
	}
	if len(b) != 48 {
		return false
	}
	var encoded [24]byte
	for i := range encoded {
		if b[2*i+1] != 0 || b[2*i] == '\r' || b[2*i] == '\n' {
			return false
		}
		encoded[i] = b[2*i]
	}
	var decoded [18]byte
	n, err := base64.StdEncoding.Strict().Decode(decoded[:], encoded[:])
	clear(decoded[:])
	return err == nil && n == 16
}

// PasswordRequest copies the four original redirection wire fields. GUID is
// base64 UTF-16 with an optional NUL; names require their NUL; password is opaque
// encrypted data, never decoded or hashed. Clear the returned sensitive packet.
func PasswordRequest(guid, user, domain, password []byte) ([]byte, error) {
	if !validGUID(guid) || !unicode(user, 512, false) || !unicode(domain, 512, true) || len(password) == 0 || len(password) > 65535 {
		return nil, ErrInvalid
	}
	b := []byte{1, 0, 2, 0, 1, 0}
	for _, field := range [][]byte{guid, user, domain, password} {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(field)))
		b = append(b, field...)
	}
	return b, nil
}

// CookieRequest uses the original 28-byte ARC_SC_PRIVATE_PACKET in the RDSTLS
// authentication exchange. This is NOT the derived verifier sent in Client Info.
// Transmit the result only after the original TLS identity is reverified. This internal
// packet contains the server's secret random; clear all copies after the attempt.
func CookieRequest(cookie []byte) ([]byte, error) {
	if len(cookie) != 28 || binary.LittleEndian.Uint32(cookie) != 28 || binary.LittleEndian.Uint32(cookie[4:]) != 1 {
		return nil, ErrInvalid
	}
	b := []byte{1, 0, 2, 0, 2, 0}
	b = append(b, cookie[8:12]...)
	b = binary.LittleEndian.AppendUint16(b, 28)
	return append(b, cookie...), nil
}

func ParseCapabilities(b []byte) error {
	if len(b) != 8 {
		return ErrInvalid
	}
	for i := 0; i < 8; i += 2 {
		if binary.LittleEndian.Uint16(b[i:]) != 1 {
			return ErrInvalid
		}
	}
	return nil
}

func ParseResponse(b []byte) error {
	if len(b) != 10 || binary.LittleEndian.Uint16(b) != 1 || binary.LittleEndian.Uint16(b[2:]) != 4 || binary.LittleEndian.Uint16(b[4:]) != 1 {
		return ErrInvalid
	}
	if code := binary.LittleEndian.Uint32(b[6:]); code != 0 {
		return &AuthenticationError{Code: code}
	}
	return nil
}

// Authenticate consumes exactly 8 capability bytes and 10 response bytes.
// There is no TPKT, X.224 or total-length prefix in this exchange. The caller
// supplies a packet produced by the request encoders, verified TLS, deadlines
// and cancellation. Any failure requires closing the connection, without retry
// on that stream. Subsequent RDP bytes remain unread, even when coalesced.
func Authenticate(rw io.ReadWriter, packet []byte) error {
	if len(packet) < 6 || binary.LittleEndian.Uint16(packet) != 1 || binary.LittleEndian.Uint16(packet[2:]) != 2 {
		return ErrInvalid
	}
	var caps [8]byte
	if _, err := io.ReadFull(rw, caps[:]); err != nil {
		return err
	}
	if err := ParseCapabilities(caps[:]); err != nil {
		return err
	}
	n, err := rw.Write(packet)
	if err != nil {
		return err
	}
	if n != len(packet) {
		return io.ErrShortWrite
	}
	var response [10]byte
	if _, err := io.ReadFull(rw, response[:]); err != nil {
		return err
	}
	return ParseResponse(response[:])
}
