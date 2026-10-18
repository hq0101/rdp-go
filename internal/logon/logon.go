// Package logon parses Save Session Info and keeps reconnect material out of
// the public event API. It is internal because cookies authorize a session.
package logon

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"
)

var ErrInvalid = errors.New("rdp: invalid Save Session Info")

const MaxNameBytes = 8192
const MaxMessage = 2*MaxNameBytes + 580

type Message struct {
	Type                          uint32
	Logon                         bool
	IdentityKnown, SessionIDKnown bool
	Domain, Username              string
	SessionID                     uint32
	ErrorNotification             bool
	ErrorType, ErrorData          uint32
	Cookie                        *Cookie
}

// Cookie is owned, opaque reconnect material. Never persist it or return it
// through public APIs. Only RDSTLSPacket may copy the raw server credential for
// its private authentication exchange. Clear it when replaced or discarded.
// These operations require the caller to serialize access.
type Cookie struct {
	sessionID uint32
	random    [16]byte
	valid     bool
}

// SessionID is non-secret metadata used to verify restoration of the same session.
func (c *Cookie) SessionID() uint32 {
	if c == nil || !c.valid {
		return 0
	}
	return c.sessionID
}

func (*Cookie) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, "[redacted reconnect cookie]") }
func (*Cookie) MarshalJSON() ([]byte, error) { return []byte(`"[redacted reconnect cookie]"`), nil }
func (c *Cookie) Clear() {
	if c != nil {
		clear(c.random[:])
		c.sessionID, c.valid = 0, false
	}
}

// RDSTLSPacket serializes the server cookie for the RDSTLS authentication PDU,
// not for Client Info. Only the internal RDSTLS recovery path may use it, and
// must verify the original TLS identity before transmission. Clear it promptly.
func (c *Cookie) RDSTLSPacket() ([]byte, error) {
	if c == nil || !c.valid {
		return nil, ErrInvalid
	}
	b := make([]byte, 28)
	binary.LittleEndian.PutUint32(b, 28)
	binary.LittleEndian.PutUint32(b[4:], 1)
	binary.LittleEndian.PutUint32(b[8:], c.sessionID)
	copy(b[12:], c.random[:])
	return b, nil
}

// ClientPacketTLS derives ARC_CS_PRIVATE_PACKET for Enhanced RDP Security.
// Its 32-byte client random is zero, not the TLS handshake's ClientHello random.
// The returned verifier is sensitive and must be cleared after use. A cookie
// does not bypass TLS certificate verification or the selected NLA/RDSTLS
// authentication exchange.
func (c *Cookie) ClientPacketTLS() ([]byte, error) {
	if c == nil || !c.valid {
		return nil, ErrInvalid
	}
	b := make([]byte, 28)
	binary.LittleEndian.PutUint32(b, 28)
	binary.LittleEndian.PutUint32(b[4:], 1)
	binary.LittleEndian.PutUint32(b[8:], c.sessionID)
	var random [32]byte
	h := hmac.New(md5.New, c.random[:]) // Required by MS-RDPBCGR 5.5.
	_, _ = h.Write(random[:])
	h.Sum(b[:12])
	return b, nil
}

func unicodeName(b []byte) (string, error) {
	if len(b) < 2 || len(b) > MaxNameBytes || len(b)%2 != 0 || b[len(b)-2] != 0 || b[len(b)-1] != 0 {
		return "", ErrInvalid
	}
	units := make([]uint16, 0, len(b)/2-1)
	for i := 0; i < len(b)-2; i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 {
			return "", ErrInvalid
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+4 >= len(b) {
				return "", ErrInvalid
			}
			v := binary.LittleEndian.Uint16(b[i+2:])
			if v < 0xdc00 || v > 0xdfff {
				return "", ErrInvalid
			}
			units = append(units, u, v)
			i += 2
		} else {
			if u >= 0xdc00 && u <= 0xdfff {
				return "", ErrInvalid
			}
			units = append(units, u)
		}
	}
	return string(utf16.Decode(units)), nil
}

// Parse accepts the Share Data payload beginning at infoType. On failure it
// returns no partial identity, notification or cookie. Padding is ignored.
func Parse(data []byte) (message Message, err error) {
	var m Message
	defer func() {
		if err != nil {
			m.Cookie.Clear()
			// Length/version diagnostics only; never include names or cookie bytes.
			detail := ""
			if m.Type == 1 && len(data) >= 22 {
				detail = fmt.Sprintf(" version=%d size=%d domainBytes=%d userBytes=%d", binary.LittleEndian.Uint16(data[4:]), binary.LittleEndian.Uint32(data[6:]), binary.LittleEndian.Uint32(data[14:]), binary.LittleEndian.Uint32(data[18:]))
			}
			if m.Type == 3 && len(data) >= 10 {
				detail = fmt.Sprintf(" length=%d flags=%#x", binary.LittleEndian.Uint16(data[4:]), binary.LittleEndian.Uint32(data[6:]))
			}
			err = fmt.Errorf("%w: type=%d bytes=%d%s", err, m.Type, len(data), detail)
		}
	}()
	if len(data) < 4 || len(data) > MaxMessage {
		return Message{}, ErrInvalid
	}
	m.Type = binary.LittleEndian.Uint32(data)
	b := data[4:]
	switch m.Type {
	case 0:
		// RDP 4 lacks the trailing session ID; modern peers include it.
		if len(b) != 572 && len(b) != 576 {
			return Message{}, ErrInvalid
		}
		dn, un := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[56:])
		if dn > 52 || un > 512 {
			return Message{}, ErrInvalid
		}
		m.Domain, err = unicodeName(b[4 : 4+dn])
		if err != nil {
			return Message{}, err
		}
		m.Username, err = unicodeName(b[60 : 60+un])
		if err != nil {
			return Message{}, err
		}
		if len(b) == 576 {
			m.SessionIDKnown = true
			m.SessionID = binary.LittleEndian.Uint32(b[572:])
		}
		m.Logon, m.IdentityKnown = true, true
	case 1:
		if len(b) < 576 || binary.LittleEndian.Uint16(b) != 1 {
			return Message{}, ErrInvalid
		}
		// Windows 10 reports the 18-byte header size without the 558 bytes
		// of padding. Names still begin at offset 576 in both conventions.
		size := binary.LittleEndian.Uint32(b[2:])
		if size != 576 && size != 18 {
			return Message{}, ErrInvalid
		}
		dn, un := binary.LittleEndian.Uint32(b[10:]), binary.LittleEndian.Uint32(b[14:])
		if uint64(dn)+uint64(un) != uint64(len(b)-576) || dn > MaxNameBytes || un > MaxNameBytes {
			return Message{}, ErrInvalid
		}
		m.Domain, err = unicodeName(b[576 : 576+dn])
		if err != nil {
			return Message{}, err
		}
		m.Username, err = unicodeName(b[576+dn:])
		if err != nil {
			return Message{}, err
		}
		m.SessionID = binary.LittleEndian.Uint32(b[6:])
		m.Logon, m.IdentityKnown, m.SessionIDKnown = true, true, true
	case 2:
		if len(b) != 576 {
			return Message{}, ErrInvalid
		}
		m.Logon = true
	case 3:
		if len(b) < 576 {
			return Message{}, ErrInvalid
		}
		// Windows 10 sends Length excluding the final 570-byte padding (for
		// example 18 with one eight-byte error field), while MS-RDPBCGR calls
		// it the total size. Accept these two exact conventions only; field
		// boundaries and the mandatory padding remain independently checked.
		length := int(binary.LittleEndian.Uint16(b))
		if length != len(b) && length != len(b)-570 {
			return Message{}, ErrInvalid
		}
		flags := binary.LittleEndian.Uint32(b[2:])
		if flags & ^uint32(3) != 0 {
			return Message{}, ErrInvalid
		}
		fields := b[6 : len(b)-570]
		for _, bit := range []uint32{1, 2} {
			if flags&bit == 0 {
				continue
			}
			if len(fields) < 4 {
				return Message{}, ErrInvalid
			}
			n := binary.LittleEndian.Uint32(fields)
			fields = fields[4:]
			if uint64(n) > uint64(len(fields)) {
				return Message{}, ErrInvalid
			}
			field := fields[:n]
			fields = fields[n:]
			if bit == 1 {
				if n != 28 || binary.LittleEndian.Uint32(field) != 28 || binary.LittleEndian.Uint32(field[4:]) != 1 {
					return Message{}, ErrInvalid
				}
				m.Cookie = &Cookie{sessionID: binary.LittleEndian.Uint32(field[8:]), valid: true}
				copy(m.Cookie.random[:], field[12:])
			} else {
				if n != 8 {
					return Message{}, ErrInvalid
				}
				m.ErrorNotification = true
				m.ErrorType, m.ErrorData = binary.LittleEndian.Uint32(field), binary.LittleEndian.Uint32(field[4:])
			}
		}
		if len(fields) != 0 {
			return Message{}, ErrInvalid
		}
	default:
		return Message{}, ErrInvalid
	}
	return m, nil
}
