// Package kkdcp implements the bounded MS-KKDCP DER envelope. It does not
// interpret Kerberos credentials or choose a KDC from a server response.
package kkdcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode"
	"unicode/utf8"

	"github.com/hq0101/rdp-go/internal/der"
)

const MaxMessage = 1 << 20
const MaxEnvelope = MaxMessage + 2048

var ErrInvalid = errors.New("kkdcp: invalid proxy message")

func ValidRealm(s string) bool {
	return len(s) > 0 && len(s) <= 1024 && utf8.ValidString(s) && !bytes.ContainsFunc([]byte(s), unicode.IsControl)
}

// EncodeRequest always includes the locally selected realm. hint is the
// optional DC locator flags, not a KDC address or a transport selection.
func EncodeRequest(message []byte, realm string, hint *uint32) ([]byte, error) {
	if len(message) == 0 || len(message) > MaxMessage || !ValidRealm(realm) {
		return nil, ErrInvalid
	}
	framed := binary.BigEndian.AppendUint32(nil, uint32(len(message)))
	framed = append(framed, message...)
	defer clear(framed)
	f := [][]byte{der.Wrap(0xa0, der.Wrap(4, framed)), der.Wrap(0xa1, der.Wrap(0x1b, []byte(realm)))}
	if hint != nil {
		f = append(f, der.Wrap(0xa2, der.Integer(2, *hint)))
	}
	return der.Wrap(0x30, f...), nil
}

// take requires canonical definite DER and bounds every level independently.
func take(b *[]byte, tag byte) ([]byte, error) {
	p := *b
	if len(p) < 2 || p[0] != tag {
		return nil, ErrInvalid
	}
	n, h := int(p[1]), 2
	if n&128 != 0 {
		count := n & 127
		if count == 0 || count > 3 || len(p) < 2+count || p[2] == 0 {
			return nil, ErrInvalid
		}
		n = 0
		h += count
		for _, v := range p[2:h] {
			n = n<<8 | int(v)
		}
		if n < 128 {
			return nil, ErrInvalid
		}
	}
	if n > MaxEnvelope || n > len(p)-h {
		return nil, ErrInvalid
	}
	*b = p[h+n:]
	return p[h : h+n], nil
}
func unwrap(b []byte, tag byte) ([]byte, error) {
	v, e := take(&b, tag)
	if e != nil || len(b) != 0 {
		return nil, ErrInvalid
	}
	return v, nil
}

// DecodeResponse returns an owned Kerberos message. Optional realm and locator
// fields are syntax-checked but cannot alter the client's routing or identity.
func DecodeResponse(b []byte) ([]byte, error) {
	if len(b) > MaxEnvelope {
		return nil, ErrInvalid
	}
	seq, e := unwrap(b, 0x30)
	if e != nil {
		return nil, e
	}
	var fields [3][]byte
	last := -1
	for len(seq) > 0 {
		i := int(seq[0]) - 0xa0
		if i < 0 || i >= len(fields) || i <= last {
			return nil, ErrInvalid
		}
		last = i
		fields[i], e = take(&seq, byte(0xa0+i))
		if e != nil {
			return nil, e
		}
	}
	framed, e := unwrap(fields[0], 4)
	if e != nil || len(framed) < 5 || len(framed) > MaxMessage+4 || binary.BigEndian.Uint32(framed) != uint32(len(framed)-4) {
		return nil, ErrInvalid
	}
	if fields[1] != nil {
		realm, e := unwrap(fields[1], 0x1b)
		if e != nil || !ValidRealm(string(realm)) {
			return nil, ErrInvalid
		}
	}
	if fields[2] != nil {
		n, e := unwrap(fields[2], 2)
		if e != nil || len(n) == 0 || len(n) > 5 || n[0]&128 != 0 || (len(n) > 1 && n[0] == 0 && n[1]&128 == 0) || (len(n) == 5 && n[0] != 0) {
			return nil, ErrInvalid
		}
	}
	return bytes.Clone(framed[4:]), nil
}
