package kerberos

import (
	"encoding/binary"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hq0101/rdp-go/internal/der"
)

const MaxMessage = 1 << 20
const maxItems = 32

// take accepts canonical definite-length DER and a single-byte expected tag.
// It returns views, consumes only on success, and never accepts trailing bytes
// on behalf of an enclosing sequence. All protocol structures are depth-bounded.
func take(b *[]byte, tag byte) (body, full []byte, err error) {
	p := *b
	if len(p) < 2 || p[0] != tag {
		return nil, nil, ErrInvalid
	}
	n, h := int(p[1]), 2
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 3 || len(p) < 2+count || p[2] == 0 {
			return nil, nil, ErrInvalid
		}
		n = 0
		h += count
		for _, v := range p[2:h] {
			n = n<<8 | int(v)
		}
		if n < 128 {
			return nil, nil, ErrInvalid
		}
	}
	if n > MaxMessage || n > len(p)-h {
		return nil, nil, ErrInvalid
	}
	*b = p[h+n:]
	return p[h : h+n], p[:h+n], nil
}

func unwrap(b []byte, tag byte) ([]byte, error) {
	value, _, err := take(&b, tag)
	if err != nil || len(b) != 0 {
		return nil, ErrInvalid
	}
	return value, nil
}

type fields struct {
	raw [16][]byte
	err error
}

func readFields(b []byte, app byte, allowed, required uint16) *fields {
	f := &fields{}
	if len(b) > MaxMessage {
		f.err = ErrInvalid
		return f
	}
	if app != 0 {
		b, f.err = unwrap(b, app)
		if f.err != nil {
			return f
		}
	}
	b, f.err = unwrap(b, 0x30)
	if f.err != nil {
		return f
	}
	last := -1
	var seen uint16
	for len(b) > 0 {
		i := int(b[0]) - 0xa0
		if i < 0 || i >= 16 || i <= last || allowed&(1<<i) == 0 {
			f.err = ErrInvalid
			return f
		}
		last = i
		seen |= 1 << i
		f.raw[i], _, f.err = take(&b, byte(0xa0+i))
		if f.err != nil {
			return f
		}
	}
	if seen&required != required {
		f.err = ErrInvalid
	}
	return f
}

func (f *fields) get(i int, tag byte) []byte {
	if f.err != nil {
		return nil
	}
	var b []byte
	b, f.err = unwrap(f.raw[i], tag)
	return b
}
func (f *fields) has(i int) bool { return f.raw[i] != nil }
func (f *fields) reject(err error) {
	if err != nil && f.err == nil {
		f.err = err
	}
}

func canonicalInteger(b []byte) bool {
	return len(b) > 0 && !(len(b) > 1 && ((b[0] == 0 && b[1]&0x80 == 0) || (b[0] == 0xff && b[1]&0x80 != 0)))
}
func (f *fields) int32(i int) int32 {
	b := f.get(i, 2)
	if !canonicalInteger(b) || len(b) > 4 {
		f.reject(ErrInvalid)
		return 0
	}
	var n int32
	if b[0]&0x80 != 0 {
		n = -1
	}
	for _, v := range b {
		n = n<<8 | int32(v)
	}
	return n
}
func (f *fields) uint32(i int) uint32 {
	b := f.get(i, 2)
	if !canonicalInteger(b) || len(b) > 5 || b[0]&0x80 != 0 || (len(b) == 5 && b[0] != 0) {
		f.reject(ErrInvalid)
		return 0
	}
	var n uint32
	for _, v := range b {
		n = n<<8 | uint32(v)
	}
	return n
}
func (f *fields) microseconds(i int) int32 {
	n := f.int32(i)
	if n < 0 || n > 999999 {
		f.reject(ErrInvalid)
	}
	return n
}
func validName(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func (f *fields) text(i, max int) string {
	s := string(f.get(i, 0x1b))
	if !validName(s, max) {
		f.reject(ErrInvalid)
	}
	return s
}
func (f *fields) timestamp(i int) time.Time {
	b := f.get(i, 0x18)
	if len(b) != 15 {
		f.reject(ErrInvalid)
		return time.Time{}
	}
	t, err := time.Parse("20060102150405Z", string(b))
	if err != nil || t.Year() < 1 || t.Format("20060102150405Z") != string(b) {
		f.reject(ErrInvalid)
	}
	return t
}
func (f *fields) flags(i int) uint32 {
	b := f.get(i, 3)
	if len(b) < 5 || len(b) > 33 || b[0] > 7 || (len(b)-1)*8-int(b[0]) < 32 || b[len(b)-1]&byte((1<<b[0])-1) != 0 {
		f.reject(ErrInvalid)
		return 0
	}
	for _, v := range b[5:] {
		if v != 0 {
			f.reject(ErrUnsupported)
		}
	}
	return binary.BigEndian.Uint32(b[1:5])
}

func contextField(i byte, b []byte) []byte         { return der.Wrap(0xa0+i, b) }
func sequence(parts ...[]byte) []byte              { return der.Wrap(0x30, parts...) }
func application(tag byte, parts ...[]byte) []byte { return der.Wrap(0x60+tag, sequence(parts...)) }
func integer(n uint32) []byte                      { return der.Integer(2, n) }
func generalString(s string) []byte                { return der.Wrap(0x1b, []byte(s)) }
func octets(b []byte) []byte                       { return der.Wrap(4, b) }
func kerberosTime(t time.Time) []byte {
	return der.Wrap(0x18, []byte(t.UTC().Format("20060102150405Z")))
}
func bitFlags(n uint32) []byte { return der.Wrap(3, binary.BigEndian.AppendUint32([]byte{0}, n)) }
