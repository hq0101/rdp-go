// Package der provides bounded definite-length TLV helpers for protocol codecs.
package der

import (
	"errors"
	"io"
)

var ErrInvalid = errors.New("invalid ASN.1 encoding")

const MaxSize = 1 << 20

func Wrap(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	n := len(body)
	b := []byte{tag}
	if n < 128 {
		b = append(b, byte(n))
	} else {
		var v [4]byte
		i := 4
		for x := n; x > 0; x >>= 8 {
			i--
			v[i] = byte(x)
		}
		b = append(b, byte(0x80+4-i))
		b = append(b, v[i:]...)
	}
	return append(b, body...)
}

func Integer(tag byte, n uint32) []byte {
	var b [5]byte
	i := 4
	b[i] = byte(n)
	for n >>= 8; n > 0; n >>= 8 {
		i--
		b[i] = byte(n)
	}
	if b[i]&0x80 != 0 {
		i--
	}
	return Wrap(tag, b[i:])
}

func Uint(b []byte) (uint32, error) {
	if len(b) == 0 || len(b) > 5 || b[0]&0x80 != 0 || (len(b) == 5 && b[0] != 0) {
		return 0, ErrInvalid
	}
	var n uint32
	for _, v := range b {
		n = n<<8 | uint32(v)
	}
	return n, nil
}

// Take consumes one definite-length, single-octet-tag element. It returns views.
func Take(b *[]byte, tag byte) ([]byte, error) {
	p := *b
	if len(p) < 2 || p[0] != tag {
		return nil, ErrInvalid
	}
	n, h := int(p[1]), 2
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 3 || len(p) < 2+count {
			return nil, ErrInvalid
		}
		n = 0
		h += count
		for _, v := range p[2:h] {
			n = n<<8 | int(v)
		}
	}
	if n > MaxSize || n > len(p)-h {
		return nil, ErrInvalid
	}
	*b = p[h+n:]
	return p[h : h+n], nil
}

// ReadSequence reads one ASN.1 SEQUENCE without consuming subsequent PDUs.
func ReadSequence(r io.Reader) ([]byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	if h[0] != 0x30 {
		return nil, ErrInvalid
	}
	n := int(h[1])
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 3 {
			return nil, ErrInvalid
		}
		more := make([]byte, count)
		if _, err := io.ReadFull(r, more); err != nil {
			return nil, err
		}
		h = append(h, more...)
		n = 0
		for _, v := range more {
			n = n<<8 | int(v)
		}
	}
	if n > MaxSize {
		return nil, ErrInvalid
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(h, body...), nil
}

func Write(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
