package graphics

import "encoding/binary"

// DecodeAlpha decodes MS-RDPEGFX 2.2.4.3 into a caller-owned, top-down alpha
// plane. AlphaCodec changes opacity only; it contains no RGB color information.
func DecodeAlpha(src []byte, width, height int) ([]byte, error) {
	if !codecDimensions(width, height) || len(src) < 4 || len(src) > maxClearInput || binary.LittleEndian.Uint16(src) != 0x414c {
		return nil, ErrInvalid
	}
	compressed := binary.LittleEndian.Uint16(src[2:]) != 0
	src = src[4:]
	n := width * height
	if !compressed {
		if len(src) != n {
			return nil, ErrInvalid
		}
		return append([]byte(nil), src...), nil
	}
	out := make([]byte, n)
	r := clearReader{data: src}
	pos := 0
	for len(r.data) != 0 && !r.bad {
		value := r.u8()
		count := r.run(n - pos)
		if r.bad {
			return nil, ErrInvalid
		}
		for end := pos + count; pos < end; pos++ {
			out[pos] = value
		}
	}
	if r.bad || pos != n {
		return nil, ErrInvalid
	}
	return out, nil
}

func codecDimensions(w, h int) bool {
	return w > 0 && h > 0 && w <= maxDimension && h <= maxDimension && w*h <= MaxPixels
}

// ClearCodec and AlphaCodec share the 8/16/32-bit run length representation.
// Each extension REPLACES the preceding sentinel, rather than adding to it.
type clearReader struct {
	data []byte
	bad  bool
}

func (r *clearReader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.data) {
		r.bad = true
		return nil
	}
	b := r.data[:n]
	r.data = r.data[n:]
	return b
}
func (r *clearReader) u8() byte {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (r *clearReader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}
func (r *clearReader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}
func (r *clearReader) run(remaining int) int {
	n := uint32(r.u8())
	if n == 255 {
		n = uint32(r.u16())
		if n == 65535 {
			n = r.u32()
		}
	}
	if r.bad || remaining < 0 || uint64(n) > uint64(remaining) {
		r.bad = true
		return 0
	}
	return int(n)
}
