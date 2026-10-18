// Package zgfx implements MS-RDPEGFX RDP 8 bulk decompression. This stream is
// carried inside the graphics dynamic channel, independently of RDP 4-6.1
// share/static-channel compression. It is not a bitmap codec.
package zgfx

import (
	"encoding/binary"
	"errors"
)

const (
	HistorySize       = 2500000
	MaxSegment        = 65535
	MaxDecoded        = 64 << 20
	maxEncodedSegment = MaxSegment + 1001 // at most 1000 bytes expansion + header
	// MaxEncoded bounds a complete segmented message, including worst-case expansion.
	MaxEncoded = MaxDecoded + 65535*1005 + 7
)

var ErrInvalid = errors.New("zgfx: invalid or oversized compressed data")

// Decoder owns one ordered graphics channel history. The zero value is ready.
// Calls must be serialized; do not copy after first use. Decode returns owned
// data and commits history only if the entire single/multipart message is valid.
type Decoder struct {
	history []byte
	offset  int
}

// Reset discards the history when the graphics channel is closed/recreated.
// A graphics reset/resize on the same channel does not reset compression.
func (d *Decoder) Reset() { *d = Decoder{} }

// Decode consumes one complete RDP_SEGMENTED_DATA after DVC reassembly. limit
// bounds total output (0..MaxDecoded), independently of the untrusted wire size.
func (d *Decoder) Decode(src []byte, limit int) ([]byte, error) {
	if len(src) < 2 || len(src) > MaxEncoded || limit < 0 || limit > MaxDecoded {
		return nil, ErrInvalid
	}
	var out []byte
	if src[0] == 0xe0 {
		var err error
		out, err = d.segment(src[1:], out, limit)
		if err != nil {
			return nil, err
		}
	} else if src[0] == 0xe1 {
		if len(src) < 7 {
			return nil, ErrInvalid
		}
		count := int(binary.LittleEndian.Uint16(src[1:]))
		expected := uint64(binary.LittleEndian.Uint32(src[3:]))
		src = src[7:]
		if count == 0 || count > len(src)/5 || expected > uint64(limit) {
			return nil, ErrInvalid
		}
		// Bound reservation independently of advertised size: output grows only
		// as bytes actually decode. A tiny packet cannot force a 64 MB allocation.
		for i := 0; i < count; i++ {
			if len(src) < 4 {
				return nil, ErrInvalid
			}
			n := uint64(binary.LittleEndian.Uint32(src))
			src = src[4:]
			if n == 0 || n > uint64(len(src)) {
				return nil, ErrInvalid
			}
			var err error
			out, err = d.segment(src[:int(n)], out, int(expected))
			if err != nil {
				return nil, err
			}
			src = src[int(n):]
		}
		if len(src) != 0 || uint64(len(out)) != expected {
			return nil, ErrInvalid
		}
	} else {
		return nil, ErrInvalid
	}
	d.commit(out)
	return out, nil
}

func (d *Decoder) commit(out []byte) {
	if len(out) == 0 {
		return
	}
	if d.history == nil {
		d.history = make([]byte, HistorySize)
	}
	end := (d.offset + len(out)) % HistorySize
	if len(out) > HistorySize {
		out = out[len(out)-HistorySize:]
	}
	start := (end - len(out) + HistorySize) % HistorySize
	n := copy(d.history[start:], out)
	copy(d.history, out[n:])
	d.offset = end
}

func (d *Decoder) segment(src, out []byte, limit int) ([]byte, error) {
	if len(src) == 0 || len(src) > maxEncodedSegment || src[0]&^byte(0x20) != 4 {
		return nil, ErrInvalid
	}
	start := len(out)
	limit = min(limit, start+MaxSegment)
	if src[0]&0x20 == 0 {
		if len(src)-1 > limit-start {
			return nil, ErrInvalid
		}
		return append(out, src[1:]...), nil
	}
	if len(src) < 2 || src[len(src)-1] > 7 {
		return nil, ErrInvalid
	}
	r := bitReader{data: src[1 : len(src)-1], end: (len(src)-2)*8 - int(src[len(src)-1])}
	if r.end < 0 {
		return nil, ErrInvalid
	}
	for r.pos < r.end {
		t := tokens[r.peek8()]
		if t.bits == 0 || int(t.bits) > r.left() {
			return nil, ErrInvalid
		}
		r.pos += int(t.bits)
		value := t.base + r.read(int(t.extra))
		if r.bad {
			return nil, ErrInvalid
		}
		if !t.match {
			// Dedicated short literal codes make these 9-bit forms reserved.
			if t.bits == 1 && shortLiteral[byte(value)] || len(out) == limit {
				return nil, ErrInvalid
			}
			out = append(out, byte(value))
			continue
		}
		if value == 0 {
			// Raw runs include alignment bits in the stream's declared bit count.
			n := r.read(15)
			padding := (-r.pos) & 7
			_ = r.read(padding)
			if r.bad || n > limit-len(out) || n > r.left()/8 {
				return nil, ErrInvalid
			}
			out = append(out, r.data[r.pos/8:r.pos/8+n]...)
			r.pos += 8 * n
			continue
		}
		if value > HistorySize {
			return nil, ErrInvalid
		}
		ones := 0
		for r.read(1) != 0 {
			ones++
			if ones > 14 {
				return nil, ErrInvalid
			}
		}
		n := 3
		if ones > 0 {
			n = 1<<(ones+1) + r.read(ones+1)
		}
		if r.bad || n > limit-len(out) {
			return nil, ErrInvalid
		}
		for i := 0; i < n; i++ {
			var v byte
			if value <= len(out) {
				v = out[len(out)-value]
			} else if d.history != nil {
				p := (d.offset - (value - len(out)) + HistorySize) % HistorySize
				v = d.history[p]
			}
			out = append(out, v)
		}
	}
	return out, nil
}

type bitReader struct {
	data     []byte
	pos, end int
	bad      bool
}

func (r *bitReader) left() int { return r.end - r.pos }
func (r *bitReader) read(n int) int {
	if n > r.left() {
		r.bad = true
		return 0
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<1 | int((r.data[r.pos/8]>>uint(7-r.pos%8))&1)
		r.pos++
	}
	return v
}
func (r *bitReader) peek8() byte {
	n := min(8, r.left())
	v := 0
	for i := 0; i < n; i++ {
		p := r.pos + i
		v = v<<1 | int((r.data[p/8]>>uint(7-p%8))&1)
	}
	return byte(v << (8 - n))
}

type token struct {
	bits, extra byte
	base        int
	match       bool
}
type prefix struct {
	code  int
	token token
}

// Factual assignments from MS-RDPEGFX 3.1.9.1.2.4, independently represented
// here as an 8-bit prefix lookup. No external implementation is used.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/4c26b84a-fa5e-42d0-bcf4-3eee8fac2d3f
var definitions = []prefix{
	{0b0, token{1, 8, 0, false}},
	{0b10001, token{5, 5, 0, true}}, {0b10010, token{5, 7, 32, true}},
	{0b10011, token{5, 9, 160, true}}, {0b10100, token{5, 10, 672, true}},
	{0b10101, token{5, 12, 1696, true}}, {0b101100, token{6, 14, 5792, true}},
	{0b101101, token{6, 15, 22176, true}}, {0b1011100, token{7, 18, 54944, true}},
	{0b1011101, token{7, 20, 317088, true}}, {0b10111100, token{8, 20, 1365664, true}},
	{0b10111101, token{8, 21, 2414240, true}},
	{0b11000, token{5, 0, 0, false}}, {0b11001, token{5, 0, 1, false}},
	{0b110100, token{6, 0, 2, false}}, {0b110101, token{6, 0, 3, false}},
	{0b110110, token{6, 0, 255, false}}, {0b1101110, token{7, 0, 4, false}},
	{0b1101111, token{7, 0, 5, false}}, {0b1110000, token{7, 0, 6, false}},
	{0b1110001, token{7, 0, 7, false}}, {0b1110010, token{7, 0, 8, false}},
	{0b1110011, token{7, 0, 9, false}}, {0b1110100, token{7, 0, 10, false}},
	{0b1110101, token{7, 0, 11, false}}, {0b1110110, token{7, 0, 58, false}},
	{0b1110111, token{7, 0, 59, false}}, {0b1111000, token{7, 0, 60, false}},
	{0b1111001, token{7, 0, 61, false}}, {0b1111010, token{7, 0, 62, false}},
	{0b1111011, token{7, 0, 63, false}}, {0b1111100, token{7, 0, 64, false}},
	{0b1111101, token{7, 0, 128, false}}, {0b11111100, token{8, 0, 12, false}},
	{0b11111101, token{8, 0, 56, false}}, {0b11111110, token{8, 0, 57, false}},
	{0b11111111, token{8, 0, 102, false}},
}
var tokens, shortLiteral = makeTables()

func makeTables() ([256]token, [256]bool) {
	var table [256]token
	var short [256]bool
	for _, p := range definitions {
		for i := 0; i < 1<<(8-p.token.bits); i++ {
			idx := p.code<<(8-p.token.bits) | i
			if table[idx].bits != 0 {
				panic("zgfx: overlapping constant prefix table")
			}
			table[idx] = p.token
		}
		if !p.token.match && p.token.bits != 1 {
			short[p.token.base] = true
		}
	}
	return table, short
}
