// Package bulk implements RDP 4.0/5.0 MPPC and RDP 6/6.1 bulk decompression.
// It is independent of bitmap compression and TLS framing.
package bulk

import "errors"

const (
	Type8K     byte = 0
	Type64K    byte = 1
	TypeRDP6   byte = 2
	TypeRDP61  byte = 3
	Compressed byte = 0x20
	AtFront    byte = 0x40
	Flushed    byte = 0x80
	MaxDecoded      = 65535
)

var ErrInvalid = errors.New("bulk: invalid or unsupported compressed data")

// Decoder maintains one ordered direction of an RDP connection. Share data,
// fast-path updates and static channels use the same receiver, before fragment
// reassembly. A dynamic channel's own compression is a separate protocol.
// The zero value is ready to use; calls must be serialized. Results are owned
// by the caller and a failed Decode leaves the history unchanged.
// A Decoder must not be copied after first use.
type Decoder struct {
	history     [65536]byte
	offset      int
	typ         byte
	initialized bool
	offsetCache [4]int
	offsetCount int
	rdp61       *rdp61State
}

// Reset discards all history. Reactivation on the same transport does not call
// Reset: PACKET_FLUSHED, rather than graphics capabilities, governs history.
func (d *Decoder) Reset() { *d = Decoder{} }

// Decode accepts the compression-type/flags byte and just the payload. limit is
// a caller supplied output budget in 0..MaxDecoded. Raw packets do not enter
// MPPC history, but their FLUSHED flag still takes effect. AT_FRONT preserves
// the MPPC buffer (or slides RDP6 history); FLUSHED zeroes it. RDP6.1 has
// additional L1/L2 control bytes. RDP permits references to initialized zeros.
func (d *Decoder) Decode(flags byte, src []byte, limit int) ([]byte, error) {
	typ := flags & 15
	if typ > TypeRDP61 || flags&0x10 != 0 || flags&AtFront != 0 && flags&Compressed == 0 || limit < 0 || limit > MaxDecoded || len(src) > MaxDecoded {
		return nil, ErrInvalid
	}
	if flags&Compressed == 0 {
		if len(src) > limit {
			return nil, ErrInvalid
		}
		if flags&Flushed != 0 {
			d.Reset()
		}
		return append([]byte(nil), src...), nil
	}
	if typ == TypeRDP6 {
		return d.decodeNCrush(flags, src, limit)
	}
	if typ == TypeRDP61 {
		return d.decodeRDP61(flags, src, limit)
	}
	// Working copy provides transactional history updates, including a flush.
	next := *d
	if flags&Flushed != 0 {
		next.Reset()
	}
	if next.initialized && next.typ != typ {
		return nil, ErrInvalid
	}
	next.typ, next.initialized = typ, true
	size, maxLengthBits := 8192, 12
	if typ == Type64K {
		size, maxLengthBits = 65536, 15
	}
	if flags&AtFront != 0 {
		next.offset = 0
	}
	start := next.offset
	limit = min(limit, size-1, size-start)
	r := bitReader{data: src}
	for r.left() >= 8 {
		first := r.read(1)
		if first == 0 {
			v := r.read(7)
			if next.offset-start >= limit {
				return nil, ErrInvalid
			}
			next.history[next.offset] = byte(v)
			next.offset++
			continue
		}
		if r.read(1) == 0 {
			v := r.read(7)
			if r.bad || next.offset-start >= limit {
				return nil, ErrInvalid
			}
			next.history[next.offset] = byte(v) | 0x80
			next.offset++
			continue
		}
		var distance int
		if typ == Type8K {
			if r.read(1) == 0 {
				distance = 320 + r.read(13)
			} else if r.read(1) == 0 {
				distance = 64 + r.read(8)
			} else {
				distance = r.read(6)
			}
		} else {
			if r.read(1) == 0 {
				distance = 2368 + r.read(16)
			} else if r.read(1) == 0 {
				distance = 320 + r.read(11)
			} else if r.read(1) == 0 {
				distance = 64 + r.read(8)
			} else {
				distance = r.read(6)
			}
		}
		length := 3
		if r.read(1) != 0 {
			bits := 2
			for r.read(1) != 0 {
				bits++
				if bits > maxLengthBits {
					return nil, ErrInvalid
				}
			}
			length = 1<<bits | r.read(bits)
		}
		if r.bad || distance >= size || length > limit-(next.offset-start) {
			return nil, ErrInvalid
		}
		// Replicating copy, including overlap and references across the circular
		// history boundary. The output of one packet never wraps the buffer.
		for i := 0; i < length; i++ {
			next.history[next.offset] = next.history[(next.offset-distance)&(size-1)]
			next.offset++
		}
	}
	// Fewer than eight bits cannot encode another token. They are byte padding;
	// the format does not specify a padding bit value.
	out := append([]byte(nil), next.history[start:next.offset]...)
	*d = next
	return out, nil
}

type bitReader struct {
	data []byte
	pos  int
	bad  bool
}

func (r *bitReader) left() int { return len(r.data)*8 - r.pos }
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
