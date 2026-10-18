package bulk

import (
	"encoding/binary"
	"fmt"
)

const rdp61HistorySize = 2000000
const rdp61BlockLimit = 16382 // strictly less than 16383 (MS-RDPEGDI 3.1.8.2.1)

type rdp61State struct {
	history []byte
	offset  int
	inner   Decoder // separate RDP5 history used only by this compression chain
}

func (d *Decoder) decodeRDP61(flags byte, src []byte, limit int) ([]byte, error) {
	if len(src) < 2 || src[0]&^byte(0x17) != 0 || src[0]&3 != 1 && src[0]&3 != 2 {
		return nil, fmt.Errorf("%w: RDP6.1 L1 header", ErrInvalid)
	}
	if d.initialized && d.typ != TypeRDP61 && flags&Flushed == 0 {
		return nil, fmt.Errorf("%w: RDP6.1 package change without flush", ErrInvalid)
	}
	state := d.rdp61
	flush := flags&Flushed != 0
	front := src[0]&4 != 0 || flush
	start := 0
	var inner Decoder
	if state != nil && flags&Flushed == 0 {
		inner = state.inner
		if !front {
			start = state.offset
		}
	}
	limit = min(limit, rdp61BlockLimit, rdp61HistorySize-start)
	l1, l2 := src[0], src[1]
	data := src[2:]
	if l1&0x10 != 0 {
		// Windows omits the package hint for an uncompressed L2 fallback,
		// notably 0x80 (raw + FLUSHED). Only compressed bytes require type 1.
		if l2&15 != Type64K && (l2&Compressed != 0 || l2&15 != Type8K) {
			return nil, fmt.Errorf("%w: RDP6.1 L2 flags 0x%02x", ErrInvalid, l2)
		}
		var err error
		// The intermediate match table can be larger than the final output.
		data, err = inner.Decode(l2, data, MaxDecoded)
		if err != nil {
			return nil, fmt.Errorf("RDP6.1 L2 flags 0x%02x: %w", l2, err)
		}
	}
	// Stage at most one block. Reading through this overlay implements a
	// replicating copy without mutating (or cloning) the 2 MB history on errors.
	out := make([]byte, 0, min(limit, len(data)))
	if l1&2 != 0 {
		if len(data) > limit {
			return nil, fmt.Errorf("%w: RDP6.1 literals %d exceed budget %d", ErrInvalid, len(data), limit)
		}
		out = append(out, data...)
	} else {
		if len(data) < 2 {
			return nil, fmt.Errorf("%w: RDP6.1 missing match count", ErrInvalid)
		}
		count := int(binary.LittleEndian.Uint16(data))
		data = data[2:]
		if count == 0 || count > len(data)/8 {
			return nil, fmt.Errorf("%w: RDP6.1 match table size", ErrInvalid)
		}
		matches, literals := data[:count*8], data[count*8:]
		for len(matches) > 0 {
			length := int(binary.LittleEndian.Uint16(matches))
			outputOffset := int(binary.LittleEndian.Uint16(matches[2:]))
			source := uint64(binary.LittleEndian.Uint32(matches[4:]))
			matches = matches[8:]
			gap := outputOffset - len(out)
			if length == 0 || gap < 0 || gap > len(literals) || outputOffset > limit || length > limit-outputOffset || source+uint64(length) > rdp61HistorySize {
				return nil, fmt.Errorf("%w: RDP6.1 match bounds (length %d, output %d, source %d, budget %d)", ErrInvalid, length, outputOffset, source, limit)
			}
			out = append(out, literals[:gap]...)
			literals = literals[gap:]
			for i := 0; i < length; i++ {
				p := int(source) + i
				var value byte
				if p >= start && p < start+len(out) {
					value = out[p-start]
				} else if !flush && state != nil {
					value = state.history[p]
				}
				out = append(out, value)
			}
		}
		if len(literals) > limit-len(out) {
			return nil, fmt.Errorf("%w: RDP6.1 trailing literals exceed budget", ErrInvalid)
		}
		out = append(out, literals...)
	}
	// Commit both levels together only after all match/literal bounds succeeded.
	if state == nil {
		state = &rdp61State{history: make([]byte, rdp61HistorySize)}
	} else if flush {
		clear(state.history)
	}
	// L1_PACKET_AT_FRONT rewinds the insertion offset. Windows 10 continues
	// referencing untouched bytes beyond the new offset (observed in real
	// streams after the 2,000,000-byte wrap). Preserve that history as shown by
	// the offset-only reset in MS-RDPEGDI 3.1.8.2.3's decoding flowchart, despite
	// the zero-fill wording in 2.2.2.4.1. An outer FLUSHED still clears both levels.
	copy(state.history[start:], out)
	state.offset, state.inner = start+len(out), inner
	if flags&Flushed != 0 {
		d.Reset()
	}
	d.typ, d.initialized, d.rdp61 = TypeRDP61, true, state
	return out, nil
}
