package rdpudp2

import "math"

// ExpandSequence reconstructs a 64-bit sequence from a nearby reference.
// The exactly-half-range case is ambiguous and is rejected, as are underflow
// and overflow. Callers must additionally enforce their active window.
func ExpandSequence(wire uint16, reference uint64) (uint64, error) {
	d := uint16(wire - uint16(reference))
	if d == 0x8000 {
		return 0, ErrInvalid
	}
	return addSigned(reference, int64(int16(d)))
}

func addSigned(v uint64, d int64) (uint64, error) {
	if d < 0 {
		if v < uint64(-d) {
			return 0, ErrInvalid
		}
		return v - uint64(-d), nil
	}
	if v > math.MaxUint64-uint64(d) {
		return 0, ErrInvalid
	}
	return v + uint64(d), nil
}

// ExpandTimestamp returns microseconds using the peer's own clock reference,
// not the local wall clock. It rejects ambiguous/out-of-range reconstruction
// and the spec's more-than-32-second future result. No clock synchronization
// or RTT estimate follows merely from decoding this value.
func ExpandTimestamp(wire uint32, referenceUS uint64) (uint64, error) {
	if wire > 0xffffff {
		return 0, ErrInvalid
	}
	d := (wire - uint32(referenceUS/4)) & 0xffffff
	if d == 0x800000 {
		return 0, ErrInvalid
	}
	delta := int64(d)
	if d&0x800000 != 0 {
		delta -= 1 << 24
	}
	v, err := addSigned(referenceUS/4, delta)
	if err != nil || v > math.MaxUint64/4 {
		return 0, ErrInvalid
	}
	v *= 4
	if v > referenceUS && v-referenceUS > 32000000 {
		return 0, ErrInvalid
	}
	return v, nil
}

// NextChannel skips zero in the on-wire 16-bit Windows channel counter,
// including on wrap; coded datagram counters do not skip zero.
func NextChannel(current uint64) (uint64, error) {
	if current == math.MaxUint64 {
		return 0, ErrLimit
	}
	n := current + 1
	if uint16(n) == 0 {
		n++
	}
	return n, nil
}

// VectorSpan validates both bitmap and run-length entries. A zero-length RLE
// entry has no meaning and is rejected. Memory is never allocated from a
// sequence number supplied by the network.
func VectorSpan(codes []byte) (int, error) {
	if len(codes) == 0 {
		return 0, ErrInvalid
	}
	if len(codes) > MaxVectorBytes {
		return 0, ErrLimit
	}
	n := 0
	for _, c := range codes {
		if c&128 == 0 {
			n += 7
		} else {
			if c&63 == 0 {
				return 0, ErrInvalid
			}
			n += int(c & 63)
		}
	}
	return n, nil
}

func DecodeVector(codes []byte) ([]bool, error) {
	n, err := VectorSpan(codes)
	if err != nil {
		return nil, err
	}
	out := make([]bool, 0, n)
	for _, c := range codes {
		if c&128 == 0 {
			for i := 0; i < 7; i++ {
				out = append(out, c&(1<<i) != 0)
			}
		} else {
			for i := 0; i < int(c&63); i++ {
				out = append(out, c&64 != 0)
			}
		}
	}
	return out, nil
}

// EncodeVector encodes exactly the provided states, without fictitious tail
// states. A vector too large for one payload is rejected; split it at a known
// sequence boundary and send multiple ACKVEC payloads instead.
func EncodeVector(states []bool) ([]byte, error) {
	if len(states) == 0 {
		return nil, ErrInvalid
	}
	if len(states) > MaxVectorSpan {
		return nil, ErrLimit
	}
	out := make([]byte, 0, min(len(states), MaxVectorBytes))
	for i := 0; i < len(states); {
		run := 1
		for run < 63 && i+run < len(states) && states[i+run] == states[i] {
			run++
		}
		if run >= 7 || len(states)-i < 7 {
			c := byte(128 | run)
			if states[i] {
				c |= 64
			}
			out = append(out, c)
			i += run
		} else {
			var c byte
			for j := 0; j < 7; j++ {
				if states[i+j] {
					c |= 1 << j
				}
			}
			out = append(out, c)
			i += 7
		}
		if len(out) > MaxVectorBytes {
			return nil, ErrLimit
		}
	}
	return out, nil
}
