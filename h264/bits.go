package h264

// A bounded MSB-first RBSP reader. A failed read never advances beyond its
// input, and variable-length codes have a fixed 32-bit work bound.
type bitReader struct {
	data []byte
	pos  int
	bad  bool
}

func (r *bitReader) read(n int) uint32 {
	if r.bad || n < 0 || n > 32 || n > len(r.data)*8-r.pos {
		r.bad = true
		return 0
	}
	var v uint32
	for ; n > 0; n-- {
		v = v<<1 | uint32((r.data[r.pos/8]>>uint(7-r.pos%8))&1)
		r.pos++
	}
	return v
}
func (r *bitReader) flag() bool { return r.read(1) != 0 }
func (r *bitReader) ue(maximum uint32) uint32 {
	zeros := 0
	for !r.bad && r.read(1) == 0 {
		zeros++
		if zeros > 31 {
			r.bad = true
		}
	}
	if r.bad {
		return 0
	}
	v := (uint32(1) << uint(zeros)) - 1 + r.read(zeros)
	if v > maximum {
		r.bad = true
		return 0
	}
	return v
}
func (r *bitReader) se(low, high int) int {
	v := r.ue(^uint32(0) - 1)
	n := int64((uint64(v) + 1) / 2)
	if v&1 == 0 {
		n = -n
	}
	if n < int64(low) || n > int64(high) {
		r.bad = true
		return 0
	}
	return int(n)
}

// more distinguishes payload from a stop bit and its byte-alignment zeros.
// RBSP trailing bits occupy at most one byte, so this is constant work.
func (r *bitReader) more() bool {
	remaining := len(r.data)*8 - r.pos
	if r.bad || remaining <= 0 {
		return false
	}
	if remaining > 8 {
		return true
	}
	x := *r
	return x.read(remaining) != uint32(1)<<uint(remaining-1)
}
func (r *bitReader) trailing() error {
	if r.read(1) != 1 {
		r.bad = true
	}
	for r.pos%8 != 0 && !r.bad {
		if r.read(1) != 0 {
			r.bad = true
		}
	}
	if r.bad || r.pos != len(r.data)*8 {
		return ErrInvalid
	}
	return nil
}
