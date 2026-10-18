package bulk

// RDP 6.0 uses canonical Huffman codes packed into the low bits of each byte,
// unlike MPPC's high-bit-first tokens. The published codewords are bit-reversed
// canonical numbers (MS-RDPEGDI 3.1.8.1.4).
type huffmanEntry struct {
	symbol uint16
	bits   byte
}
type huffmanTable struct {
	entries []huffmanEntry
	width   int
}

func fixedHuffman(lengths []byte, width int) huffmanTable {
	var counts, next [16]int
	for _, n := range lengths {
		if n == 0 || int(n) > width {
			panic("bulk: invalid fixed Huffman table")
		}
		counts[n]++
	}
	for n := 1; n <= width; n++ {
		next[n] = (next[n-1] + counts[n-1]) << 1
	}
	t := huffmanTable{entries: make([]huffmanEntry, 1<<width), width: width}
	for symbol, n := range lengths {
		code, value := 0, next[n]
		next[n]++
		for j := byte(0); j < n; j++ {
			code = code<<1 | value&1
			value >>= 1
		}
		for i := code; i < len(t.entries); i += 1 << n {
			if t.entries[i].bits != 0 {
				panic("bulk: overlapping fixed Huffman codes")
			}
			t.entries[i] = huffmanEntry{uint16(symbol), n}
		}
	}
	return t
}

var ncrushLiterals = fixedHuffman(ncrushLiteralLengths[:], 13)
var ncrushLengths = fixedHuffman(ncrushMatchLengths[:], 9)

type littleBitReader struct {
	data []byte
	pos  int
	bad  bool
}

func (r *littleBitReader) left() int { return len(r.data)*8 - r.pos }
func (r *littleBitReader) peek(n int) int {
	v := 0
	for i := 0; i < min(n, r.left()); i++ {
		p := r.pos + i
		v |= int((r.data[p/8]>>uint(p%8))&1) << i
	}
	return v
}
func (r *littleBitReader) read(n int) int {
	if n > r.left() {
		r.bad = true
		return 0
	}
	v := r.peek(n)
	r.pos += n
	return v
}
func (t huffmanTable) read(r *littleBitReader) int {
	e := t.entries[r.peek(t.width)]
	if e.bits == 0 || int(e.bits) > r.left() {
		r.bad = true
		return -1
	}
	r.pos += int(e.bits)
	return int(e.symbol)
}

func (d *Decoder) decodeNCrush(flags byte, src []byte, limit int) ([]byte, error) {
	next := *d
	if flags&Flushed != 0 {
		next.Reset()
	}
	if next.initialized && next.typ != TypeRDP6 {
		return nil, ErrInvalid
	}
	next.typ, next.initialized = TypeRDP6, true
	if flags&AtFront != 0 && flags&Flushed == 0 {
		if next.offset < 32768 {
			return nil, ErrInvalid
		}
		// Keep the most recent half-window relative to the current history end.
		copy(next.history[:32768], next.history[next.offset-32768:next.offset])
		clear(next.history[32768:])
		next.offset = 32768
	}
	start := next.offset
	limit = min(limit, 65535, len(next.history)-start)
	r := littleBitReader{data: src}
	for {
		symbol := ncrushLiterals.read(&r)
		if r.bad {
			return nil, ErrInvalid
		}
		if symbol == 256 {
			break
		} // remaining wire bits are padding, not another PDU
		if symbol < 256 {
			if next.offset-start >= limit {
				return nil, ErrInvalid
			}
			next.history[next.offset] = byte(symbol)
			next.offset++
			continue
		}
		var distance int
		if symbol < 289 {
			index := symbol - 257
			distance = ncrushOffsetBase[index] + r.read(int(ncrushOffsetBits[index])) - 1
			copy(next.offsetCache[1:], next.offsetCache[:3])
			next.offsetCache[0] = distance
			next.offsetCount = min(next.offsetCount+1, 4)
		} else {
			index := symbol - 289
			if index >= next.offsetCount {
				return nil, ErrInvalid
			}
			distance = next.offsetCache[index]
			// A cache hit swaps with the head; it does not shift intermediate entries.
			next.offsetCache[index], next.offsetCache[0] = next.offsetCache[0], distance
		}
		index := ncrushLengths.read(&r)
		if r.bad || index < 0 || index >= len(ncrushLengthBase) {
			return nil, ErrInvalid
		}
		length := ncrushLengthBase[index] + r.read(int(ncrushLengthBits[index]))
		if r.bad || distance < 0 || distance >= 65536 || length > limit-(next.offset-start) {
			return nil, ErrInvalid
		}
		for i := 0; i < length; i++ {
			next.history[next.offset] = next.history[(next.offset-distance)&65535]
			next.offset++
		}
	}
	out := append([]byte(nil), next.history[start:next.offset]...)
	*d = next
	return out, nil
}
