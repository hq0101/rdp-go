package bulk

// Encoder compresses client-to-server static-channel chunks using RDP 4.0
// (8K), the only bulk package permitted in that direction. It uses a bounded
// single-candidate hash table: a missed match costs bandwidth, not correctness.
// Calls must be serialized. Once Encode succeeds the returned packet must be
// sent in order, or the connection must be discarded. Results own their bytes.
type Encoder struct {
	history [8192]byte
	offset  int
}

func (e *Encoder) Reset() { *e = Encoder{} }

func (e *Encoder) Encode(src []byte) (flags byte, payload []byte, err error) {
	if len(src) >= len(e.history) {
		return 0, nil, ErrInvalid
	}
	if len(src) == 0 {
		return 0, nil, nil
	}
	flags = Compressed
	if e.offset == 0 || e.offset+len(src) > len(e.history) {
		e.offset = 0
		flags |= AtFront
	}
	start, end := e.offset, e.offset+len(src)
	copy(e.history[start:end], src)
	var table [4096]int
	for i := range table {
		table[i] = -1
	}
	hash := func(p int) int {
		return (int(e.history[p])*251*251 + int(e.history[p+1])*251 + int(e.history[p+2])) & 4095
	}
	// Only refer backwards within the current prefix. Retained history after
	// AT_FRONT is legal but intentionally not searched by this encoder.
	for i := 0; i < start && i+2 < end; i++ {
		table[hash(i)] = i
	}
	w := bitWriter{}
	for pos := start; pos < end; {
		match, distance := 0, 0
		if pos+2 < end {
			candidate := table[hash(pos)]
			if candidate >= 0 && candidate < pos {
				for pos+match < end && e.history[candidate+match] == e.history[pos+match] {
					match++
				}
				distance = pos - candidate
			}
		}
		if match >= 3 {
			switch {
			case distance < 64:
				w.put(15, 4)
				w.put(distance, 6)
			case distance < 320:
				w.put(14, 4)
				w.put(distance-64, 8)
			default:
				w.put(6, 3)
				w.put(distance-320, 13)
			}
			if match == 3 {
				w.put(0, 1)
			} else {
				bits := 2
				for 1<<(bits+1) <= match {
					bits++
				}
				w.put((1<<bits)-2, bits)
				w.put(match-(1<<bits), bits)
			}
		} else {
			match = 1
			v := int(e.history[pos])
			if v < 128 {
				w.put(v, 8)
			} else {
				w.put(2, 2)
				w.put(v&127, 7)
			}
		}
		for i := pos; i < pos+match && i+2 < end; i++ {
			table[hash(i)] = i
		}
		pos += match
	}
	if len(w.data) >= len(src) {
		// Raw data never enters the receiver's history. Flush both ends before
		// any following references, including when encoded and raw sizes tie.
		e.Reset()
		return Flushed, append([]byte(nil), src...), nil
	}
	e.offset = end
	return flags, w.data, nil
}

type bitWriter struct {
	data []byte
	bits int
}

func (w *bitWriter) put(v, n int) {
	for i := n - 1; i >= 0; i-- {
		if w.bits%8 == 0 {
			w.data = append(w.data, 0)
		}
		w.data[w.bits/8] |= byte((v>>i)&1) << uint(7-w.bits%8)
		w.bits++
	}
}
