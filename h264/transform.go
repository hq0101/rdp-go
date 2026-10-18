package h264

// Intra 4x4 scaling matrices, in raster order. H.264 7.4.2.1.1/7.4.2.2
// distinguish an absent matrix from a present matrix whose lists are absent.
func intraWeights(s *SPS, p PPS) [3][16]int32 { return scalingWeights4(s, p, false) }

func scalingWeights4(s *SPS, p PPS, inter bool) (out [3][16]int32) {
	def := [16]byte{6, 13, 13, 20, 20, 20, 28, 28, 28, 28, 32, 32, 32, 37, 37, 42}
	base := 0
	if inter {
		base = 3
		def = [16]byte{10, 14, 14, 20, 20, 20, 24, 24, 24, 24, 27, 27, 27, 30, 30, 34}
	}
	var seq, pic [3][16]byte
	for i := 0; i < 3; i++ {
		for j := range seq[i] {
			seq[i][j] = 16
		}
		if s.ScalingMatrixPresent {
			switch {
			case s.Scaling[i+base].Present && !s.Scaling[i+base].Default:
				copy(seq[i][:], s.Scaling[i+base].Values[:16])
			case s.Scaling[i+base].Present || i == 0:
				seq[i] = def
			default:
				seq[i] = seq[i-1]
			}
		}
		pic[i] = seq[i]
		if p.ScalingMatrixPresent {
			switch {
			case p.Scaling[i+base].Present && !p.Scaling[i+base].Default:
				copy(pic[i][:], p.Scaling[i+base].Values[:16])
			case p.Scaling[i+base].Present:
				pic[i] = def
			case i != 0:
				pic[i] = pic[i-1]
			case !s.ScalingMatrixPresent:
				pic[i] = def
			}
		}
		for j, v := range pic[i] {
			out[i][scan4[j]] = int32(v)
		}
	}
	return
}

var norm4 = [6][3]int64{{10, 16, 13}, {11, 18, 14}, {13, 20, 16}, {14, 23, 18}, {16, 25, 20}, {18, 29, 23}}

func in16(v int64) bool { return v >= -32768 && v <= 32767 }

// Inverse 4x4 scaling and integer transform (8.5.12). Arithmetic uses int64
// before checking each normative eight-bit intermediate range, never wrapping.
func inverse4(c [16]int32, qp int, weight [16]int32, dcReady bool) (out [16]int32, err error) {
	var d, f [16]int64
	for i, v := range c {
		if !in16(int64(v)) {
			return out, ErrInvalid
		}
		if i == 0 && dcReady {
			d[i] = int64(v)
		} else {
			k := 2
			if i%2 == 0 && i/4%2 == 0 {
				k = 0
			}
			if i%2 == 1 && i/4%2 == 1 {
				k = 1
			}
			x := int64(v) * int64(weight[i]) * norm4[qp%6][k]
			if qp >= 24 {
				d[i] = x << (qp/6 - 4)
			} else {
				d[i] = (x + (1 << (3 - qp/6))) >> (4 - qp/6)
			}
		}
		if !in16(d[i]) {
			return out, ErrInvalid
		}
	}
	line := func(a, b, c, d int64) ([4]int64, bool) {
		e := [4]int64{a + c, a - c, (b >> 1) - d, b + (d >> 1)}
		for _, v := range e {
			if !in16(v) {
				return [4]int64{}, false
			}
		}
		v := [4]int64{e[0] + e[3], e[1] + e[2], e[1] - e[2], e[0] - e[3]}
		for _, n := range v {
			if !in16(n) {
				return v, false
			}
		}
		return v, true
	}
	for y := 0; y < 4; y++ {
		v, ok := line(d[y*4], d[y*4+1], d[y*4+2], d[y*4+3])
		if !ok {
			return out, ErrInvalid
		}
		copy(f[y*4:y*4+4], v[:])
	}
	for x := 0; x < 4; x++ {
		v, ok := line(f[x], f[x+4], f[x+8], f[x+12])
		if !ok {
			return out, ErrInvalid
		}
		for y, n := range v {
			if n > 32735 {
				return out, ErrInvalid
			} // h + 32 must fit
			out[y*4+x] = int32((n + 32) >> 6)
		}
	}
	return
}

func lumaDC(c [16]int32, qp int, weight int32) (out [16]int32, err error) {
	// H*c*H, with H as specified by Equation 8-320.
	h := [4][4]int64{{1, 1, 1, 1}, {1, 1, -1, -1}, {1, -1, -1, 1}, {1, -1, 1, -1}}
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			var f int64
			for i := 0; i < 4; i++ {
				for j := 0; j < 4; j++ {
					f += h[y][i] * int64(c[i*4+j]) * h[j][x]
				}
			}
			if !in16(f) {
				return out, ErrInvalid
			}
			d := f * int64(weight) * norm4[qp%6][0]
			if qp >= 36 {
				d <<= qp/6 - 6
			} else {
				d = (d + (1 << (5 - qp/6))) >> (6 - qp/6)
			}
			if !in16(d) {
				return out, ErrInvalid
			}
			out[y*4+x] = int32(d)
		}
	}
	return
}

func chromaDC(c [4]int32, qp int, weight int32) (out [4]int32, err error) {
	for y := 0; y < 2; y++ {
		for x := 0; x < 2; x++ {
			var f int64
			for i := 0; i < 2; i++ {
				for j := 0; j < 2; j++ {
					v := int64(c[i*2+j])
					if (i*y+j*x)%2 == 1 {
						v = -v
					}
					f += v
				}
			}
			if !in16(f) {
				return out, ErrInvalid
			}
			d := ((f * int64(weight) * norm4[qp%6][0]) << (qp / 6)) >> 5
			if !in16(d) {
				return out, ErrInvalid
			}
			out[y*2+x] = int32(d)
		}
	}
	return
}
