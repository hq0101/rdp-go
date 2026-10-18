package graphics

import "image"

// Progressive coefficients are stored at twice the RemoteFX 11.5 fixed-point
// scale. This represents scalar quantization zero exactly, including a sequence
// of upgrades whose individual contributions would otherwise round to zero.
// Limit accumulated differences before the inverse transform can overflow.
const progressiveCoefficientLimit int64 = 1 << 52

type progressivePlane struct {
	coeff [4096]int64
	sign  [4096]int8
	bits  [10]byte // scalar + progressive quantization, in wire band order
}
type progressiveTile struct {
	planes [3]progressivePlane
	reduce bool
}
type progressiveBand struct{ offset, length, quant int }

// Progressive wire order differs from RemoteFX: LL3,HL3,LH3,HH3,HL2,LH2,
// HH2,HL1,LH1,HH1. Linear coefficient order remains HL1,LH1,HH1,...,LL3.
func progressiveBands(reduce bool) [10]progressiveBand {
	lengths := [10]int{1024, 1024, 1024, 256, 256, 256, 64, 64, 64, 64}
	if reduce {
		lengths = [10]int{1023, 1023, 961, 272, 272, 256, 72, 72, 64, 81}
	}
	indices := [10]int{7, 8, 9, 4, 5, 6, 1, 2, 3, 0}
	var bands [10]progressiveBand
	offset := 0
	for i, n := range lengths {
		bands[i] = progressiveBand{offset, n, indices[i]}
		offset += n
	}
	return bands
}

func progressiveBitPositions(base, extra [10]byte) ([10]byte, error) {
	var out [10]byte
	for i := range out {
		if base[i] > 15 || extra[i] > 8 {
			return out, ErrInvalid
		}
		out[i] = base[i] + extra[i]
	}
	return out, nil
}
func progressiveAdd(dst *int64, value int64, shift byte) error {
	// Every first-pass coefficient is bounded by RLGR's signed 16-bit range
	// (LL3 cumulative sums have at most 81 terms); upgrades have <=23 bits.
	if shift > 23 || value > progressiveCoefficientLimit>>shift || value < -(progressiveCoefficientLimit>>shift) {
		return ErrInvalid
	}
	value <<= shift
	if value > 0 && *dst > progressiveCoefficientLimit-value || value < 0 && *dst < -progressiveCoefficientLimit-value {
		return ErrInvalid
	}
	*dst += value
	return nil
}
func progressiveSign(v int64) int8 {
	if v < 0 {
		return -1
	}
	if v > 0 {
		return 1
	}
	return 0
}

// firstProgressiveTile implements the first pass, including the full-quality
// SIMPLE case (zero extra quantization). A difference is based on the current
// reconstructed reference, even if that reference was only partly refined.
// Returned state is independent; failure never changes previous state.
func firstProgressiveTile(previous *progressiveTile, data [3][]byte, base, extra [3][10]byte, reduce, difference bool) (*progressiveTile, error) {
	if difference && (previous == nil || previous.reduce != reduce) {
		return nil, ErrInvalid
	}
	next := &progressiveTile{reduce: reduce}
	if difference {
		*next = *previous
	}
	bands := progressiveBands(reduce)
	ll := bands[9].offset
	for component := range next.planes {
		positions, err := progressiveBitPositions(base[component], extra[component])
		if err != nil {
			return nil, err
		}
		decoded, _, err := decodeRFXEntropy(data[component], 1)
		if err != nil {
			return nil, err
		}
		// FIRST/SIMPLE LL3 values are differences between adjacent quantized
		// coefficients, also for a full-quality difference tile. Accumulate
		// before inverse quantization and adding the previous tile reference.
		// Windows 10 quality=255 FIRST captures exercise this case; treating
		// Diff-LL as already reconstructed leaves taskbar-shaped artifacts.
		for i := ll + 1; i < len(decoded); i++ {
			decoded[i] += decoded[i-1]
		}
		plane := &next.planes[component]
		plane.bits = positions
		clear(plane.sign[:])
		for _, band := range bands {
			for i := band.offset; i < band.offset+band.length; i++ {
				if i < ll {
					plane.sign[i] = progressiveSign(decoded[i])
				}
				if err := progressiveAdd(&plane.coeff[i], decoded[i], positions[band.quant]); err != nil {
					return nil, err
				}
			}
		}
	}
	return next, nil
}

// SRL is one continuous stream of zero-sign coefficients across all non-LL
// bands, skipping bands with no new bits. Its pending zero run can span bands
// with different bit depths. The unary value uses the depth of its own element.
type progressiveSRL struct {
	reader    rfxBits
	kp, zeros int
	nonzero   bool
}

func (s *progressiveSRL) next(bits int) (int64, error) {
	if bits < 1 || bits > 23 {
		return 0, ErrInvalid
	}
	if s.zeros > 0 {
		s.zeros--
		return 0, nil
	}
	if !s.nonzero {
		k := s.kp >> 3
		b := s.reader.read(1)
		if s.reader.bad {
			return 0, ErrInvalid
		}
		if b == 0 {
			s.zeros = (1 << k) - 1
			s.kp = rfxAdapt(s.kp, 4)
			return 0, nil
		}
		run := int(s.reader.read(k))
		if s.reader.bad {
			return 0, ErrInvalid
		}
		s.kp = rfxAdapt(s.kp, -6)
		s.nonzero = true
		if run > 0 {
			s.zeros = run - 1
			return 0, nil
		}
	}
	sign := s.reader.read(1)
	mag, maximum := int64(1), int64(1<<bits)-1
	for mag < maximum && !s.reader.bad {
		if s.reader.read(1) != 0 {
			break
		}
		mag++
	}
	if s.reader.bad {
		return 0, ErrInvalid
	}
	s.nonzero = false
	if sign != 0 {
		mag = -mag
	}
	return mag, nil
}
func progressiveRaw(r *rfxBits, n int) int64 {
	if n <= 18 {
		return int64(r.read(n))
	}
	return int64(r.read(n-18))<<18 | int64(r.read(18))
}

func upgradeProgressiveTile(previous *progressiveTile, srl, raw [3][]byte, base, extra [3][10]byte) (*progressiveTile, error) {
	if previous == nil {
		return nil, ErrInvalid
	}
	next := new(progressiveTile)
	*next = *previous
	bands := progressiveBands(next.reduce)
	ll := bands[9].offset
	for component := range next.planes {
		positions, err := progressiveBitPositions(base[component], extra[component])
		if err != nil {
			return nil, err
		}
		if len(srl[component]) > 65535 || len(raw[component]) > 65535 {
			return nil, ErrInvalid
		}
		// The encoder description mentions extra zero padding, but Windows 10
		// emits SRL fields ending in actual nonzero payload bits. This bounded
		// reader does not need lookahead: consume only the required coefficients
		// from the declared field, leaving unused tail bits/bytes uninterpreted.
		s := progressiveSRL{kp: 8, reader: rfxBits{data: srl[component]}}
		r := rfxBits{data: raw[component]}
		plane := &next.planes[component]
		for _, band := range bands {
			bits := int(plane.bits[band.quant]) - int(positions[band.quant])
			if bits < 0 {
				return nil, ErrInvalid
			}
			if bits == 0 {
				continue
			}
			for i := band.offset; i < band.offset+band.length; i++ {
				var value int64
				if i >= ll || plane.sign[i] != 0 {
					value = progressiveRaw(&r, bits)
					if r.bad {
						return nil, ErrInvalid
					}
					if i < ll && plane.sign[i] < 0 {
						value = -value
					}
					// Sign represents cumulative DAS, not just this upgrade.
					// A raw zero must not erase an already known sign.
				} else {
					value, err = s.next(bits)
					if err != nil {
						return nil, err
					}
					plane.sign[i] = progressiveSign(value)
				}
				if err := progressiveAdd(&plane.coeff[i], value, positions[band.quant]); err != nil {
					return nil, err
				}
			}
		}
		plane.bits = positions
	}
	return next, nil
}

// inverseProgressiveLine reconstructs 2*N-1 samples from N low-frequency
// samples. At the outer level the absent final high-frequency value is zero;
// the resulting extrapolated 65th sample is dropped by a 64-element dst.
func inverseProgressiveLine(low, high, dst []int64) {
	h := func(i int) int64 {
		if i >= len(high) {
			return 0
		}
		return high[i]
	}
	var even [33]int64
	for i := range low {
		previous, next := max(i-1, 0), min(i, len(low)-2)
		even[i] = low[i] - ((h(previous) + h(next) + 1) >> 1)
		if 2*i < len(dst) {
			dst[2*i] = even[i]
		}
	}
	for i := 0; 2*i+1 < len(dst); i++ {
		dst[2*i+1] = 2*h(i) + ((even[i] + even[i+1]) >> 1)
	}
}
func inverseProgressiveLevel(dst, low, hl, lh, hh []int64, n, h, w int, scratch *[4096]int64) {
	lo, hi := scratch[:n*w], scratch[n*w:(n+h)*w]
	for y := 0; y < n; y++ {
		inverseProgressiveLine(low[y*n:(y+1)*n], hl[y*h:(y+1)*h], lo[y*w:(y+1)*w])
	}
	for y := 0; y < h; y++ {
		inverseProgressiveLine(lh[y*n:(y+1)*n], hh[y*h:(y+1)*h], hi[y*w:(y+1)*w])
	}
	var l, high [33]int64
	var line [65]int64
	for x := 0; x < w; x++ {
		for y := 0; y < n; y++ {
			l[y] = lo[y*w+x]
		}
		for y := 0; y < h; y++ {
			high[y] = hi[y*w+x]
		}
		inverseProgressiveLine(l[:n], high[:h], line[:w])
		for y := 0; y < w; y++ {
			dst[y*w+x] = line[y]
		}
	}
}
func renderProgressiveTile(tile *progressiveTile) *image.NRGBA {
	var coeff [3][4096]int64
	var scratch [4096]int64
	for c := range coeff {
		for i, v := range tile.planes[c].coeff {
			coeff[c][i] = v >> 1
		}
		p := coeff[c][:]
		if tile.reduce {
			inverseProgressiveLevel(p[3807:], p[4015:], p[3807:3879], p[3879:3951], p[3951:4015], 9, 8, 17, &scratch)
			inverseProgressiveLevel(p[3007:], p[3807:], p[3007:3279], p[3279:3551], p[3551:3807], 17, 16, 33, &scratch)
			inverseProgressiveLevel(p, p[3007:], p[:1023], p[1023:2046], p[2046:3007], 33, 31, 64, &scratch)
		} else {
			inverseRFXWithScratch(&coeff[c], &scratch)
		}
	}
	return rfxRGB(coeff[0][:], coeff[1][:], coeff[2][:])
}
