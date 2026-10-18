package graphics

import (
	"fmt"
	"image"
	"math/bits"
)

// RemoteFX tile components are independent. All intermediate arithmetic is
// widened: malformed but bounded coefficient streams must never wrap the 16-bit
// or 32-bit arithmetic commonly used by native image implementations.
const rfxTilePixels = 64 * 64

type rfxBits struct {
	data []byte
	pos  int
	bad  bool
}

func (r *rfxBits) read(n int) uint32 {
	if r.bad || n < 0 || n > 18 || n > len(r.data)*8-r.pos {
		r.bad = true
		return 0
	}
	var v uint32
	for i := 0; i < n; i++ {
		v = v<<1 | uint32(r.data[r.pos/8]>>(7-r.pos%8)&1)
		r.pos++
	}
	return v
}

func rfxAdapt(p, delta int) int { return min(80, max(0, p+delta)) }

func (r *rfxBits) golomb(krp *int) uint32 {
	k := *krp >> 3
	var q uint32
	for r.read(1) != 0 && !r.bad {
		q++
		// Two signed 16-bit coefficients produce at most two 65535 codes.
		if q > 131070>>k {
			r.bad = true
			return 0
		}
	}
	v := q<<k | r.read(k)
	if v > 131070 {
		r.bad = true
	}
	if q == 0 {
		*krp = rfxAdapt(*krp, -2)
	} else if q > 1 {
		*krp = rfxAdapt(*krp, int(q))
	}
	return v
}

func rfxSigned(v uint32) (int64, bool) {
	if v > 65535 {
		return 0, false
	}
	if v&1 != 0 {
		return -int64((v + 1) / 2), true
	}
	return int64(v / 2), true
}

// decodeRFXEntropy follows the parameter rules in MS-RDPRFX 3.1.8.1.7.
// mode is the wire entropy identifier, 1 (RLGR1) or 4 (RLGR3).
func decodeRFXEntropy(src []byte, mode byte) (out [rfxTilePixels]int64, used int, err error) {
	if len(src) == 0 || len(src) > 65535 || mode != 1 && mode != 4 {
		return out, 0, ErrInvalid
	}
	r := rfxBits{data: src}
	kp, krp, pos := 8, 8, 0
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: RemoteFX entropy at coefficient %d, bit %d", err, pos, r.pos)
		}
	}()
	put := func(v uint32) bool {
		s, ok := rfxSigned(v)
		if !ok || pos >= len(out) {
			return false
		}
		out[pos] = s
		pos++
		return true
	}
	for pos < len(out) && !r.bad {
		k := kp >> 3
		if k != 0 {
			for r.read(1) == 0 && !r.bad {
				run := min(1<<k, len(out)-pos)
				pos += run
				kp = rfxAdapt(kp, 4)
				k = kp >> 3
				if pos == len(out) {
					break
				}
			}
			if r.bad {
				break
			}
			if pos == len(out) {
				break
			}
			run := min(int(r.read(k)), len(out)-pos)
			if r.bad {
				return out, 0, ErrInvalid
			}
			pos += run
			if pos == len(out) {
				break
			}
			sign := r.read(1)
			mag := r.golomb(&krp) + 1
			if r.bad || mag > 32768 || sign == 0 && mag > 32767 {
				return out, 0, ErrInvalid
			}
			v := int64(mag)
			if sign != 0 {
				v = -v
			}
			out[pos] = v
			pos++
			kp = rfxAdapt(kp, -6)
		} else {
			v := r.golomb(&krp)
			if mode == 1 {
				if r.bad || !put(v) {
					return out, 0, ErrInvalid
				}
				if v == 0 {
					kp = rfxAdapt(kp, 3)
				} else {
					kp = rfxAdapt(kp, -3)
				}
			} else {
				first := r.read(bits.Len32(v))
				if r.bad || first > v {
					return out, 0, ErrInvalid
				}
				second := v - first
				if !put(first) {
					return out, 0, ErrInvalid
				}
				// WriteValue/WriteZeroes stop at the tile's coefficient count.
				// The public sample ends on a pair's first member, and its
				// unused second member is not necessarily zero.
				if pos < len(out) {
					if !put(second) {
						return out, 0, ErrInvalid
					}
				}
				if first == 0 && second == 0 {
					kp = rfxAdapt(kp, 6)
				} else if first != 0 && second != 0 {
					kp = rfxAdapt(kp, -6)
				}
			}
		}
	}
	if r.bad || pos != len(out) {
		return out, 0, ErrInvalid
	}
	return out, r.pos, nil
}

// Quant order on wire is LL3,LH3,HL3,HH3,LH2,HL2,HH2,LH1,HL1,HH1.
// Linear coefficient order is HL1,LH1,HH1,HL2,LH2,HH2,HL3,LH3,HH3,LL3.
func reconstructRFX(coeff *[rfxTilePixels]int64, quant [10]byte) error {
	for _, q := range quant {
		if q < 6 || q > 15 {
			return ErrInvalid
		}
	}
	for i := 4033; i < 4096; i++ {
		coeff[i] += coeff[i-1]
	}
	offset := 0
	for i, qi := range [...]int{8, 7, 9, 5, 4, 6, 2, 1, 3, 0} {
		n := 1024
		if i >= 3 {
			n = 256
		}
		if i >= 6 {
			n = 64
		}
		// 11.5 fixed point: quantization scale 2^(q-6), then 5 fraction bits.
		for j := offset; j < offset+n; j++ {
			coeff[j] <<= quant[qi] - 1
		}
		offset += n
	}
	return nil
}

// Inverse 5/3 lifting, with symmetric extension at both boundaries. Go's signed
// right shift implements the floor divisions in the normative equations.
func inverseRFXLine(low, high, dst []int64) {
	n := len(low)
	for i := 0; i < n; i++ {
		prev := max(0, i-1)
		dst[2*i] = low[i] - ((high[prev] + high[i] + 1) >> 1)
	}
	for i := 0; i < n; i++ {
		next := min(n-1, i+1)
		dst[2*i+1] = 2*high[i] + ((dst[2*i] + dst[2*next]) >> 1)
	}
}

func inverseRFXLevel(low, hl, lh, hh []int64, n int) []int64 {
	out := make([]int64, 4*n*n)
	var scratch [4096]int64
	inverseRFXLevelInto(out, low, hl, lh, hh, n, &scratch)
	return out
}

func inverseRFXLevelInto(out, low, hl, lh, hh []int64, n int, scratch *[4096]int64) {
	width := n * 2
	lo, hi := scratch[:n*width], scratch[n*width:2*n*width]
	for y := 0; y < n; y++ {
		inverseRFXLine(low[y*n:(y+1)*n], hl[y*n:(y+1)*n], lo[y*width:(y+1)*width])
		inverseRFXLine(lh[y*n:(y+1)*n], hh[y*n:(y+1)*n], hi[y*width:(y+1)*width])
	}
	// Every input row is now in scratch; output may overlap any input band.
	var l, h, line [64]int64
	for x := 0; x < width; x++ {
		for y := 0; y < n; y++ {
			l[y], h[y] = lo[y*width+x], hi[y*width+x]
		}
		inverseRFXLine(l[:n], h[:n], line[:width])
		for y := 0; y < width; y++ {
			out[y*width+x] = line[y]
		}
	}
}

func inverseRFX(coeff *[rfxTilePixels]int64) []int64 {
	var scratch [4096]int64
	return inverseRFXWithScratch(coeff, &scratch)
}

func inverseRFXWithScratch(coeff *[rfxTilePixels]int64, scratch *[4096]int64) []int64 {
	inverseRFXLevelInto(coeff[3840:], coeff[4032:], coeff[3840:3904], coeff[3904:3968], coeff[3968:4032], 8, scratch)
	inverseRFXLevelInto(coeff[3072:], coeff[3840:], coeff[3072:3328], coeff[3328:3584], coeff[3584:3840], 16, scratch)
	inverseRFXLevelInto(coeff[:], coeff[3072:], coeff[:1024], coeff[1024:2048], coeff[2048:3072], 32, scratch)
	return coeff[:]
}

func rfxRGB(y, cb, cr []int64) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	clamp := func(v float64) byte {
		if v < 0 {
			return 0
		}
		if v > 255 {
			return 255
		}
		return byte(v + 0.5)
	}
	for i := 0; i < rfxTilePixels; i++ {
		a, b, c := float64(y[i])/32+128, float64(cb[i])/32, float64(cr[i])/32
		img.Pix[4*i] = clamp(a + 1.402525*c)
		img.Pix[4*i+1] = clamp(a - 0.343730*b - 0.714401*c)
		img.Pix[4*i+2] = clamp(a + 1.769905*b + 0.000013*c)
		img.Pix[4*i+3] = 255
	}
	return img
}
