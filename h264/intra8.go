package h264

import (
	"fmt"
	"image"
)

// H.264 Table 8-14, progressive zig-zag scan to raster order.
var scan8 = [64]int{
	0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5,
	12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
	35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
	58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
}

// Intra 8x8 luma scaling list (index 6), including fall-back rules A/B.
// Chroma remains 4x4 in the supported 4:2:0 format.
func intraWeights8(s *SPS, p PPS) [64]int32 { return scalingWeights8(s, p, false) }

func scalingWeights8(s *SPS, p PPS, inter bool) (out [64]int32) {
	def := [64]byte{
		6, 10, 10, 13, 11, 13, 16, 16, 16, 16, 18, 18, 18, 18, 18, 23,
		23, 23, 23, 23, 23, 25, 25, 25, 25, 25, 25, 25, 27, 27, 27, 27,
		27, 27, 27, 27, 29, 29, 29, 29, 29, 29, 29, 31, 31, 31, 31, 31,
		31, 33, 33, 33, 33, 33, 36, 36, 36, 36, 38, 38, 38, 40, 40, 42,
	}
	index := 6
	if inter {
		index = 7
		def = [64]byte{9, 13, 13, 15, 13, 15, 17, 17, 17, 17, 19, 19, 19, 19, 19, 21, 21, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 27, 27, 27, 27, 27, 27, 28, 28, 28, 28, 28, 30, 30, 30, 30, 32, 32, 32, 33, 33, 35}
	}
	var list [64]byte
	for i := range list {
		list[i] = 16
	}
	if s.ScalingMatrixPresent {
		list = def
		if s.Scaling[index].Present && !s.Scaling[index].Default {
			list = s.Scaling[index].Values
		}
	}
	if p.ScalingMatrixPresent {
		switch {
		case p.Scaling[index].Present && !p.Scaling[index].Default:
			list = p.Scaling[index].Values
		case p.Scaling[index].Present || !s.ScalingMatrixPresent:
			list = def
		}
	}
	for i, v := range list {
		out[scan8[i]] = int32(v)
	}
	return
}

// Reference sample filtering is local: reconstruction must leave the original
// neighbouring pixels intact for other block sizes and later deblocking.
func filterIntra8Edges(e intraEdges) intraEdges {
	out := e
	filter := func(src, dst []int) {
		if src[0] < 0 {
			return
		}
		corner := e.corner
		if corner < 0 {
			corner = src[0]
		}
		dst[0] = (corner + 2*src[0] + src[1] + 2) >> 2
		for i := 1; i < len(src)-1; i++ {
			dst[i] = (src[i-1] + 2*src[i] + src[i+1] + 2) >> 2
		}
		last := len(src) - 1
		dst[last] = (src[last-1] + 3*src[last] + 2) >> 2
	}
	filter(e.top[:], out.top[:])
	filter(e.left[:8], out.left[:8])
	if e.corner >= 0 {
		t, l := e.top[0], e.left[0]
		if t < 0 {
			t = e.corner
		}
		if l < 0 {
			l = e.corner
		}
		out.corner = (t + 2*e.corner + l + 2) >> 2
	}
	return out
}

func predict8(mode byte, e intraEdges) ([64]int32, error) {
	return predictAngular(mode, filterIntra8Edges(e), 8)
}

var norm8 = [6][6]int64{
	{20, 18, 32, 19, 25, 24}, {22, 19, 35, 21, 28, 26}, {26, 23, 42, 24, 33, 31},
	{28, 25, 45, 26, 35, 33}, {32, 28, 51, 30, 40, 38}, {36, 32, 58, 34, 46, 43},
}

// Scaling and inverse integer transform, 8.5.13. Wide intermediates are
// range-checked before narrowing; malformed coefficients cannot wrap.
func inverse8(c [64]int32, qp int, weight [64]int32) (out [64]int32, err error) {
	var d, g [64]int64
	for i, v := range c {
		if !in16(int64(v)) {
			return out, ErrInvalid
		}
		y, x, k := i/8, i%8, 5
		switch {
		case y%4 == 0 && x%4 == 0:
			k = 0
		case y%2 == 1 && x%2 == 1:
			k = 1
		case y%4 == 2 && x%4 == 2:
			k = 2
		case y%4 == 0 && x%2 == 1 || y%2 == 1 && x%4 == 0:
			k = 3
		case y%4 == 0 && x%4 == 2 || y%4 == 2 && x%4 == 0:
			k = 4
		}
		a := int64(v) * int64(weight[i]) * norm8[qp%6][k]
		if qp >= 36 {
			a <<= qp/6 - 6
		} else {
			a = (a + (1 << (5 - qp/6))) >> (6 - qp/6)
		}
		if !in16(a) {
			return out, ErrInvalid
		}
		d[i] = a
	}
	line := func(a [8]int64) (v [8]int64, ok bool) {
		e := [8]int64{
			a[0] + a[4], -a[3] + a[5] - a[7] - (a[7] >> 1), a[0] - a[4], a[1] + a[7] - a[3] - (a[3] >> 1),
			(a[2] >> 1) - a[6], -a[1] + a[7] + a[5] + (a[5] >> 1), a[2] + (a[6] >> 1), a[3] + a[5] + a[1] + (a[1] >> 1),
		}
		f := [8]int64{e[0] + e[6], e[1] + (e[7] >> 2), e[2] + e[4], e[3] + (e[5] >> 2), e[2] - e[4], (e[3] >> 2) - e[5], e[0] - e[6], e[7] - (e[1] >> 2)}
		v = [8]int64{f[0] + f[7], f[2] + f[5], f[4] + f[3], f[6] + f[1], f[6] - f[1], f[4] - f[3], f[2] - f[5], f[0] - f[7]}
		for i := range e {
			if !in16(e[i]) || !in16(f[i]) || !in16(v[i]) {
				return v, false
			}
		}
		return v, true
	}
	for y := 0; y < 8; y++ {
		v, ok := line([8]int64(d[y*8 : y*8+8]))
		if !ok {
			return out, ErrInvalid
		}
		copy(g[y*8:y*8+8], v[:])
	}
	for x := 0; x < 8; x++ {
		var col [8]int64
		for y := range col {
			col[y] = g[y*8+x]
		}
		v, ok := line(col)
		if !ok {
			return out, ErrInvalid
		}
		for y, a := range v {
			if a > 32735 {
				return out, ErrInvalid
			}
			out[y*8+x] = int32((a + 32) >> 6)
		}
	}
	return
}

func reconstructIntra8(dst *image.YCbCr, blocks []*intraMB, address, columns int, r *intraResidual, weights [64]int32) error {
	b := blocks[address]
	for i := 0; i < 4; i++ {
		x, y := i%2*8, i/2*8
		p, err := predict8(b.modes[y/4*4+x/4], edgesFor(dst.Y, dst.YStride, blocks, address, columns, 0, x, y, 8, i))
		if err != nil {
			return fmt.Errorf("macroblock %d block8 %d prediction: %w", address, i, err)
		}
		var c [64]int32
		for j := 0; j < 4; j++ {
			copy(c[j*16:j*16+16], r.blocks[i*4+j][:])
		}
		res, err := inverse8(c, b.qp[0], weights)
		if err != nil {
			return fmt.Errorf("macroblock %d block8 %d transform: %w", address, i, err)
		}
		for yy := 0; yy < 8; yy++ {
			for xx := 0; xx < 8; xx++ {
				dst.Y[(address/columns*16+y+yy)*dst.YStride+address%columns*16+x+xx] = byte(clipSample(int(p[yy*8+xx] + res[yy*8+xx])))
			}
		}
	}
	return nil
}
