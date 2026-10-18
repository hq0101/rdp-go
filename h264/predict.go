package h264

import (
	"fmt"
	"image"
)

type intraEdges struct {
	top, left [16]int
	corner    int
}

func clipSample(v int) int { return max(0, min(255, v)) }

func dcPrediction(top, left []int) int {
	sum, n := 0, 0
	for _, edge := range [][]int{top, left} {
		if len(edge) == 0 || edge[0] < 0 {
			continue
		}
		for _, v := range edge {
			sum += v
			n++
		}
	}
	if n == 0 {
		return 128
	}
	return (sum + n/2) / n
}

func predict4(mode byte, e intraEdges) (out [16]int32, err error) {
	all, err := predictAngular(mode, e, 4)
	copy(out[:], all[:16])
	return out, err
}

// H.264 8.3.1/8.3.2: both block sizes share the directional formulae.
// The caller of the 8x8 variant first filters its reference samples.
func predictAngular(mode byte, e intraEdges, n int) (out [64]int32, err error) {
	t, l := e.top[:], e.left[:]
	if ((mode == 0 || mode == 3 || mode == 7) && t[0] < 0) || ((mode == 1 || mode == 8) && l[0] < 0) ||
		(mode >= 4 && mode <= 6 && (t[0] < 0 || l[0] < 0 || e.corner < 0)) || mode > 8 {
		return out, ErrInvalid
	}
	top := func(i int) int {
		if i < 0 {
			return e.corner
		}
		return t[min(i, 2*n-1)]
	}
	dc := dcPrediction(t[:n], l[:n])
	left := func(i int) int {
		if i < 0 {
			return e.corner
		}
		return l[min(i, n-1)]
	}
	// Mode 6 is the transpose of mode 5, with top and left exchanged.
	verticalRight := func(x, y int, a, b func(int) int) int {
		z := 2*x - y
		if z >= 0 {
			k := x - (y >> 1)
			if z%2 == 0 {
				return (a(k-1) + a(k) + 1) >> 1
			}
			return (a(k-2) + 2*a(k-1) + a(k) + 2) >> 2
		}
		if z == -1 {
			return (b(0) + 2*e.corner + a(0) + 2) >> 2
		}
		return (b(-z-1) + 2*b(-z-2) + b(-z-3) + 2) >> 2
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			v := 0
			switch mode {
			case 0:
				v = top(x)
			case 1:
				v = left(y)
			case 2:
				v = dc
			case 3:
				v = (top(x+y) + 2*top(x+y+1) + top(x+y+2) + 2) >> 2
			case 4:
				if x > y {
					v = (top(x-y-2) + 2*top(x-y-1) + top(x-y) + 2) >> 2
				} else if x < y {
					v = (left(y-x-2) + 2*left(y-x-1) + left(y-x) + 2) >> 2
				} else {
					v = (top(0) + 2*e.corner + left(0) + 2) >> 2
				}
			case 5:
				v = verticalRight(x, y, top, left)
			case 6:
				v = verticalRight(y, x, left, top)
			case 7:
				k := x + y/2
				if y%2 == 0 {
					v = (top(k) + top(k+1) + 1) >> 1
				} else {
					v = (top(k) + 2*top(k+1) + top(k+2) + 2) >> 2
				}
			case 8:
				k := y + x/2
				if x%2 == 0 {
					v = (left(k) + left(k+1) + 1) >> 1
				} else {
					v = (left(k) + 2*left(k+1) + left(k+2) + 2) >> 2
				}
			}
			out[y*n+x] = int32(v)
		}
	}
	return
}

// Chroma uses a different numbering and four separate DC regions (8.3.4).
func predictLarge(mode byte, chroma bool, e intraEdges) (out [256]int32, err error) {
	if mode > 3 {
		return out, ErrInvalid
	}
	n := 16
	if chroma {
		n = 8
		mode = [4]byte{2, 1, 0, 3}[mode]
	}
	t, l := e.top[:n], e.left[:n]
	if mode > 3 || mode == 0 && t[0] < 0 || mode == 1 && l[0] < 0 || mode == 3 && (t[0] < 0 || l[0] < 0 || e.corner < 0) {
		return out, ErrInvalid
	}
	a, b, c := 0, 0, 0
	var dc [4]int
	if mode == 2 {
		if !chroma {
			dc[0] = dcPrediction(t, l)
		} else {
			for i := range dc {
				x, y := i%2*4, i/2*4
				tt, ll := t[x:x+4], l[y:y+4]
				if x > 0 && y == 0 && tt[0] >= 0 {
					ll = nil
				}
				if x == 0 && y > 0 && ll[0] >= 0 {
					tt = nil
				}
				dc[i] = dcPrediction(tt, ll)
			}
		}
	}
	if mode == 3 {
		h, v := 0, 0
		for i := 1; i <= n/2; i++ {
			t0, l0 := e.corner, e.corner
			if i < n/2 {
				t0, l0 = t[n/2-1-i], l[n/2-1-i]
			}
			h += i * (t[n/2-1+i] - t0)
			v += i * (l[n/2-1+i] - l0)
		}
		factor := 5
		if chroma {
			factor = 34
		}
		a, b, c = 16*(t[n-1]+l[n-1]), (factor*h+32)>>6, (factor*v+32)>>6
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			v := 0
			switch mode {
			case 0:
				v = t[x]
			case 1:
				v = l[y]
			case 2:
				if !chroma {
					v = dc[0]
				} else {
					v = dc[(y/4)*2+x/4]
				}
			case 3:
				v = clipSample((a + b*(x-(n/2-1)) + c*(y-(n/2-1)) + 16) >> 5)
			}
			out[y*n+x] = int32(v)
		}
	}
	return
}

func edgesFor(plane []byte, stride int, blocks []*intraMB, address, columns, component, bx, by, size, scanIndex int) intraEdges {
	n := 16
	if component != 0 {
		n = 8
	}
	mx, my := address%columns*n, address/columns*n
	sample := func(x, y int) int {
		x, y = mx+bx+x, my+by+y
		if x < 0 || y < 0 || x >= columns*n || y >= len(blocks)/columns*n {
			return -1
		}
		a := y/n*columns + x/n
		if a > address || blocks[a].firstMB != blocks[address].firstMB || blocks[address].constrained && blocks[a].inter != nil {
			return -1
		}
		if a == address {
			// Only already reconstructed luma blocks can supply edges.
			if component != 0 || size != 4 && size != 8 {
				return -1
			}
			index := blockRaster[(y%n)/4*4+(x%n)/4]
			if size == 8 {
				index /= 4
			}
			if index >= scanIndex {
				return -1
			}
		}
		return int(plane[y*stride+x])
	}
	e := intraEdges{corner: sample(-1, -1)}
	for i := range e.top {
		e.top[i], e.left[i] = -1, -1
	}
	topSize := size
	if component == 0 && (size == 4 || size == 8) {
		topSize = 2 * size
	}
	for i := 0; i < topSize; i++ {
		e.top[i] = sample(i, -1)
	}
	for i := 0; i < size; i++ {
		e.left[i] = sample(-1, i)
	}
	if topSize == 2*size && e.top[size] < 0 && e.top[size-1] >= 0 {
		for i := size; i < topSize; i++ {
			e.top[i] = e.top[size-1]
		}
	}
	return e
}

func reconstructIntra(dst *image.YCbCr, blocks []*intraMB, weights [3][16]int32, weights8 [64]int32) error {
	return reconstructPicture(dst, blocks, weights, weights8, weights, weights8)
}

func reconstructPicture(dst *image.YCbCr, blocks []*intraMB, weights [3][16]int32, weights8 [64]int32, inter4 [3][16]int32, inter8 [64]int32) error {
	columns := dst.Rect.Dx() / 16
	for address, b := range blocks {
		if b.inter != nil {
			if e := reconstructInter(dst, b, address, inter4, inter8); e != nil {
				return fmt.Errorf("macroblock %d inter prediction: %w", address, e)
			}
			continue
		}
		if b.kind == 25 {
			copyPCM(dst, address, b.pcm)
			continue
		}
		var zero intraResidual
		r := b.residual
		if r == nil {
			r = &zero
		}
		var dc [16]int32
		var pred [256]int32
		var err error
		if b.kind != 0 {
			pred, err = predictLarge((b.kind-1)%4, false, edgesFor(dst.Y, dst.YStride, blocks, address, columns, 0, 0, 0, 16, 0))
			if err != nil {
				return fmt.Errorf("macroblock %d luma prediction: %w", address, err)
			}
			dc, err = lumaDC(r.lumaDC, b.qp[0], weights[0][0])
			if err != nil {
				return fmt.Errorf("macroblock %d luma DC: %w", address, err)
			}
		}
		if b.transform8 {
			if e := reconstructIntra8(dst, blocks, address, columns, r, weights8); e != nil {
				return e
			}
		}
		for scan, raster := range blockRaster {
			if b.transform8 {
				break
			}
			x, y := raster%4*4, raster/4*4
			var p [16]int32
			if b.kind == 0 {
				p, err = predict4(b.modes[raster], edgesFor(dst.Y, dst.YStride, blocks, address, columns, 0, x, y, 4, scan))
				if err != nil {
					return fmt.Errorf("macroblock %d block %d prediction: %w", address, scan, err)
				}
			} else {
				for j := 0; j < 4; j++ {
					copy(p[j*4:j*4+4], pred[(y+j)*16+x:(y+j)*16+x+4])
				}
			}
			c := r.blocks[raster]
			if b.kind != 0 {
				c[0] = dc[raster]
			}
			res, e := inverse4(c, b.qp[0], weights[0], b.kind != 0)
			if e != nil {
				return fmt.Errorf("macroblock %d block %d transform: %w", address, scan, e)
			}
			writeBlock(dst.Y, dst.YStride, address%columns*16+x, address/columns*16+y, p, res)
		}
		for component, plane := range [][]byte{dst.Cb, dst.Cr} {
			pred, err = predictLarge(b.chromaMode, true, edgesFor(plane, dst.CStride, blocks, address, columns, component+1, 0, 0, 8, 0))
			if err != nil {
				return fmt.Errorf("macroblock %d chroma prediction: %w", address, err)
			}
			cd, e := chromaDC(r.chromaDC[component], b.qp[component+1], weights[component+1][0])
			if e != nil {
				return fmt.Errorf("macroblock %d chroma DC: %w", address, e)
			}
			for i := 0; i < 4; i++ {
				x, y := i%2*4, i/2*4
				c := r.blocks[16+component*4+i]
				c[0] = cd[i]
				res, e := inverse4(c, b.qp[component+1], weights[component+1], true)
				if e != nil {
					return fmt.Errorf("macroblock %d chroma transform: %w", address, e)
				}
				var p [16]int32
				for j := 0; j < 4; j++ {
					copy(p[j*4:j*4+4], pred[(y+j)*8+x:(y+j)*8+x+4])
				}
				writeBlock(plane, dst.CStride, address%columns*8+x, address/columns*8+y, p, res)
			}
		}
	}
	return nil
}

func writeBlock(plane []byte, stride, x, y int, pred, res [16]int32) {
	for j := 0; j < 4; j++ {
		for i := 0; i < 4; i++ {
			plane[(y+j)*stride+x+i] = byte(clipSample(int(pred[j*4+i] + res[j*4+i])))
		}
	}
}
