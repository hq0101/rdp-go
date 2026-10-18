package h264

import "image"

func referenceSample(plane []byte, stride, width, height, x, y int) int {
	return int(plane[max(0, min(height-1, y))*stride+max(0, min(width-1, x))])
}

// The diagonal half-pel filter retains the unrounded horizontal intermediate.
// Each source coordinate is extended at the coded picture border (8.4.2.2.1).
func lumaSample(plane []byte, stride, width, height, qx, qy int) int {
	x, y, fx, fy := qx>>2, qy>>2, qx&3, qy&3
	sample := func(a, b int) int { return referenceSample(plane, stride, width, height, a, b) }
	if fx == 0 && fy == 0 {
		return sample(x, y)
	}
	taps := [6]int{1, -5, 20, 20, -5, 1}
	horizontal := func(y int) int {
		sum := 0
		for i, v := range taps {
			sum += v * sample(x+i-2, y)
		}
		return sum
	}
	vertical := func(x int) int {
		sum := 0
		for i, v := range taps {
			sum += v * sample(x, y+i-2)
		}
		return clipSample((sum + 16) >> 5)
	}
	if fy == 0 {
		b := clipSample((horizontal(y) + 16) >> 5)
		if fx == 2 {
			return b
		}
		return (b + sample(x+fx/2, y) + 1) >> 1
	}
	if fx == 0 {
		h := vertical(x)
		if fy == 2 {
			return h
		}
		return (h + sample(x, y+fy/2) + 1) >> 1
	}
	if fx&1 != 0 && fy&1 != 0 {
		return (clipSample((horizontal(y+fy/2)+16)>>5) + vertical(x+fx/2) + 1) >> 1
	}
	sum := 0
	for i, v := range taps {
		sum += v * horizontal(y+i-2)
	}
	j := clipSample((sum + 512) >> 10)
	if fx == 2 && fy == 2 {
		return j
	}
	if fx == 2 {
		return (j + clipSample((horizontal(y+fy/2)+16)>>5) + 1) >> 1
	}
	return (j + vertical(x+fx/2) + 1) >> 1
}

func chromaSample(plane []byte, stride, width, height, ex, ey int) int {
	x, y, fx, fy := ex>>3, ey>>3, ex&7, ey&7
	a := referenceSample(plane, stride, width, height, x, y)
	b := referenceSample(plane, stride, width, height, x+1, y)
	c := referenceSample(plane, stride, width, height, x, y+1)
	d := referenceSample(plane, stride, width, height, x+1, y+1)
	return ((8-fx)*(8-fy)*a + fx*(8-fy)*b + (8-fx)*fy*c + fx*fy*d + 32) >> 6
}

func weightSample(value int, w predictionWeight) int32 {
	if w.denom == 0 {
		return int32(clipSample(value*w.weight + w.offset))
	}
	return int32(clipSample(((value*w.weight + (1 << (w.denom - 1))) >> w.denom) + w.offset))
}

func reconstructInter(dst *image.YCbCr, b *intraMB, address int, weights [3][16]int32, weights8 [64]int32) error {
	columns := dst.Rect.Dx() / 16
	mx, my := address%columns*16, address/columns*16
	var predicted [3][256]int32
	for component := 0; component < 3; component++ {
		n := 16
		if component != 0 {
			n = 8
		}
		for y := 0; y < n; y++ {
			for x := 0; x < n; x++ {
				scale := 16 / n
				v, e := interPrediction(b.inter, (y*scale/4)*4+x*scale/4, component, mx, my, x, y)
				if e != nil {
					return e
				}
				predicted[component][y*n+x] = v
			}
		}
	}
	var zero intraResidual
	r := b.residual
	if r == nil {
		r = &zero
	}
	if b.transform8 {
		for quad := 0; quad < 4; quad++ {
			var c [64]int32
			for i := 0; i < 4; i++ {
				copy(c[i*16:(i+1)*16], r.blocks[quad*4+i][:])
			}
			res, e := inverse8(c, b.qp[0], weights8)
			if e != nil {
				return e
			}
			bx, by := quad%2*8, quad/2*8
			for y := 0; y < 8; y++ {
				for x := 0; x < 8; x++ {
					dst.Y[(my+by+y)*dst.YStride+mx+bx+x] = byte(clipSample(int(predicted[0][(by+y)*16+bx+x] + res[y*8+x])))
				}
			}
		}
	} else {
		for block := 0; block < 16; block++ {
			x, y := block%4*4, block/4*4
			res, e := inverse4(r.blocks[block], b.qp[0], weights[0], false)
			if e != nil {
				return e
			}
			var pred [16]int32
			for j := 0; j < 4; j++ {
				copy(pred[j*4:j*4+4], predicted[0][(y+j)*16+x:(y+j)*16+x+4])
			}
			writeBlock(dst.Y, dst.YStride, mx+x, my+y, pred, res)
		}
	}
	for component, plane := range [][]byte{dst.Cb, dst.Cr} {
		dc, e := chromaDC(r.chromaDC[component], b.qp[component+1], weights[component+1][0])
		if e != nil {
			return e
		}
		for block := 0; block < 4; block++ {
			x, y := block%2*4, block/2*4
			c := r.blocks[16+component*4+block]
			c[0] = dc[block]
			res, e := inverse4(c, b.qp[component+1], weights[component+1], true)
			if e != nil {
				return e
			}
			var pred [16]int32
			for j := 0; j < 4; j++ {
				copy(pred[j*4:j*4+4], predicted[component+1][(y+j)*8+x:(y+j)*8+x+4])
			}
			writeBlock(plane, dst.CStride, mx/2+x, my/2+y, pred, res)
		}
	}
	return nil
}
