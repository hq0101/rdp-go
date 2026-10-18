package h264

import "fmt"

// Block coefficients are stored in raster order; luma syntax visits the four
// 8x8 quadrants in turn. The same permutation is its own inverse.
var blockRaster = [16]int{0, 1, 4, 5, 2, 3, 6, 7, 8, 9, 12, 13, 10, 11, 14, 15}
var scan4 = [16]int{0, 1, 4, 8, 5, 2, 3, 6, 9, 12, 13, 10, 7, 11, 14, 15}
var intraCBP = [48]int{47, 31, 15, 0, 23, 27, 29, 30, 7, 11, 13, 14, 39, 43, 45, 46, 16, 3, 5, 10, 12, 19, 21, 26, 28, 35, 37, 42, 44, 1, 2, 4, 8, 17, 18, 20, 24, 6, 9, 22, 25, 32, 33, 34, 36, 40, 38, 41}

type intraResidual struct {
	lumaDC   [16]int32
	chromaDC [2][4]int32
	// For transform8, the first sixteen entries hold four consecutive
	// raster-order 8x8 matrices, split into four arrays each.
	blocks [24][16]int32
}
type intraMB struct {
	inter            *interMB
	constrained      bool
	pcm              []byte
	residual         *intraResidual
	firstMB          int // neighbours across a slice boundary are unavailable
	kind, chromaMode byte
	modes            [16]byte
	totals           [24]byte
	qp               [3]int
	filter           deblockParams
	transform8       bool
	cbp, codedDC     byte // CABAC block-pattern and DC coded-block contexts
}

// neighbourBlock uses a component's 4x4-block grid for syntax contexts.
// Constrained intra prediction affects prediction edges/modes, not coefficients.
func neighbourBlock(blocks []*intraMB, address, columns, component, x, y int) (*intraMB, int) {
	n, base := 4, 0
	if component != 0 {
		n, base = 2, 16+(component-1)*4
	}
	mx, my := address%columns, address/columns
	if x < 0 {
		mx--
		x += n
	}
	if y < 0 {
		my--
		y += n
	}
	if x >= n {
		mx++
		x -= n
	}
	if y >= n {
		my++
		y -= n
	}
	if mx < 0 || mx >= columns || my < 0 || my >= len(blocks)/columns {
		return nil, 0
	}
	a := my*columns + mx
	if a > address || blocks[a] == nil || blocks[a].firstMB != blocks[address].firstMB {
		return nil, 0
	}
	return blocks[a], base + y*n + x
}

func coefficientContext(blocks []*intraMB, address, columns, component, x, y int) int {
	a, ai := neighbourBlock(blocks, address, columns, component, x-1, y)
	b, bi := neighbourBlock(blocks, address, columns, component, x, y-1)
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return int(b.totals[bi])
	}
	if b == nil {
		return int(a.totals[ai])
	}
	return (int(a.totals[ai]) + int(b.totals[bi]) + 1) / 2
}

func predictedIntraMode(blocks []*intraMB, address, columns, raster int) byte {
	x, y := raster%4, raster/4
	a, ai := neighbourBlock(blocks, address, columns, 0, x-1, y)
	c, ci := neighbourBlock(blocks, address, columns, 0, x, y-1)
	if a == nil || c == nil || blocks[address].constrained && (a.inter != nil || c.inter != nil) {
		return 2
	}
	am, cm := byte(2), byte(2)
	if a.inter == nil && a.kind == 0 {
		am = a.modes[ai]
	}
	if c.inter == nil && c.kind == 0 {
		cm = c.modes[ci]
	}
	return min(am, cm)
}

func parseIntraMB(r *bitReader, blocks []*intraMB, address, columns int, h *idrSlice, s *SPS) error {
	return parseIntraKind(r, blocks, address, columns, h, s, byte(r.ue(25)))
}

func parseIntraKind(r *bitReader, blocks []*intraMB, address, columns int, h *idrSlice, s *SPS, kind byte) error {
	b := &intraMB{firstMB: h.firstMB, kind: kind, filter: h.filter, constrained: h.parameters.ConstrainedIntra}
	blocks[address] = b
	if r.bad {
		return ErrInvalid
	}
	if b.kind == 25 {
		for r.pos%8 != 0 && !r.bad {
			if r.read(1) != 0 {
				r.bad = true
			}
		}
		if r.bad || len(r.data)-r.pos/8 < 384 {
			return ErrInvalid
		}
		b.pcm = r.data[r.pos/8 : r.pos/8+384]
		r.pos += 384 * 8
		for i := range b.totals {
			b.totals[i] = 16
		}
		// PCM uses QPY=0 for filtering, including chroma QP offsets. This
		// does not reset the slice's running QPY used by subsequent blocks.
		b.qp = [3]int{0, chromaQP(h.parameters.ChromaQPOffset), chromaQP(h.parameters.SecondChromaQPOffset)}
		return nil // I_PCM preserves the previous QPY
	}
	cbp := 0
	if b.kind == 0 {
		b.transform8 = h.parameters.Transform8x8 && r.flag()
		for scan, raster := range blockRaster {
			if b.transform8 && scan%4 != 0 {
				continue
			}
			pred := predictedIntraMode(blocks, address, columns, raster)
			if r.flag() {
				b.modes[raster] = pred
			} else {
				m := byte(r.read(3))
				if m >= pred {
					m++
				}
				b.modes[raster] = m
			}
			if b.transform8 {
				// The 4x4 grid also supplies mode contexts to adjacent I4 blocks.
				for _, delta := range []int{1, 4, 5} {
					b.modes[raster+delta] = b.modes[raster]
				}
			}
		}
	} else {
		cbp = ((int(b.kind) - 1) / 4 % 3) * 16
		if b.kind >= 13 {
			cbp += 15
		}
	}
	b.chromaMode = byte(r.ue(3))
	if b.kind == 0 {
		cbp = intraCBP[r.ue(47)]
	}
	if r.bad {
		return ErrInvalid
	}
	return parseCAVLCResidual(r, blocks, address, columns, h, s, cbp)
}

func parseCAVLCResidual(r *bitReader, blocks []*intraMB, address, columns int, h *idrSlice, s *SPS, cbp int) error {
	b := blocks[address]
	b.cbp = byte(cbp)
	intra16 := b.inter == nil && b.kind != 0
	if cbp != 0 || intra16 {
		h.qp = (h.qp + r.se(-26, 25) + 52) % 52
	}
	b.qp = [3]int{h.qp, chromaQP(h.qp + h.parameters.ChromaQPOffset), chromaQP(h.qp + h.parameters.SecondChromaQPOffset)}
	if r.bad {
		return ErrInvalid
	}
	if s.TransformBypass && h.qp == 0 {
		return fmt.Errorf("transform bypass: %w", ErrUnsupported)
	}
	if cbp == 0 && !intra16 {
		return nil
	}
	b.residual = &intraResidual{}
	if intra16 {
		c, _ := residualCAVLC(r, coefficientContext(blocks, address, columns, 0, 0, 0), 16)
		for i, v := range c {
			b.residual.lumaDC[scan4[i]] = v
		}
	}
	for i, raster := range blockRaster {
		if cbp&(1<<(i/4)) == 0 {
			continue
		}
		count, start := 16, 0
		if intra16 {
			count, start = 15, 1
		}
		c, total := residualCAVLC(r, coefficientContext(blocks, address, columns, 0, raster%4, raster/4), count)
		b.totals[raster] = byte(total)
		for j := 0; j < count; j++ {
			if b.transform8 {
				// CAVLC interleaves four 16-coefficient lists (7.3.5.3.1).
				index := scan8[4*j+i%4]
				b.residual.blocks[i/4*4+index/16][index%16] = c[j]
			} else {
				b.residual.blocks[raster][scan4[j+start]] = c[j]
			}
		}
	}
	if cbp/16 > 0 {
		for component := 0; component < 2; component++ {
			c, _ := residualCAVLC(r, -1, 4)
			copy(b.residual.chromaDC[component][:], c[:4])
		}
	}
	if cbp/16 == 2 {
		for component := 1; component <= 2; component++ {
			for raster := 0; raster < 4; raster++ {
				c, total := residualCAVLC(r, coefficientContext(blocks, address, columns, component, raster%2, raster/2), 15)
				index := 16 + (component-1)*4 + raster
				b.totals[index] = byte(total)
				for j := 0; j < 15; j++ {
					b.residual.blocks[index][scan4[j+1]] = c[j]
				}
			}
		}
	}
	if r.bad {
		return ErrInvalid
	}
	return nil
}

func chromaQP(q int) int {
	q = max(0, min(51, q))
	if q < 30 {
		return q
	}
	return [...]int{29, 30, 31, 32, 32, 33, 34, 34, 35, 35, 36, 36, 37, 37, 37, 38, 38, 38, 39, 39, 39, 39}[q-30]
}
