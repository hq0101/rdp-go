package h264

import "fmt"

func parseCABACSlice(r *bitReader, blocks []*intraMB, h *idrSlice, s *SPS) (int, error) {
	if h.sliceType != 2 && h.sliceType != 0 && h.sliceType != 1 {
		return 0, ErrUnsupported
	}
	init := &cabacInitI
	if h.sliceType != 2 {
		if h.cabacInit < 0 || h.cabacInit > 2 {
			return 0, ErrInvalid
		}
		init = &cabacInitP[h.cabacInit]
	}
	c := newCABACWithInit(r, h.qp, init)
	count := 0
	previousDelta := false
	for !r.bad {
		address := h.firstMB + count
		if address >= len(blocks) || blocks[address] != nil {
			return 0, ErrInvalid
		}
		var err error
		if h.sliceType == 0 {
			err = parseCABACP(c, blocks, address, s.WidthInMBs, h, s, &previousDelta)
		} else if h.sliceType == 1 {
			err = parseCABACB(c, blocks, address, s.WidthInMBs, h, s, &previousDelta)
		} else {
			err = parseCABACIntra(c, blocks, address, s.WidthInMBs, h, s, &previousDelta)
		}
		if err != nil {
			return 0, fmt.Errorf("CABAC macroblock %d at bit %d: %w", address, r.pos, err)
		}
		count++
		if c.terminate() {
			return count, c.finish()
		}
	}
	return 0, ErrInvalid
}

func parseCABACIntra(c *cabac, blocks []*intraMB, address, columns int, h *idrSlice, s *SPS, previousDelta *bool) error {
	b := &intraMB{firstMB: h.firstMB, constrained: h.parameters.ConstrainedIntra, filter: h.filter}
	blocks[address] = b
	a, _ := neighbourBlock(blocks, address, columns, 0, -1, 0)
	up, _ := neighbourBlock(blocks, address, columns, 0, 0, -1)
	neighbours := [2]*intraMB{a, up}
	sum := func(test func(*intraMB) bool) int {
		n := 0
		for _, b := range neighbours {
			if b != nil && test(b) {
				n++
			}
		}
		return n
	}
	ctx := 3 + sum(func(n *intraMB) bool { return n.kind != 0 })
	luma, chroma, chromaNext, mode, modeNext := 6, 7, 8, 9, 10
	if h.sliceType == 0 {
		ctx = 17
		luma, chroma, chromaNext, mode, modeNext = 18, 19, 19, 20, 20
	} else if h.sliceType == 1 {
		ctx = 32
		luma, chroma, chromaNext, mode, modeNext = 33, 34, 34, 35, 35
	}
	if c.decision(ctx) != 0 {
		if c.terminate() {
			b.kind = 25
		} else {
			kind := 1 + 12*c.decision(luma)
			if c.decision(chroma) != 0 {
				kind += 4 + 4*c.decision(chromaNext)
			}
			kind += 2*c.decision(mode) + c.decision(modeNext)
			b.kind = byte(kind)
		}
	}
	r := c.r
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
		b.qp = [3]int{0, chromaQP(h.parameters.ChromaQPOffset), chromaQP(h.parameters.SecondChromaQPOffset)}
		*previousDelta = false
		c.restart()
		if r.bad {
			return ErrInvalid
		}
		return nil
	}
	if b.kind == 0 {
		if h.parameters.Transform8x8 {
			ctx = 399 + sum(func(n *intraMB) bool { return n.transform8 })
			b.transform8 = c.decision(ctx) != 0
		}
		for scan, raster := range blockRaster {
			if b.transform8 && scan%4 != 0 {
				continue
			}
			mode := predictedIntraMode(blocks, address, columns, raster)
			if c.decision(68) == 0 {
				rem := byte(c.decision(69) | c.decision(69)<<1 | c.decision(69)<<2)
				if rem >= mode {
					rem++
				}
				mode = rem
			}
			b.modes[raster] = mode
			if b.transform8 {
				for _, delta := range []int{1, 4, 5} {
					b.modes[raster+delta] = mode
				}
			}
		}
	}
	ctx = 64 + sum(func(n *intraMB) bool { return n.kind != 25 && n.chromaMode != 0 })
	if c.decision(ctx) != 0 {
		b.chromaMode = 1
		for b.chromaMode < 3 && c.decision(67) != 0 {
			b.chromaMode++
		}
	}
	if b.kind == 0 {
		cabacCBP(c, blocks, address, columns)
	} else {
		b.cbp = (b.kind - 1) / 4 % 3 * 16
		if b.kind >= 13 {
			b.cbp += 15
		}
	}
	return parseCABACResidual(c, blocks, address, columns, h, s, previousDelta)
}

func parseCABACResidual(c *cabac, blocks []*intraMB, address, columns int, h *idrSlice, s *SPS, previousDelta *bool) error {
	b, r := blocks[address], c.r
	intra16 := b.inter == nil && b.kind != 0
	a, _ := neighbourBlock(blocks, address, columns, 0, -1, 0)
	up, _ := neighbourBlock(blocks, address, columns, 0, 0, -1)
	ctx := 0
	delta := 0
	if b.cbp != 0 || intra16 {
		ctx = 60
		if *previousDelta {
			ctx++
		}
		value := 0
		for c.decision(ctx) != 0 && !r.bad {
			value++
			if value > 52 {
				r.bad = true
				break
			}
			ctx = 63
			if value == 1 {
				ctx = 62
			}
		}
		if value%2 == 0 {
			delta = -value / 2
		} else {
			delta = (value + 1) / 2
		}
		if delta < -26 || delta > 25 {
			r.bad = true
		}
		h.qp = (h.qp + delta + 52) % 52
	}
	*previousDelta = delta != 0
	b.qp = [3]int{h.qp, chromaQP(h.qp + h.parameters.ChromaQPOffset), chromaQP(h.qp + h.parameters.SecondChromaQPOffset)}
	if r.bad {
		return ErrInvalid
	}
	if s.TransformBypass && h.qp == 0 {
		return fmt.Errorf("transform bypass: %w", ErrUnsupported)
	}
	if b.cbp == 0 && !intra16 {
		return nil
	}
	b.residual = &intraResidual{}
	// Unavailable neighbours imply CBF=1 for intra and CBF=0 for inter.
	// PCM implies 1; other absent transform blocks imply 0 (9.3.3.1.1.9).
	coded := func(category, component, raster int) bool {
		var left, top *intraMB
		li, ti := 0, 0
		dc := category == 0 || category == 3
		if dc {
			left, top = a, up
		} else {
			n := 4
			if component != 0 {
				n = 2
			}
			left, li = neighbourBlock(blocks, address, columns, component, raster%n-1, raster/n)
			top, ti = neighbourBlock(blocks, address, columns, component, raster%n, raster/n-1)
		}
		cond := func(n *intraMB, index int) int {
			if n == nil {
				if b.inter == nil {
					return 1
				}
				return 0
			}
			if n.kind == 25 {
				return 1
			}
			if dc {
				if n.codedDC&(1<<uint(component)) != 0 {
					return 1
				}
			} else if n.totals[index] != 0 {
				return 1
			}
			return 0
		}
		return c.decision(85+4*category+cond(left, li)+2*cond(top, ti)) != 0
	}
	if intra16 && coded(0, 0, 0) {
		b.codedDC |= 1
		coeff := c.residual(0, 16)
		for i := 0; i < 16; i++ {
			b.residual.lumaDC[scan4[i]] = coeff[i]
		}
	}
	for quad := 0; quad < 4 && !r.bad; quad++ {
		if b.cbp&(1<<uint(quad)) == 0 {
			continue
		}
		if b.transform8 {
			coeff := c.residual(5, 64)
			for i, v := range coeff {
				index := scan8[i]
				b.residual.blocks[quad*4+index/16][index%16] = v
			}
			for j := 0; j < 4; j++ {
				b.totals[blockRaster[quad*4+j]] = 1
			}
		} else {
			category, count, start := 2, 16, 0
			if intra16 {
				category, count, start = 1, 15, 1
			}
			for j := 0; j < 4; j++ {
				raster := blockRaster[quad*4+j]
				if !coded(category, 0, raster) {
					continue
				}
				coeff := c.residual(category, count)
				for i := 0; i < count; i++ {
					b.residual.blocks[raster][scan4[i+start]] = coeff[i]
					if coeff[i] != 0 {
						b.totals[raster]++
					}
				}
			}
		}
	}
	if b.cbp/16 > 0 {
		for component := 1; component <= 2; component++ {
			if !coded(3, component, 0) {
				continue
			}
			b.codedDC |= 1 << uint(component)
			coeff := c.residual(3, 4)
			copy(b.residual.chromaDC[component-1][:], coeff[:4])
		}
	}
	if b.cbp/16 == 2 {
		for component := 1; component <= 2; component++ {
			for raster := 0; raster < 4; raster++ {
				if !coded(4, component, raster) {
					continue
				}
				coeff := c.residual(4, 15)
				index := 16 + (component-1)*4 + raster
				for i := 0; i < 15; i++ {
					b.residual.blocks[index][scan4[i+1]] = coeff[i]
					if coeff[i] != 0 {
						b.totals[index]++
					}
				}
			}
		}
	}
	if r.bad {
		return ErrInvalid
	}
	return nil
}

func cabacCBP(c *cabac, blocks []*intraMB, address, columns int) {
	b := blocks[address]
	a, _ := neighbourBlock(blocks, address, columns, 0, -1, 0)
	up, _ := neighbourBlock(blocks, address, columns, 0, 0, -1)
	neighbours := [2]*intraMB{a, up}
	ctx := 0
	for quad := 0; quad < 4; quad++ {
		x, y := quad%2*2, quad/2*2
		left, li := neighbourBlock(blocks, address, columns, 0, x-1, y)
		top, ti := neighbourBlock(blocks, address, columns, 0, x, y-1)
		cond := func(n *intraMB, index int) int {
			if n == nil || n.kind == 25 || n.cbp&(1<<uint(blockRaster[index]/4)) != 0 {
				return 0
			}
			return 1
		}
		ctx = 73 + cond(left, li) + 2*cond(top, ti)
		b.cbp |= byte(c.decision(ctx) << uint(quad))
	}
	for bin := 0; bin < 2; bin++ {
		ctx = 77 + 4*bin
		for i, n := range neighbours {
			if n != nil && (n.kind == 25 || bin == 0 && n.cbp/16 > 0 || bin == 1 && n.cbp/16 == 2) {
				ctx += 1 << uint(i)
			}
		}
		if c.decision(ctx) == 0 {
			break
		}
		b.cbp += 16
	}
}
