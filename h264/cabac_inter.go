package h264

// P-slice syntax (H.264 9.3). Prediction, transform and reference-picture
// management are shared with CAVLC; the arithmetic contexts are slice-local.
func parseCABACP(c *cabac, blocks []*intraMB, address, columns int, h *idrSlice, s *SPS, previousDelta *bool) error {
	blocks[address] = &intraMB{firstMB: h.firstMB}
	a, _ := neighbourBlock(blocks, address, columns, 0, -1, 0)
	up, _ := neighbourBlock(blocks, address, columns, 0, 0, -1)
	ctx := 11
	for _, n := range []*intraMB{a, up} {
		if n != nil && (n.inter == nil || !n.inter.skip) {
			ctx++
		}
	}
	if c.decision(ctx) != 0 {
		*previousDelta = false
		return parsePSkip(blocks, address, columns, h)
	}
	// A one-bit prefix selects the intra suffix, whose contexts differ from
	// those in an I slice. P_8x8ref0 has no CABAC codeword (Table 9-37).
	if c.decision(14) != 0 {
		return parseCABACIntra(c, blocks, address, columns, h, s, previousDelta)
	}
	kind := 0
	if c.decision(15) == 0 {
		if c.decision(16) != 0 {
			kind = 3
		}
	} else {
		kind = 2 - c.decision(17)
	}
	b := newInterMB(blocks, address, h)
	b.inter.kind = byte(kind)
	b.inter.differences = &[16][2]int32{}
	parts, width, height := 1, 16, 16
	switch kind {
	case 1:
		parts, height = 2, 8
	case 2:
		parts, width = 2, 8
	case 3:
		parts, width, height = 4, 8, 8
	}
	allow8 := true
	if parts == 4 {
		for i := 0; i < 4; i++ {
			sub := byte(0)
			if c.decision(21) == 0 {
				sub = 1
				if c.decision(22) != 0 {
					sub = byte(3 - c.decision(23))
				}
			}
			b.inter.subTypes[i] = sub
			if sub != 0 {
				allow8 = false
			}
		}
	}
	var refs [4]int
	for part := 0; part < parts; part++ {
		x, y := part*width%16, part*width/16*height
		if h.references > 1 {
			refs[part] = cabacRefIndex(c, blocks, address, columns, x, y, h.references)
		}
		if c.r.bad || h.list0[refs[part]].picture == nil {
			return ErrInvalid
		}
		// All ref_idx syntax precedes all MVD syntax. Publish only reference
		// indices now; motion predictors must not see undecoded vectors as ready.
		setMotion(b.inter, x, y, width, height, motion{ref: int8(refs[part])})
	}
	for part := 0; part < parts; part++ {
		px, py := part*width%16, part*width/16*height
		sw, sh := width, height
		if parts == 4 {
			switch b.inter.subTypes[part] {
			case 1:
				sh = 4
			case 2:
				sw = 4
			case 3:
				sw, sh = 4, 4
			}
		}
		for y := 0; y < height; y += sh {
			for x := 0; x < width; x += sw {
				bx, by := px+x, py+y
				left, li := neighbourBlock(blocks, address, columns, 0, (bx-1)>>2, by>>2)
				top, ti := neighbourBlock(blocks, address, columns, 0, bx>>2, (by-1)>>2)
				difference := func(n *intraMB, index, component int) int {
					if n == nil || n.inter == nil || n.inter.skip || n.inter.differences == nil {
						return 0
					}
					return abs(int(n.inter.differences[index][component]))
				}
				var delta [2]int32
				for component := 0; component < 2; component++ {
					delta[component] = int32(c.motionDifference(component, difference(left, li, component)+difference(top, ti, component)))
				}
				pred := predictMotion(blocks, address, columns, bx, by, sw, kind, part, refs[part])
				vx, vy := int(pred.x)+int(delta[0]), int(pred.y)+int(delta[1])
				if c.r.bad || !in16(int64(vx)) || !in16(int64(vy)) {
					return ErrInvalid
				}
				setMotion(b.inter, bx, by, sw, sh, motion{int16(vx), int16(vy), int8(refs[part]), true})
				for row := by / 4; row < (by+sh)/4; row++ {
					for col := bx / 4; col < (bx+sw)/4; col++ {
						b.inter.differences[row*4+col] = delta
					}
				}
			}
		}
	}
	cabacCBP(c, blocks, address, columns)
	if b.cbp&15 != 0 && h.parameters.Transform8x8 && allow8 {
		ctx = 399
		for _, n := range []*intraMB{a, up} {
			if n != nil && n.transform8 {
				ctx++
			}
		}
		b.transform8 = c.decision(ctx) != 0
	}
	return parseCABACResidual(c, blocks, address, columns, h, s, previousDelta)
}

func cabacRefIndex(c *cabac, blocks []*intraMB, address, columns, x, y, count int) int {
	return cabacRefIndexList(c, blocks, address, columns, x, y, count, 0)
}

func cabacRefIndexList(c *cabac, blocks []*intraMB, address, columns, x, y, count, list int) int {
	a, ai := neighbourBlock(blocks, address, columns, 0, (x-1)>>2, y>>2)
	b, bi := neighbourBlock(blocks, address, columns, 0, x>>2, (y-1)>>2)
	cond := func(n *intraMB, i int) int {
		if n == nil || n.inter == nil || n.inter.skip || n.inter.direct&(1<<uint(i/8*2+i%4/2)) != 0 {
			return 0
		}
		m := n.inter.cells[i]
		if list == 1 {
			if n.inter.back == nil {
				return 0
			}
			m = n.inter.back.cells[i]
		}
		if m.ref > 0 {
			return 1
		}
		return 0
	}
	ctx := 54 + cond(a, ai) + 2*cond(b, bi)
	ref := 0
	// Unlike truncated Exp-Golomb, CABAC ref_idx uses unary with a terminating
	// zero even for the maximum active index. Reject overflow before another bin.
	for c.decision(ctx) != 0 && !c.r.bad {
		ref++
		if ref >= count {
			c.r.bad = true
			return 0
		}
		ctx = 59
		if ref == 1 {
			ctx = 58
		}
	}
	return ref
}

// UEG3: a context-coded truncated unary prefix (cutoff 9), bypass-coded
// expanding suffix and sign. Bound the code before any oversized shift.
func (c *cabac) motionDifference(component, neighbourSum int) int {
	base := 40 + 7*component
	ctx := base
	if neighbourSum > 32 {
		ctx += 2
	} else if neighbourSum >= 3 {
		ctx++
	}
	value := 0
	for value < 9 && c.decision(ctx) != 0 && !c.r.bad {
		value++
		ctx = base + min(value+2, 6)
	}
	if value == 9 {
		k := 3
		for c.bypass() != 0 && !c.r.bad {
			if k >= 16 {
				c.r.bad = true
				return 0
			}
			value += 1 << k
			k++
		}
		for j := k - 1; j >= 0 && !c.r.bad; j-- {
			value += c.bypass() << j
		}
	}
	if value > 65535 {
		c.r.bad = true
		return 0
	}
	if value != 0 && c.bypass() != 0 {
		value = -value
	}
	return value
}
