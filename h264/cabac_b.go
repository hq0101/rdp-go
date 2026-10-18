package h264

// H.264 Tables 9-37/39/41. Intra is represented by 23, followed by the
// B-specific I suffix; the remaining codes map directly to Table 7-14.
func (c *cabac) bMacroblockType(context int) int {
	if c.decision(context) == 0 {
		return 0
	}
	if c.decision(30) == 0 {
		return 1 + c.decision(32)
	}
	code := c.decision(31)
	for i := 0; i < 3; i++ {
		code = code*2 + c.decision(32)
	}
	if code < 8 {
		return 3 + code
	}
	if code == 13 {
		return 23
	}
	if code == 14 {
		return 11
	}
	if code == 15 {
		return 22
	}
	return 12 + 2*(code-8) + c.decision(32)
}

// Table 9-38: bin 2 uses context 39 for a 10 prefix and 38 for 11.
func (c *cabac) bSubMacroblockType() byte {
	if c.decision(36) == 0 {
		return 0
	}
	if c.decision(37) == 0 {
		return byte(1 + c.decision(39))
	}
	if c.decision(38) == 0 {
		return byte(3 + 2*c.decision(39) + c.decision(39))
	}
	if c.decision(39) != 0 {
		return byte(11 + c.decision(39))
	}
	return byte(7 + 2*c.decision(39) + c.decision(39))
}

func parseCABACB(c *cabac, blocks []*intraMB, address, columns int, h *idrSlice, s *SPS, previousDelta *bool) error {
	blocks[address] = &intraMB{firstMB: h.firstMB}
	a, _ := neighbourBlock(blocks, address, columns, 0, -1, 0)
	up, _ := neighbourBlock(blocks, address, columns, 0, 0, -1)
	skipContext, typeContext := 24, 27
	for _, n := range []*intraMB{a, up} {
		if n != nil && (n.inter == nil || !n.inter.skip) {
			skipContext++
		}
		if n != nil && (n.inter == nil || !n.inter.skip && n.inter.kind != 0) {
			typeContext++
		}
	}
	if c.decision(skipContext) != 0 {
		*previousDelta = false
		return parseBSkip(blocks, address, columns, h, s)
	}
	kind := c.bMacroblockType(typeContext)
	if c.r.bad {
		return ErrInvalid
	}
	if kind == 23 {
		return parseCABACIntra(c, blocks, address, columns, h, s, previousDelta)
	}
	b := newBMacroblock(blocks, address, h)
	b.inter.kind = byte(kind)
	b.inter.differences = &[16][2]int32{}
	b.inter.back.differences = &[16][2]int32{}
	parts, width, height, shape := 1, 16, 16, 0
	modes := [4]byte{byte(kind)}
	if kind == 0 || kind == 22 {
		parts, width, height = 4, 8, 8
		modes = [4]byte{}
	}
	if kind >= 4 && kind <= 21 {
		parts, width, height, shape = 2, 16, 8, 1
		if kind%2 != 0 {
			width, height, shape = 8, 16, 2
		}
		pair := bPartitionModes[(kind-4)/2]
		modes[0], modes[1] = pair[0], pair[1]
	}
	allow8 := true
	if parts == 4 {
		for part := 0; part < 4; part++ {
			if kind == 22 {
				b.inter.subTypes[part] = c.bSubMacroblockType()
			}
			sub := bSubParts[b.inter.subTypes[part]]
			modes[part] = sub.mask
			if sub.mask == 0 {
				if !s.Direct8x8 {
					allow8 = false
				}
			} else if sub.width < 8 || sub.height < 8 {
				allow8 = false
			}
		}
	}
	var refs [2][4]int
	for list := 0; list < 2; list++ {
		count, pool := h.references, &h.list0
		if list == 1 {
			count, pool = h.referencesL1, &h.list1
		}
		for part := 0; part < parts; part++ {
			refs[list][part] = -1
			if modes[part]&(1<<list) == 0 {
				continue
			}
			x, y := part*width%16, part*width/16*height
			ref := 0
			if count > 1 {
				ref = cabacRefIndexList(c, blocks, address, columns, x, y, count, list)
			}
			if c.r.bad || pool[ref].picture == nil {
				return ErrInvalid
			}
			refs[list][part] = ref
			setMotionList(b.inter, x, y, width, height, motion{ref: int8(ref)}, list)
		}
	}
	// Entropy neighbours use explicit MVD syntax for the selected list, not
	// reconstructed vectors. Direct/inactive lists contribute zero. Store each
	// delta before decoding the next one, but derive all motion only afterwards.
	var deltas [2][16][2]int
	for list := 0; list < 2; list++ {
		for part := 0; part < parts; part++ {
			if refs[list][part] < 0 {
				continue
			}
			px, py := part*width%16, part*width/16*height
			sw, sh := width, height
			if parts == 4 {
				sub := bSubParts[b.inter.subTypes[part]]
				sw, sh = sub.width, sub.height
			}
			for y := 0; y < height; y += sh {
				for x := 0; x < width; x += sw {
					bx, by := px+x, py+y
					left, li := neighbourBlock(blocks, address, columns, 0, (bx-1)>>2, by>>2)
					top, ti := neighbourBlock(blocks, address, columns, 0, bx>>2, (by-1)>>2)
					var delta [2]int
					for comp := 0; comp < 2; comp++ {
						delta[comp] = c.motionDifference(comp, cabacDifference(left, li, comp, list)+cabacDifference(top, ti, comp, list))
					}
					if c.r.bad {
						return ErrInvalid
					}
					deltas[list][by/4*4+bx/4] = delta
					values := b.inter.differences
					if list == 1 {
						values = b.inter.back.differences
					}
					for row := by / 4; row < (by+sh)/4; row++ {
						for col := bx / 4; col < (bx+sw)/4; col++ {
							values[row*4+col] = [2]int32{int32(delta[0]), int32(delta[1])}
						}
					}
				}
			}
		}
	}
	if e := deriveBMotion(blocks, address, columns, h, s, parts, width, height, shape, modes, refs, deltas); e != nil {
		return e
	}
	cabacCBP(c, blocks, address, columns)
	if b.cbp&15 != 0 && h.parameters.Transform8x8 && allow8 {
		ctx := 399
		for _, n := range []*intraMB{a, up} {
			if n != nil && n.transform8 {
				ctx++
			}
		}
		b.transform8 = c.decision(ctx) != 0
	}
	return parseCABACResidual(c, blocks, address, columns, h, s, previousDelta)
}

func cabacDifference(n *intraMB, index, component, list int) int {
	if n == nil || n.inter == nil || n.inter.skip || n.inter.direct&(1<<uint(index/8*2+index%4/2)) != 0 {
		return 0
	}
	m, values := n.inter.cells[index], n.inter.differences
	if list == 1 {
		if n.inter.back == nil {
			return 0
		}
		m, values = n.inter.back.cells[index], n.inter.back.differences
	}
	if m.ref < 0 || values == nil {
		return 0
	}
	return abs(int(values[index][component]))
}
