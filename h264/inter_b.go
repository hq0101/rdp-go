package h264

// Prediction masks and dimensions from H.264 Tables 7-14 and 7-18.
var bPartitionModes = [9][2]byte{{1, 1}, {2, 2}, {1, 2}, {2, 1}, {1, 3}, {2, 3}, {3, 1}, {3, 2}, {3, 3}}
var bSubParts = [13]struct {
	mask          byte
	width, height int
}{
	{0, 4, 4}, {1, 8, 8}, {2, 8, 8}, {3, 8, 8}, {1, 8, 4}, {1, 4, 8},
	{2, 8, 4}, {2, 4, 8}, {3, 8, 4}, {3, 4, 8}, {1, 4, 4}, {2, 4, 4}, {3, 4, 4},
}

func newBMacroblock(blocks []*intraMB, address int, h *idrSlice) *intraMB {
	b := newInterMB(blocks, address, h)
	b.inter.back = &backwardMotion{list: &h.list1}
	b.inter.biWeight, b.inter.order = h.parameters.WeightedBiPrediction, h.order
	for i := range b.inter.back.cells {
		b.inter.back.cells[i].ref = -1
	}
	return b
}

func setMotionList(b *interMB, x, y, w, h int, m motion, list int) {
	if list == 0 {
		setMotion(b, x, y, w, h, m)
		return
	}
	for j := y / 4; j < (y+h)/4; j++ {
		for i := x / 4; i < (x+w)/4; i++ {
			b.back.cells[j*4+i] = m
		}
	}
}

func parseBSkip(blocks []*intraMB, address, columns int, h *idrSlice, s *SPS) error {
	b := newBMacroblock(blocks, address, h)
	b.inter.skip = true
	for q := 0; q < 4; q++ {
		if e := deriveDirect(blocks, address, columns, q, h, s); e != nil {
			return e
		}
	}
	return nil
}

func parseCAVLCB(r *bitReader, blocks []*intraMB, address, columns int, h *idrSlice, s *SPS) error {
	kind := int(r.ue(48))
	if r.bad {
		return ErrInvalid
	}
	if kind >= 23 {
		return parseIntraKind(r, blocks, address, columns, h, s, byte(kind-23))
	}
	b := newBMacroblock(blocks, address, h)
	b.inter.kind = byte(kind)
	parts, width, height, shape := 1, 16, 16, 0
	modes := [4]byte{byte(kind)}
	if kind == 0 || kind == 22 {
		parts, width, height = 4, 8, 8
		modes = [4]byte{}
	}
	if kind >= 4 && kind <= 21 {
		parts = 2
		width, height, shape = 16, 8, 1
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
				b.inter.subTypes[part] = byte(r.ue(12))
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
		count := h.references
		pool := &h.list0
		if list == 1 {
			count = h.referencesL1
			pool = &h.list1
		}
		for part := 0; part < parts; part++ {
			if modes[part]&(1<<list) == 0 {
				refs[list][part] = -1
				continue
			}
			if count == 2 {
				refs[list][part] = int(1 - r.read(1))
			} else if count > 2 {
				refs[list][part] = int(r.ue(uint32(count - 1)))
			}
			if r.bad || pool[refs[list][part]].picture == nil {
				return ErrInvalid
			}
		}
	}
	// Both ref_idx lists precede both MVD lists. Derive motion afterwards in
	// partition order so spatial/direct neighbours have both lists available.
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
					i := (py+y)/4*4 + (px+x)/4
					deltas[list][i] = [2]int{r.se(-65535, 65535), r.se(-65535, 65535)}
				}
			}
		}
	}
	if r.bad {
		return ErrInvalid
	}
	if e := deriveBMotion(blocks, address, columns, h, s, parts, width, height, shape, modes, refs, deltas); e != nil {
		return e
	}
	cbp := interCBP[r.ue(47)]
	b.transform8 = cbp&15 != 0 && h.parameters.Transform8x8 && allow8 && r.flag()
	if r.bad {
		return ErrInvalid
	}
	return parseCAVLCResidual(r, blocks, address, columns, h, s, cbp)
}

// Motion is derived after both syntax lists, in partition order. Direct uses
// complete neighbouring predictions, including list 1 of earlier partitions.
func deriveBMotion(blocks []*intraMB, address, columns int, h *idrSlice, s *SPS,
	parts, width, height, shape int, modes [4]byte, refs [2][4]int, deltas [2][16][2]int) error {
	b := blocks[address]
	for part := 0; part < parts; part++ {
		if modes[part] == 0 {
			if e := deriveDirect(blocks, address, columns, part, h, s); e != nil {
				return e
			}
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
				i := (py+y)/4*4 + (px+x)/4
				for list := 0; list < 2; list++ {
					ref := refs[list][part]
					m := motion{ref: int8(ref), ready: true}
					if ref >= 0 {
						pred := predictMotionList(blocks, address, columns, px+x, py+y, sw, shape, part, ref, list)
						vx, vy := int(pred.x)+deltas[list][i][0], int(pred.y)+deltas[list][i][1]
						if !in16(int64(vx)) || !in16(int64(vy)) {
							return ErrInvalid
						}
						m.x, m.y = int16(vx), int16(vy)
					}
					setMotionList(b.inter, px+x, py+y, sw, sh, m, list)
				}
			}
		}
	}
	return nil
}

func orderDifference(a, b PictureOrder) (int, error) {
	d := int64(a.Count()) - int64(b.Count())
	if !in16(d) {
		return 0, ErrInvalid
	}
	return int(d), nil
}

func distanceScale(current, first, second PictureOrder) (int, error) {
	td, e := orderDifference(second, first)
	if e != nil {
		return 0, e
	}
	tb, e := orderDifference(current, first)
	if e != nil {
		return 0, e
	}
	td = max(-128, min(127, td))
	tb = max(-128, min(127, tb))
	if td == 0 {
		return 256, nil
	}
	tx := (16384 + abs(td/2)) / td
	return max(-1024, min(1023, (tb*tx+32)>>6)), nil
}

func deriveDirect(blocks []*intraMB, address, columns, quad int, h *idrSlice, s *SPS) error {
	b := blocks[address].inter
	b.direct |= 1 << quad
	colRef := h.list1[0]
	if colRef.picture == nil || address >= len(colRef.picture.motion) {
		return ErrInvalid
	}
	var base [2]motion
	zero := false
	if h.directSpatial {
		for list := 0; list < 2; list++ {
			a, _ := neighbourMotionList(blocks, address, columns, -1, 0, list)
			up, _ := neighbourMotionList(blocks, address, columns, 0, -1, list)
			c, ok := neighbourMotionList(blocks, address, columns, 16, -1, list)
			if !ok {
				c, _ = neighbourMotionList(blocks, address, columns, -1, -1, list)
			}
			ref := -1
			for _, m := range []motion{a, up, c} {
				if m.ref >= 0 && (ref < 0 || int(m.ref) < ref) {
					ref = int(m.ref)
				}
			}
			base[list] = motion{ref: int8(ref), ready: true}
			if ref >= 0 {
				base[list] = predictMotionList(blocks, address, columns, 0, 0, 16, 0, 0, ref, list)
			}
		}
		if base[0].ref < 0 && base[1].ref < 0 {
			base = [2]motion{{ref: 0, ready: true}, {ref: 0, ready: true}}
			zero = true
		}
	}
	px, py := quad%2*8, quad/2*8
	for y := 0; y < 8; y += 4 {
		for x := 0; x < 8; x += 4 {
			index := (py+y)/4*4 + (px+x)/4
			if s.Direct8x8 {
				index = blockRaster[5*quad]
			}
			col := colRef.picture.motion[address][index]
			pair := base
			if h.directSpatial {
				colZero := !colRef.longTerm && col.ref == 0 && abs(int(col.x)) <= 1 && abs(int(col.y)) <= 1
				for list := 0; list < 2; list++ {
					if zero || pair[list].ref < 0 || pair[list].ref == 0 && colZero {
						pair[list].x, pair[list].y = 0, 0
					}
				}
			} else {
				ref := 0
				if col.ref >= 0 {
					ref = -1
					for i := 0; i < h.references; i++ {
						if h.list0[i].picture != nil && h.list0[i].picture.id == col.reference {
							ref = i
							break
						}
					}
					if ref < 0 {
						return ErrInvalid
					}
				}
				first := h.list0[ref]
				if first.picture == nil {
					return ErrInvalid
				}
				pair = [2]motion{{x: col.x, y: col.y, ref: int8(ref), ready: true}, {ref: 0, ready: true}}
				diff := 0
				if !first.longTerm {
					var e error
					diff, e = orderDifference(colRef.order, first.order)
					if e != nil {
						return e
					}
				}
				if !first.longTerm && diff != 0 {
					scale, e := distanceScale(h.order, first.order, colRef.order)
					if e != nil {
						return e
					}
					vx, vy := (scale*int(col.x)+128)>>8, (scale*int(col.y)+128)>>8
					bx, by := vx-int(col.x), vy-int(col.y)
					if !in16(int64(vx)) || !in16(int64(vy)) || !in16(int64(bx)) || !in16(int64(by)) {
						return ErrInvalid
					}
					pair[0].x, pair[0].y, pair[1].x, pair[1].y = int16(vx), int16(vy), int16(bx), int16(by)
				}
			}
			for list, m := range pair {
				pool := &h.list0
				count := h.references
				if list == 1 {
					pool = &h.list1
					count = h.referencesL1
				}
				if m.ref >= 0 && (int(m.ref) >= count || pool[m.ref].picture == nil) {
					return ErrInvalid
				}
				setMotionList(b, px+x, py+y, 4, 4, m, list)
			}
		}
	}
	return nil
}
