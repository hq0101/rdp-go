package h264

import "fmt"

var interCBP = [48]int{0, 16, 1, 2, 4, 8, 32, 3, 5, 10, 12, 15, 47, 7, 11, 13, 14, 6, 9, 31, 35, 37, 42, 44, 33, 34, 36, 40, 39, 43, 45, 46, 17, 18, 20, 24, 19, 21, 26, 28, 23, 27, 29, 30, 22, 25, 38, 41}

type motion struct {
	x, y  int16
	ref   int8
	ready bool
}
type interMB struct {
	differences *[16][2]int32 // CABAC only; CAVLC does not need MVD contexts
	cells       [16]motion    // raster 4x4 grid; only earlier partitions are available
	list        *[32]predictionReference
	kind        byte
	skip        bool
	subTypes    [4]byte
	back        *backwardMotion // B only; nil means list 1 is unused
	biWeight    int
	order       PictureOrder
	direct      byte // bit per 8x8 quadrant
}

type backwardMotion struct {
	differences *[16][2]int32 // CABAC list-1 MVD contexts; Direct stays zero
	cells       [16]motion
	list        *[32]predictionReference
}

func parseCAVLCMB(r *bitReader, blocks []*intraMB, address, columns int, h *idrSlice, s *SPS) error {
	if h.sliceType == 2 {
		return parseIntraMB(r, blocks, address, columns, h, s)
	}
	if h.sliceType == 1 {
		return parseCAVLCB(r, blocks, address, columns, h, s)
	}
	kind := int(r.ue(30))
	if r.bad {
		return ErrInvalid
	}
	if kind >= 5 {
		return parseIntraKind(r, blocks, address, columns, h, s, byte(kind-5))
	}
	b := newInterMB(blocks, address, h)
	b.inter.kind = byte(kind)
	parts := 1
	w, ht := 16, 16
	switch kind {
	case 1:
		parts, ht = 2, 8
	case 2:
		parts, w = 2, 8
	case 3, 4:
		parts, w, ht = 4, 8, 8
	}
	allow8 := true
	if parts == 4 {
		for i := 0; i < 4; i++ {
			b.inter.subTypes[i] = byte(r.ue(3))
			if b.inter.subTypes[i] != 0 {
				allow8 = false
			}
		}
	}
	var refs [4]int
	if kind != 4 && h.references > 1 {
		for i := 0; i < parts; i++ {
			if h.references == 2 {
				refs[i] = int(1 - r.read(1))
			} else {
				refs[i] = int(r.ue(uint32(h.references - 1)))
			}
		}
	}
	for part := 0; part < parts; part++ {
		if r.bad || h.list0[refs[part]].picture == nil {
			return fmt.Errorf("unavailable ref_idx_l0: %w", ErrInvalid)
		}
		px, py := part*w%16, part*w/16*ht
		sw, sh := w, ht
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
		for y := 0; y < ht; y += sh {
			for x := 0; x < w; x += sw {
				pred := predictMotion(blocks, address, columns, px+x, py+y, sw, kind, part, refs[part])
				vx, vy := int(pred.x)+r.se(-65535, 65535), int(pred.y)+r.se(-65535, 65535)
				if r.bad || !in16(int64(vx)) || !in16(int64(vy)) {
					return ErrInvalid
				}
				setMotion(b.inter, px+x, py+y, sw, sh, motion{int16(vx), int16(vy), int8(refs[part]), true})
			}
		}
	}
	cbp := interCBP[r.ue(47)]
	b.transform8 = cbp&15 != 0 && h.parameters.Transform8x8 && allow8 && r.flag()
	if r.bad {
		return ErrInvalid
	}
	return parseCAVLCResidual(r, blocks, address, columns, h, s, cbp)
}

func newInterMB(blocks []*intraMB, address int, h *idrSlice) *intraMB {
	b := &intraMB{firstMB: h.firstMB, filter: h.filter, constrained: h.parameters.ConstrainedIntra, inter: &interMB{list: &h.list0}}
	for i := range b.inter.cells {
		b.inter.cells[i].ref = -1
	}
	b.qp = [3]int{h.qp, chromaQP(h.qp + h.parameters.ChromaQPOffset), chromaQP(h.qp + h.parameters.SecondChromaQPOffset)}
	blocks[address] = b
	return b
}

func parsePSkip(blocks []*intraMB, address, columns int, h *idrSlice) error {
	if h.list0[0].picture == nil {
		return fmt.Errorf("unavailable skip reference: %w", ErrInvalid)
	}
	b := newInterMB(blocks, address, h)
	b.inter.skip = true
	a, availableA := neighbourMotion(blocks, address, columns, -1, 0)
	c, availableB := neighbourMotion(blocks, address, columns, 0, -1)
	m := motion{ref: 0, ready: true}
	if availableA && availableB && !(a.ref == 0 && a.x == 0 && a.y == 0) && !(c.ref == 0 && c.x == 0 && c.y == 0) {
		m = predictMotion(blocks, address, columns, 0, 0, 16, 0, 0, 0)
	}
	setMotion(b.inter, 0, 0, 16, 16, m)
	return nil
}

func setMotion(b *interMB, x, y, w, h int, m motion) {
	for j := y / 4; j < (y+h)/4; j++ {
		for i := x / 4; i < (x+w)/4; i++ {
			b.cells[j*4+i] = m
		}
	}
}

func neighbourMotion(blocks []*intraMB, address, columns, x, y int) (motion, bool) {
	return neighbourMotionList(blocks, address, columns, x, y, 0)
}

func neighbourMotionList(blocks []*intraMB, address, columns, x, y, list int) (motion, bool) {
	b, index := neighbourBlock(blocks, address, columns, 0, x>>2, y>>2)
	if b == nil {
		return motion{ref: -1}, false
	}
	if b.inter == nil {
		return motion{ref: -1}, true
	}
	m := b.inter.cells[index]
	if list == 1 {
		if b.inter.back == nil {
			return motion{ref: -1}, true
		}
		m = b.inter.back.cells[index]
	}
	if !m.ready {
		return motion{ref: -1}, false
	}
	return m, true
}

// H.264 8.4.1.3: directional 16x8/8x16 rules, same-reference preference,
// median prediction, C-to-D substitution and the missing-top special case.
func predictMotion(blocks []*intraMB, address, columns, x, y, width, kind, part, ref int) motion {
	return predictMotionList(blocks, address, columns, x, y, width, kind, part, ref, 0)
}

func predictMotionList(blocks []*intraMB, address, columns, x, y, width, kind, part, ref, list int) motion {
	a, aa := neighbourMotionList(blocks, address, columns, x-1, y, list)
	b, ba := neighbourMotionList(blocks, address, columns, x, y-1, list)
	c, ca := neighbourMotionList(blocks, address, columns, x+width, y-1, list)
	if !ca {
		c, ca = neighbourMotionList(blocks, address, columns, x-1, y-1, list)
	}
	chosen := motion{ref: int8(ref), ready: true}
	if kind == 1 && part == 0 && int(b.ref) == ref {
		chosen.x, chosen.y = b.x, b.y
		return chosen
	}
	if (kind == 1 && part == 1 || kind == 2 && part == 0) && int(a.ref) == ref {
		chosen.x, chosen.y = a.x, a.y
		return chosen
	}
	if kind == 2 && part == 1 && int(c.ref) == ref {
		chosen.x, chosen.y = c.x, c.y
		return chosen
	}
	if !ba && !ca && aa {
		b, c = a, a
	}
	count := 0
	for _, m := range []motion{a, b, c} {
		if int(m.ref) == ref {
			chosen.x, chosen.y = m.x, m.y
			count++
		}
	}
	if count != 1 {
		chosen.x = median(a.x, b.x, c.x)
		chosen.y = median(a.y, b.y, c.y)
	}
	return chosen
}

func median(a, b, c int16) int16 { return max(min(a, b), min(max(a, b), c)) }

func parseCAVLCSlice(r *bitReader, blocks []*intraMB, h *idrSlice, s *SPS) (int, error) {
	mb, count := h.firstMB, 0
	for r.more() && !r.bad {
		if h.sliceType == 0 || h.sliceType == 1 {
			skip := int(r.ue(uint32(len(blocks))))
			if r.bad || skip > len(blocks)-mb {
				return 0, ErrInvalid
			}
			for j := 0; j < skip; j++ {
				if mb >= len(blocks) || blocks[mb] != nil {
					return 0, ErrInvalid
				}
				var e error
				if h.sliceType == 1 {
					e = parseBSkip(blocks, mb, s.WidthInMBs, h, s)
				} else {
					e = parsePSkip(blocks, mb, s.WidthInMBs, h)
				}
				if e != nil {
					return 0, e
				}
				count++
				mb++
			}
			if skip > 0 && !r.more() {
				break
			}
		}
		if mb >= len(blocks) || blocks[mb] != nil {
			return 0, ErrInvalid
		}
		if e := parseCAVLCMB(r, blocks, mb, s.WidthInMBs, h, s); e != nil {
			return 0, fmt.Errorf("macroblock %d at bit %d: %w", mb, r.pos, e)
		}
		count++
		mb++
	}
	if mb == h.firstMB {
		return 0, ErrInvalid
	}
	if e := r.trailing(); e != nil {
		return 0, e
	}
	return count, nil
}
