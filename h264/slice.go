package h264

// Fixed command bounds keep malicious headers from allocating unbounded lists.
// A progressive reference buffer holds at most sixteen pictures.
type markingOperation struct{ op, a, b int }
type listModification struct{ op, value int }

type pictureKey struct {
	pps                                          byte
	id, poc, deltaBottom, delta0, delta1         int
	frameNum                                     int
	idr, reference, noOutput, longTerm, adaptive bool
	marking                                      [64]markingOperation
	markingCount                                 int
}
type predictionWeight struct{ denom, weight, offset int }
type predictionReference struct {
	picture  *referencePicture
	weights  [3]predictionWeight
	order    PictureOrder
	longTerm bool
}
type idrSlice struct {
	pictureKey
	firstMB, qp, sliceType int
	cabacInit              int
	parameters             PPS
	filter                 deblockParams
	references             int
	modifications          [32]listModification
	modificationCount      int
	list0                  [32]predictionReference
	referencesL1           int
	modificationsL1        [32]listModification
	modificationCountL1    int
	list1                  [32]predictionReference
	directSpatial          bool
	order, storedOrder     PictureOrder
}

// Retained for the independent intra syntax fixtures.
func (d *Decoder) idrHeader(r *bitReader) (idrSlice, *SPS, error) {
	return d.sliceHeader(r, true, true)
}

func (d *Decoder) sliceHeader(r *bitReader, idr, reference bool) (idrSlice, *SPS, error) {
	h := idrSlice{firstMB: int(r.ue(MaxPixels/256 - 1))}
	h.idr, h.reference = idr, reference
	st, id := r.ue(9), r.ue(255)
	if r.bad || d.pictures[id].Type != 8 {
		return h, nil, ErrInvalid
	}
	h.sliceType = int(st % 5)
	if h.sliceType != 2 && (h.sliceType != 0 && h.sliceType != 1 || idr) {
		return h, nil, ErrUnsupported
	}
	peek := bitReader{data: d.pictures[id].RBSP}
	peek.ue(255)
	s := d.sequences[peek.ue(31)]
	if peek.bad || s == nil {
		return h, nil, ErrInvalid
	}
	p, err := ParsePPS(d.pictures[id], *s)
	if err != nil {
		return h, nil, err
	}
	h.parameters, h.pps = p, p.ID
	if !s.FrameOnly || s.ChromaFormat != 1 || s.SeparateColourPlane || s.BitDepthLuma != 8 || s.BitDepthChroma != 8 {
		return h, nil, ErrUnsupported
	}
	h.frameNum = int(r.read(s.Log2FrameNum))
	if h.firstMB >= s.WidthInMBs*s.HeightInMapUnits || idr && h.frameNum != 0 {
		return h, nil, ErrInvalid
	}
	if idr {
		h.id = int(r.ue(65535))
	}
	if s.POCType == 0 {
		h.poc = int(r.read(s.Log2POCLSB))
		if p.BottomFieldPOC {
			h.deltaBottom = r.se(-2147483647, 2147483647)
		}
	}
	if s.POCType == 1 && !s.DeltaPOCAlwaysZero {
		h.delta0 = r.se(-2147483647, 2147483647)
		if p.BottomFieldPOC {
			h.delta1 = r.se(-2147483647, 2147483647)
		}
	}
	if p.RedundantPictures && r.ue(127) != 0 {
		return h, nil, ErrUnsupported
	}
	if h.sliceType == 1 {
		h.directSpatial = r.flag()
	}
	if h.sliceType == 0 || h.sliceType == 1 {
		h.references = p.ReferencesL0
		h.referencesL1 = p.ReferencesL1
		if r.flag() {
			h.references = int(r.ue(31)) + 1
			if h.sliceType == 1 {
				h.referencesL1 = int(r.ue(31)) + 1
			}
		}
		h.modificationCount = parseListModifications(r, s, h.references, &h.modifications)
		if h.sliceType == 1 {
			h.modificationCountL1 = parseListModifications(r, s, h.referencesL1, &h.modificationsL1)
		}
		weighted := p.WeightedPrediction && h.sliceType == 0 || p.WeightedBiPrediction == 1 && h.sliceType == 1
		denominators := [3]int{}
		if weighted {
			denominators[0] = int(r.ue(7))
			denominators[1] = int(r.ue(7))
			denominators[2] = denominators[1]
		}
		parsePredictionWeights(r, denominators, weighted, h.list0[:h.references])
		if h.sliceType == 1 {
			parsePredictionWeights(r, denominators, weighted, h.list1[:h.referencesL1])
		}
	}
	if reference {
		if idr {
			h.noOutput, h.longTerm = r.flag(), r.flag()
			if h.longTerm && s.MaxReferences == 0 {
				return h, nil, ErrInvalid
			}
		} else {
			h.adaptive = r.flag()
			if h.adaptive {
				var seen [7]bool
				for !r.bad {
					op := int(r.ue(6))
					if op == 0 {
						break
					}
					if h.markingCount == len(h.marking) || op >= 4 && seen[op] || op == 5 && (seen[1] || seen[2] || seen[3] || seen[6]) || op >= 1 && op <= 3 && seen[5] {
						return h, nil, ErrInvalid
					}
					m := markingOperation{op: op}
					if op == 1 || op == 3 {
						m.a = int(r.ue(uint32((1 << s.Log2FrameNum) - 1)))
					}
					if op == 2 {
						m.a = int(r.ue(15))
					}
					if op == 3 || op == 6 {
						m.b = int(r.ue(15))
					}
					if op == 4 {
						m.a = int(r.ue(uint32(s.MaxReferences)))
					}
					seen[op] = true
					h.marking[h.markingCount] = m
					h.markingCount++
				}
			}
		}
	}
	if p.CABAC && h.sliceType != 2 {
		h.cabacInit = int(r.ue(2))
	}
	h.qp = p.InitialQP + r.se(-51, 51)
	if h.qp < 0 || h.qp > 51 {
		return h, nil, ErrInvalid
	}
	if p.DeblockingControl {
		h.filter.disable = byte(r.ue(2))
		if h.filter.disable != 1 {
			h.filter.alpha = 2 * r.se(-6, 6)
			h.filter.beta = 2 * r.se(-6, 6)
		}
	}
	if r.bad {
		return h, nil, ErrInvalid
	}
	return h, s, nil
}

func parseListModifications(r *bitReader, s *SPS, references int, list *[32]listModification) int {
	count := 0
	if r.flag() {
		for !r.bad {
			op := int(r.ue(3))
			if op == 3 {
				break
			}
			if count >= references || count >= len(list) {
				r.bad = true
				break
			}
			bound := uint32((1 << s.Log2FrameNum) - 1)
			if op == 2 {
				bound = 15
			}
			list[count] = listModification{op, int(r.ue(bound))}
			count++
		}
	}
	return count
}

func parsePredictionWeights(r *bitReader, denominators [3]int, weighted bool, list []predictionReference) {
	for i := range list {
		for c, denom := range denominators {
			list[i].weights[c] = predictionWeight{denom, 1 << denom, 0}
		}
		if weighted {
			if r.flag() {
				list[i].weights[0].weight = r.se(-128, 127)
				list[i].weights[0].offset = r.se(-128, 127)
			}
			if r.flag() {
				for c := 1; c < 3; c++ {
					list[i].weights[c].weight = r.se(-128, 127)
					list[i].weights[c].offset = r.se(-128, 127)
				}
			}
		}
	}
}
