package h264

import "fmt"

// PictureOrder contains the H.264 top/bottom field order counts of a progressive
// frame. They are relative to the latest IDR or MMCO 5 reset, not timestamps.
// They do not imply that field-coded pictures are supported.
type PictureOrder struct {
	TopField, BottomField int32
}

// Count returns PicOrderCnt for a frame (H.264 8.2.1).
func (p PictureOrder) Count() int32 { return min(p.TopField, p.BottomField) }

// All history is value-owned, so a failed AU or a copied Decoder cannot change
// another branch. Type 0 follows the previous reference picture; types 1 and 2
// follow every decoded picture, including inferred non-existing frames.
type pictureOrderState struct {
	initialized                              bool
	previousFrameNum                         int
	frameNumOffset, previousMSB, previousLSB int32
	largest                                  int32
}

func (h *idrSlice) resetsOrder() bool {
	for _, m := range h.marking[:h.markingCount] {
		if m.op == 5 {
			return true
		}
	}
	return false
}

func orderInRange(n int64) bool { return n >= -1<<31 && n <= 1<<31-1 }

// derive keeps the order used during prediction separate from the order stored
// after MMCO 5. H.264 8.2.1 changes the current counts only after reconstruction.
func (p *pictureOrderState) derive(h *idrSlice, s *SPS) error {
	next := *p
	if h.idr {
		next = pictureOrderState{}
	} else if !next.initialized {
		return fmt.Errorf("picture order before IDR: %w", ErrInvalid)
	}
	var top, bottom, msb int64
	offset := int64(next.frameNumOffset)
	if s.POCType != 0 && next.previousFrameNum > h.frameNum {
		offset += 1 << s.Log2FrameNum
	}
	if !orderInRange(offset) {
		return fmt.Errorf("frame number offset: %w", ErrInvalid)
	}
	switch s.POCType {
	case 0:
		modulus := int64(1 << s.Log2POCLSB)
		lsb, previous := int64(h.poc), int64(next.previousLSB)
		msb = int64(next.previousMSB)
		if lsb < previous && previous-lsb >= modulus/2 {
			msb += modulus
		} else if lsb > previous && lsb-previous > modulus/2 {
			msb -= modulus
		}
		top = msb + lsb
		bottom = top + int64(h.deltaBottom)
	case 1:
		absolute := int64(0)
		if len(s.POCCycle) != 0 {
			absolute = offset + int64(h.frameNum)
		}
		if !h.reference && absolute > 0 {
			absolute--
		}
		expected := int64(0)
		if absolute > 0 {
			var cycle int64
			for _, delta := range s.POCCycle {
				cycle += int64(delta)
			}
			length := int64(len(s.POCCycle))
			// With signed-32-bit offsets and <=255 signed-32-bit terms,
			// the sum/product remain within int64 even for a rejected POC.
			expected = (absolute - 1) / length * cycle
			for i := int64(0); i <= (absolute-1)%length; i++ {
				expected += int64(s.POCCycle[i])
			}
		}
		if !h.reference {
			expected += int64(s.OffsetNonRef)
		}
		top = expected + int64(h.delta0)
		bottom = top + int64(s.OffsetTopBottom) + int64(h.delta1)
	case 2:
		if !h.idr {
			top = 2 * (offset + int64(h.frameNum))
			if !h.reference {
				top--
			}
		}
		bottom = top
	default:
		return ErrInvalid
	}
	if !orderInRange(top) || !orderInRange(bottom) || !orderInRange(msb) {
		return fmt.Errorf("picture order range: %w", ErrInvalid)
	}
	current := PictureOrder{int32(top), int32(bottom)}
	if h.idr && current.Count() != 0 {
		return fmt.Errorf("IDR picture order is not zero: %w", ErrInvalid)
	}
	stored := current
	reset := h.resetsOrder()
	if reset {
		if !h.reference || current.Count() <= next.largest {
			return fmt.Errorf("MMCO 5 picture must follow preceding pictures: %w", ErrInvalid)
		}
		top -= int64(current.Count())
		bottom -= int64(current.Count())
		if !orderInRange(top) || !orderInRange(bottom) {
			return fmt.Errorf("MMCO 5 picture order range: %w", ErrInvalid)
		}
		stored = PictureOrder{int32(top), int32(bottom)}
		next.largest = stored.Count()
	} else if h.idr || current.Count() > next.largest {
		next.largest = current.Count()
	}
	next.previousFrameNum, next.frameNumOffset = h.frameNum, int32(offset)
	if reset {
		next.previousFrameNum, next.frameNumOffset = 0, 0
	}
	if s.POCType == 0 && h.reference {
		next.previousMSB, next.previousLSB = int32(msb), int32(h.poc)
		if reset {
			next.previousMSB, next.previousLSB = 0, stored.TopField
		}
	}
	next.initialized = true
	h.order, h.storedOrder = current, stored
	*p = next
	return nil
}
