package h264

import (
	"fmt"
	"image"
	"slices"
	"sort"
)

// MaxReferencePixels bounds retained reference storage to 96 MiB of 8-bit 4:2:0
// samples. It is independent of the per-picture MaxPixels parsing limit.
const MaxReferencePixels = 64 << 20

// Reference pixels are private and immutable. Neither caller-owned outputs nor
// a Decoder value copy can change another decoding branch's reference samples.
type referencePicture struct {
	samples *image.YCbCr
	id      uint64
	motion  []colocatedMB
}

// Numeric identities avoid retaining chains of prior sample buffers. Only the
// selected collocated list (L0 when used, otherwise L1) is needed by Direct.
type colocatedMotion struct {
	reference uint64
	x, y      int16
	ref       int8
}
type colocatedMB [16]colocatedMotion
type referenceSlot struct {
	picture            *referencePicture // nil denotes an inferred, non-existing frame
	frameNum, longTerm int               // -1 for short-term
	order              PictureOrder      // also retained for inferred frames of POC type 1/2
}
type referenceBuffer struct {
	slots                           [16]referenceSlot
	count, maxLongTerm, previousRef int
	sequence                        *SPS
	poc                             pictureOrderState
	nextID                          uint64
}

func pictureNumber(n, current, modulus int) int {
	if n > current {
		return n - modulus
	}
	return n
}

func (b *referenceBuffer) remove(i int) {
	copy(b.slots[i:b.count-1], b.slots[i+1:b.count])
	b.count--
	b.slots[b.count] = referenceSlot{}
}
func (b *referenceBuffer) findShort(num, current, modulus int) int {
	for i, s := range b.slots[:b.count] {
		if s.longTerm < 0 && pictureNumber(s.frameNum, current, modulus) == num {
			return i
		}
	}
	return -1
}
func (b *referenceBuffer) findLong(num int) int {
	for i, s := range b.slots[:b.count] {
		if s.longTerm == num {
			return i
		}
	}
	return -1
}
func (b *referenceBuffer) slide(current int, s *SPS) error {
	limit := max(1, s.MaxReferences)
	if b.count < limit {
		return nil
	}
	if b.count > limit {
		return ErrInvalid
	}
	oldest, number := -1, 1<<s.Log2FrameNum
	for i, slot := range b.slots[:b.count] {
		n := pictureNumber(slot.frameNum, current, 1<<s.Log2FrameNum)
		if slot.longTerm < 0 && n < number {
			oldest, number = i, n
		}
	}
	if oldest < 0 {
		return fmt.Errorf("reference window contains only long-term pictures: %w", ErrInvalid)
	}
	b.remove(oldest)
	return nil
}

func (b *referenceBuffer) prepare(h *idrSlice, s *SPS) error {
	return b.prepareOutput(h, s, nil)
}

func (b *referenceBuffer) prepareOutput(h *idrSlice, s *SPS, output *outputProcess) error {
	if h.idr {
		*b = referenceBuffer{maxLongTerm: -1, sequence: s}
		return b.poc.derive(h, s)
	}
	if b.sequence == nil {
		return fmt.Errorf("non-IDR picture before an IDR: %w", ErrInvalid)
	}
	old := b.sequence
	if old.CodedWidth != s.CodedWidth || old.CodedHeight != s.CodedHeight || old.Log2FrameNum != s.Log2FrameNum || old.POCType != s.POCType || old.Log2POCLSB != s.Log2POCLSB || old.DeltaPOCAlwaysZero != s.DeltaPOCAlwaysZero || old.OffsetNonRef != s.OffsetNonRef || old.OffsetTopBottom != s.OffsetTopBottom || !slices.Equal(old.POCCycle, s.POCCycle) {
		return fmt.Errorf("sequence change requires an IDR: %w", ErrUnsupported)
	}
	if b.count > max(1, s.MaxReferences) {
		return ErrInvalid
	}
	b.sequence = s
	modulus := 1 << s.Log2FrameNum
	if h.reference && h.frameNum == b.previousRef {
		return fmt.Errorf("duplicate reference frame_num: %w", ErrInvalid)
	}
	if h.frameNum == b.previousRef || h.frameNum == (b.previousRef+1)%modulus {
		return b.poc.derive(h, s)
	}
	if !s.AllowFrameNumGaps {
		return fmt.Errorf("missing reference frame_num: %w", ErrInvalid)
	}
	// At most MaxFrameNum-2 iterations (<=65534), with <=16 metadata slots
	// and no sample allocation for missing pictures.
	for n := (b.previousRef + 1) % modulus; n != h.frameNum; n = (n + 1) % modulus {
		if err := b.slide(n, s); err != nil {
			return err
		}
		// Non-existing frames occupy DPB slots too. Bump after marking and
		// before each inferred frame, not just after the final real picture.
		if err := output.makeRoom(b); err != nil {
			return err
		}
		inferred := idrSlice{pictureKey: pictureKey{frameNum: n, reference: true}}
		if s.POCType != 0 {
			if err := b.poc.derive(&inferred, s); err != nil {
				return err
			}
		}
		b.slots[b.count] = referenceSlot{frameNum: n, longTerm: -1, order: inferred.storedOrder}
		b.count++
		b.previousRef = n
	}
	return b.poc.derive(h, s)
}

func (b *referenceBuffer) list(h *idrSlice, s *SPS) error {
	if h.sliceType == 1 {
		return b.listB(h, s)
	}
	var order [32]*referenceSlot
	n := 0
	for i := 0; i < b.count; i++ {
		order[n] = &b.slots[i]
		n++
	}
	modulus := 1 << s.Log2FrameNum
	sort.Slice(order[:n], func(i, j int) bool {
		a, c := order[i], order[j]
		if a.longTerm < 0 && c.longTerm < 0 {
			return pictureNumber(a.frameNum, h.frameNum, modulus) > pictureNumber(c.frameNum, h.frameNum, modulus)
		}
		if a.longTerm < 0 || c.longTerm < 0 {
			return a.longTerm < 0
		}
		return a.longTerm < c.longTerm
	})
	if err := b.modifyList(&order, h.modifications[:h.modificationCount], h.references, h.frameNum, modulus); err != nil {
		return err
	}
	existing := publishList(order, h.list0[:h.references])
	if !existing {
		return fmt.Errorf("P slice has no reference picture: %w", ErrInvalid)
	}
	return nil
}

func (b *referenceBuffer) modifyList(order *[32]*referenceSlot, modifications []listModification, references, frameNum, modulus int) error {
	// Initial lists are truncated before modifications; absent entries remain nil.
	for i := references; i < len(order); i++ {
		order[i] = nil
	}
	predicted := frameNum
	for index, m := range modifications {
		var slot *referenceSlot
		if m.op != 2 {
			delta := m.value + 1
			if m.op == 0 {
				delta = -delta
			}
			predicted = (predicted + delta + modulus) % modulus
			at := b.findShort(pictureNumber(predicted, frameNum, modulus), frameNum, modulus)
			if at >= 0 {
				slot = &b.slots[at]
			}
		} else {
			at := b.findLong(m.value)
			if at >= 0 {
				slot = &b.slots[at]
			}
		}
		if slot == nil || slot.picture == nil {
			return fmt.Errorf("missing modified reference: %w", ErrInvalid)
		}
		var next [32]*referenceSlot
		copy(next[:index], order[:index])
		next[index] = slot
		write := index + 1
		for _, old := range order[index:references] {
			if old != slot && write < references {
				next[write] = old
				write++
			}
		}
		*order = next
	}
	return nil
}

func publishList(order [32]*referenceSlot, list []predictionReference) bool {
	existing := false
	for i := range list {
		list[i].picture = nil
		list[i].order, list[i].longTerm = PictureOrder{}, false
		if order[i] != nil {
			list[i].picture = order[i].picture
			list[i].order, list[i].longTerm = order[i].order, order[i].longTerm >= 0
		}
		if list[i].picture != nil {
			existing = true
		}
	}
	return existing
}

func (b *referenceBuffer) store(samples *image.YCbCr, h *idrSlice, s *SPS, blocks []*intraMB) error {
	return b.storeOutput(samples, h, s, blocks, nil, MaxReferencePixels)
}

func (b *referenceBuffer) pixels() int {
	pixels := 0
	for _, slot := range b.slots[:b.count] {
		if slot.picture != nil {
			pixels += slot.picture.samples.Rect.Dx() * slot.picture.samples.Rect.Dy()
		}
	}
	return pixels
}

func (b *referenceBuffer) storeOutput(samples *image.YCbCr, h *idrSlice, s *SPS, blocks []*intraMB, output *outputProcess, pixelBudget int) error {
	if !h.reference {
		return nil
	}
	frameNum, longTerm := h.frameNum, -1
	modulus := 1 << s.Log2FrameNum
	if h.idr {
		if h.longTerm {
			longTerm, b.maxLongTerm = 0, 0
		}
	} else if !h.adaptive {
		if err := b.slide(h.frameNum, s); err != nil {
			return err
		}
	} else {
		for _, m := range h.marking[:h.markingCount] {
			switch m.op {
			case 1, 3:
				at := b.findShort(h.frameNum-m.a-1, h.frameNum, modulus)
				if at < 0 {
					return fmt.Errorf("MMCO targets missing short-term reference: %w", ErrInvalid)
				}
				if m.op == 1 {
					b.remove(at)
					continue
				}
				slot := b.slots[at]
				if slot.picture == nil || m.b > b.maxLongTerm {
					return ErrInvalid
				}
				if m.b == longTerm {
					return ErrInvalid
				}
				b.remove(at)
				if old := b.findLong(m.b); old >= 0 {
					b.remove(old)
				}
				slot.longTerm = m.b
				b.slots[b.count] = slot
				b.count++
			case 2:
				at := b.findLong(m.a)
				if at < 0 {
					return fmt.Errorf("MMCO targets missing long-term reference: %w", ErrInvalid)
				}
				b.remove(at)
			case 4:
				b.maxLongTerm = m.a - 1
				if longTerm > b.maxLongTerm {
					return ErrInvalid
				}
				for i := b.count - 1; i >= 0; i-- {
					if b.slots[i].longTerm > b.maxLongTerm {
						b.remove(i)
					}
				}
			case 5:
				*b = referenceBuffer{maxLongTerm: -1, sequence: s, poc: b.poc, nextID: b.nextID}
				frameNum = 0
			case 6:
				if m.b > b.maxLongTerm {
					return ErrInvalid
				}
				if at := b.findLong(m.b); at >= 0 {
					b.remove(at)
				}
				if b.count >= max(1, s.MaxReferences) {
					return ErrInvalid
				}
				longTerm = m.b
			}
		}
	}
	if b.count >= max(1, s.MaxReferences) || b.count >= len(b.slots) {
		return fmt.Errorf("reference buffer full: %w", ErrInvalid)
	}
	if err := output.makeRoom(b); err != nil {
		return err
	}
	if err := output.checkPixels(b, samples.Rect.Dx()*samples.Rect.Dy()); err != nil {
		return err
	}
	pixels := samples.Rect.Dx() * samples.Rect.Dy()
	for _, slot := range b.slots[:b.count] {
		if slot.picture != nil {
			pixels += slot.picture.samples.Rect.Dx() * slot.picture.samples.Rect.Dy()
		}
	}
	if pixels > min(MaxReferencePixels, pixelBudget) {
		return fmt.Errorf("reference pixel limit: %w", ErrUnsupported)
	}
	if b.nextID == ^uint64(0) {
		return ErrInvalid
	}
	// <=64 MiB of compact motion records at the aggregate reference pixel
	// limit, in addition to <=96 MiB of samples. No recursive references.
	motion, err := retainMotion(blocks, samples.Rect.Dx()*samples.Rect.Dy()/256)
	if err != nil {
		return err
	}
	owned := image.NewYCbCr(samples.Rect, image.YCbCrSubsampleRatio420)
	copy(owned.Y, samples.Y)
	copy(owned.Cb, samples.Cb)
	copy(owned.Cr, samples.Cr)
	b.nextID++
	b.slots[b.count] = referenceSlot{picture: &referencePicture{samples: owned, id: b.nextID, motion: motion}, frameNum: frameNum, longTerm: longTerm, order: h.storedOrder}
	b.count++
	b.previousRef = frameNum
	return nil
}

func retainMotion(blocks []*intraMB, count int) ([]colocatedMB, error) {
	if len(blocks) != count {
		return nil, ErrInvalid
	}
	result := make([]colocatedMB, count)
	for at, b := range blocks {
		if b == nil {
			return nil, ErrInvalid
		}
		for i := 0; i < 16; i++ {
			result[at][i].ref = -1
			if b.inter == nil {
				continue
			}
			m, pool := b.inter.cells[i], b.inter.list
			if m.ref < 0 && b.inter.back != nil {
				m, pool = b.inter.back.cells[i], b.inter.back.list
			}
			if !m.ready || m.ref < 0 || int(m.ref) >= len(pool) || pool[m.ref].picture == nil {
				return nil, ErrInvalid
			}
			result[at][i] = colocatedMotion{reference: pool[m.ref].picture.id, x: m.x, y: m.y, ref: m.ref}
		}
	}
	return result, nil
}
