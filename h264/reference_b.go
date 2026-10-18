package h264

import (
	"fmt"
	"sort"
)

// The B-frame initial lists follow POC, not frame_num (8.2.4.2.3). This layer
// does not itself decode B macroblocks or implement direct/bi prediction.
func (b *referenceBuffer) listB(h *idrSlice, s *SPS) error {
	var lists [2][32]*referenceSlot
	n, existing := 0, false
	for i := 0; i < b.count; i++ {
		slot := &b.slots[i]
		if slot.picture == nil && s.POCType == 0 {
			continue // No POC is inferred for these non-existing frames.
		}
		if slot.picture != nil {
			existing = true
		}
		if slot.order.Count() == h.order.Count() {
			return fmt.Errorf("reference has current picture order: %w", ErrInvalid)
		}
		lists[0][n], lists[1][n] = slot, slot
		n++
	}
	if !existing {
		return fmt.Errorf("B slice has no reference picture: %w", ErrInvalid)
	}
	for list := 0; list < 2; list++ {
		order := &lists[list]
		sort.Slice(order[:n], func(i, j int) bool {
			a, c := order[i], order[j]
			if a.longTerm >= 0 || c.longTerm >= 0 {
				if a.longTerm < 0 || c.longTerm < 0 {
					return a.longTerm < 0
				}
				return a.longTerm < c.longTerm
			}
			ap, cp, current := a.order.Count(), c.order.Count(), h.order.Count()
			if list == 0 {
				if (ap < current) != (cp < current) {
					return ap < current
				}
				if ap < current {
					return ap > cp
				}
				return ap < cp
			}
			if (ap > current) != (cp > current) {
				return ap > current
			}
			if ap > current {
				return ap < cp
			}
			return ap > cp
		})
	}
	// Compare the complete initial lists before active-count truncation.
	if n > 1 && lists[0] == lists[1] {
		lists[1][0], lists[1][1] = lists[1][1], lists[1][0]
	}
	modulus := 1 << s.Log2FrameNum
	if err := b.modifyList(&lists[0], h.modifications[:h.modificationCount], h.references, h.frameNum, modulus); err != nil {
		return err
	}
	if err := b.modifyList(&lists[1], h.modificationsL1[:h.modificationCountL1], h.referencesL1, h.frameNum, modulus); err != nil {
		return err
	}
	publishList(lists[0], h.list0[:h.references])
	publishList(lists[1], h.list1[:h.referencesL1])
	return nil
}
