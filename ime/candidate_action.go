package ime

import (
	"github.com/hq0101/rdp-go/rail"
	"slices"
)

// CandidateToken identifies one element in one successful Candidates snapshot.
// Refresh, native presentation changes, an attempted action, focus changes and
// close invalidate it. It cannot be transferred to another document or input.
type CandidateToken struct{ lease *candidateLease }
type candidateLease struct{ marker byte }

type CandidateActionKind uint8

const (
	CandidateSelect CandidateActionKind = iota + 1
	// CandidateSelectPage selects the first candidate of an existing page.
	CandidateSelectPage
	// CandidateSetPages defines page boundaries; it does not navigate pages.
	CandidateSetPages
	CandidateFinalize
	// CandidateAbort asks the service to close its list. The service may still
	// finalize text; this is not a guarantee to discard a composition.
	CandidateAbort
	CandidateShow
)

// CandidateAction uses Index for Select/SelectPage, PageStarts for SetPages,
// and Visible for Show. All unused fields must be zero/empty. Finalize acts on
// the currently sampled selection; select and refresh first to choose another.
type CandidateAction struct {
	Kind       CandidateActionKind
	Index      uint32
	PageStarts []uint32
	Visible    bool
}

type candidateCommand struct {
	slot     int
	value    uint32
	pages    []uint32
	behavior bool
}

func candidateCommandFor(v CandidateList, action CandidateAction) (candidateCommand, error) {
	c := candidateCommand{}
	if action.Kind != CandidateShow && action.Visible || action.Kind != CandidateSetPages && len(action.PageStarts) != 0 || action.Kind != CandidateSelect && action.Kind != CandidateSelectPage && action.Index != 0 {
		return c, rail.ErrInvalid
	}
	switch action.Kind {
	case CandidateSelect:
		if uint64(action.Index) >= uint64(len(v.Strings)) {
			return c, rail.ErrInvalid
		}
		c.slot, c.value, c.behavior = 15, action.Index, true
	case CandidateSelectPage:
		if uint64(action.Index) >= uint64(len(v.PageStarts)) {
			return c, rail.ErrInvalid
		}
		c.slot, c.value, c.behavior = 15, v.PageStarts[action.Index], true
	case CandidateSetPages:
		if !validCandidatePages(len(v.Strings), -1, action.PageStarts, 0) {
			return c, rail.ErrInvalid
		}
		c.slot, c.pages = 13, slices.Clone(action.PageStarts)
	case CandidateFinalize:
		if v.Selection < 0 {
			return c, rail.ErrInvalid
		}
		c.slot, c.behavior = 16, true
	case CandidateAbort:
		c.slot, c.behavior = 17, true
	case CandidateShow:
		c.slot = 5
		if action.Visible {
			c.value = 1
		}
	default:
		return c, rail.ErrInvalid
	}
	return c, nil
}

func cloneCandidate(v CandidateList) CandidateList {
	v.Token = CandidateToken{}
	v.Strings = slices.Clone(v.Strings)
	v.PageStarts = slices.Clone(v.PageStarts)
	return v
}
func sameCandidate(a, b CandidateList) bool {
	return a.Kind == b.Kind && a.NativeShown == b.NativeShown && a.SupportsBehavior == b.SupportsBehavior && a.Selection == b.Selection && a.CurrentPage == b.CurrentPage && slices.Equal(a.Strings, b.Strings) && slices.Equal(a.PageStarts, b.PageStarts)
}
