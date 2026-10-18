package ime

import "github.com/hq0101/rdp-go/rail"

// TextSelection uses UTF-16 code-unit offsets (ACP), not bytes or rune indices.
// ActiveEnd is 0 (none), 1 (start), or 2 (end); interim selections use 0.
type TextSelection struct {
	Start, End int32
	ActiveEnd  uint32
	Interim    bool
}

type TextRange struct{ Start, End int32 }

// TextRect is an actual rendered rectangle in screen coordinates.
type TextRect struct{ Left, Top, Right, Bottom int32 }

// TextLayout describes the current UTF-16 text, with one bounding rectangle per
// code unit and one caret rectangle per insertion position, including the end.
// The renderer supplies the geometry; the library does not guess font metrics.
// Text changes invalidate it. Clipped reports that text extends outside Screen.
type TextLayout struct {
	Screen        TextRect
	Units, Carets []TextRect
	Clipped       bool
}

type WindowsDocumentOptions struct {
	// MaxUnits defaults to 4096 and must be in [1, 32768].
	MaxUnits  int
	Text      []uint16
	Selection TextSelection
}

// TextSnapshot is a copy of one local text store, not remote desktop text and
// not a stream of committed input. Text may contain temporary UTF-16 fragments.
// Compositions describes active TSF ranges, without clause/display attributes.
// Revision is local to this document; it is not a connection or focus token.
type TextSnapshot struct {
	Text         []uint16
	Selection    TextSelection
	Compositions []TextRange
	Revision     uint64
}

type textState struct {
	text      []uint16
	selection TextSelection
	max       int
	revision  uint64
	layout    TextLayout
	laidOut   bool
}

func newTextState(o WindowsDocumentOptions) (textState, error) {
	if o.MaxUnits == 0 {
		o.MaxUnits = 4096
	}
	if o.MaxUnits < 1 || o.MaxUnits > 32768 || len(o.Text) > o.MaxUnits || !validSelection(o.Selection, len(o.Text)) {
		return textState{}, rail.ErrInvalid
	}
	return textState{text: append([]uint16(nil), o.Text...), selection: o.Selection, max: o.MaxUnits, revision: 1}, nil
}
func validSelection(s TextSelection, n int) bool {
	return s.Start >= 0 && s.End >= s.Start && int64(s.End) <= int64(n) && s.ActiveEnd <= 2 && (!s.Interim || s.ActiveEnd == 0)
}
func (s *textState) validRange(start, end int32) bool {
	return start >= 0 && end >= start && int64(end) <= int64(len(s.text))
}
func (s *textState) canReplace(start, end int32, n uint32) bool {
	return s.validRange(start, end) && uint64(len(s.text))-uint64(end-start)+uint64(n) <= uint64(s.max)
}
func (s *textState) bump() bool {
	if s.revision == ^uint64(0) {
		return false
	}
	s.revision++
	return true
}
func (s *textState) replace(start, end int32, text []uint16) bool {
	if !s.canReplace(start, end, uint32(len(text))) || s.revision == ^uint64(0) {
		return false
	}
	v := make([]uint16, 0, len(s.text)-int(end-start)+len(text))
	v = append(v, s.text[:start]...)
	v = append(v, text...)
	v = append(v, s.text[end:]...)
	s.text = v
	s.selection = TextSelection{Start: start + int32(len(text)), End: start + int32(len(text)), ActiveEnd: 2}
	s.layout = TextLayout{}
	s.laidOut = false
	s.bump()
	return true
}
func validRect(r TextRect) bool { return r.Right >= r.Left && r.Bottom >= r.Top }
func (s *textState) setLayout(v TextLayout) error {
	if len(v.Units) != len(s.text) || len(v.Carets) != len(s.text)+1 || !validRect(v.Screen) {
		return rail.ErrInvalid
	}
	for _, list := range [][]TextRect{v.Units, v.Carets} {
		for _, r := range list {
			if !validRect(r) {
				return rail.ErrInvalid
			}
		}
	}
	if !s.bump() {
		return rail.ErrBusy
	}
	v.Units = append([]TextRect(nil), v.Units...)
	v.Carets = append([]TextRect(nil), v.Carets...)
	s.layout = v
	s.laidOut = true
	return nil
}
func (s *textState) bounds(start, end int32) (TextRect, bool) {
	if !s.laidOut || !s.validRange(start, end) {
		return TextRect{}, false
	}
	if start == end {
		return s.layout.Carets[start], true
	}
	r := s.layout.Units[start]
	for _, v := range s.layout.Units[start+1 : end] {
		r.Left = min(r.Left, v.Left)
		r.Top = min(r.Top, v.Top)
		r.Right = max(r.Right, v.Right)
		r.Bottom = max(r.Bottom, v.Bottom)
	}
	return r, true
}
func rectDistance(r TextRect, x, y int32) int64 {
	// Manhattan distance avoids overflow at opposite int32 screen extremes.
	dx, dy := int64(0), int64(0)
	if x < r.Left {
		dx = int64(r.Left) - int64(x)
	} else if x > r.Right {
		dx = int64(x) - int64(r.Right)
	}
	if y < r.Top {
		dy = int64(r.Top) - int64(y)
	} else if y > r.Bottom {
		dy = int64(y) - int64(r.Bottom)
	}
	return dx + dy
}
func (s *textState) point(x, y int32, flags uint32) (int32, bool) {
	if !s.laidOut || flags&^uint32(3) != 0 {
		return 0, false
	}
	inside := false
	for i, r := range s.layout.Units {
		if x >= r.Left && x < r.Right && y >= r.Top && y < r.Bottom {
			inside = true
			if flags&1 == 0 {
				return int32(i), true
			}
			// Only the two edges of this character are candidates when inside
			// its box. Another line's overlapping caret must not win the search.
			if rectDistance(s.layout.Carets[i+1], x, y) < rectDistance(s.layout.Carets[i], x, y) {
				return int32(i + 1), true
			}
			return int32(i), true
		}
	}
	if !inside && flags&2 == 0 {
		return 0, false
	}
	best, d := int32(0), int64(^uint64(0)>>1)
	for i, r := range s.layout.Carets {
		if v := rectDistance(r, x, y); v < d {
			best, d = int32(i), v
		}
	}
	return best, true
}
