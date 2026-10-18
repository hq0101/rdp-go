package ime

import "github.com/hq0101/rdp-go/rail"

// committedPrefix stops at the earliest active composition, including an empty
// one. Gaps and suffixes stay buffered so delivery cannot reorder remote input.
// A known surrogate pair or CRLF must remain in one delivery: SendText folds
// CRLF per call, so splitting it would produce two remote Enter keystrokes.
func committedPrefix(s TextSnapshot) (int, error) {
	n := len(s.Text)
	if n > MaxCommitUnits {
		return 0, rail.ErrInvalid
	}
	for _, r := range s.Compositions {
		if r.Start < 0 || r.End < r.Start || int64(r.End) > int64(len(s.Text)) {
			return 0, ErrChanged
		}
		n = min(n, int(r.Start))
	}
	if n > 0 && n < len(s.Text) {
		before, after := s.Text[n-1], s.Text[n]
		if before >= 0xd800 && before <= 0xdbff && after >= 0xdc00 && after <= 0xdfff || before == '\r' && after == '\n' {
			n--
		}
	}
	return n, nil
}

// trimPrefix preserves selection orientation and interim status. The removed
// text belongs to a transient input document, never remote application text.
func (s *textState) trimPrefix(n int) bool {
	if n <= 0 || n > len(s.text) {
		return false
	}
	selection := s.selection
	if !s.replace(0, int32(n), nil) {
		return false
	}
	selection.Start = max(0, selection.Start-int32(n))
	selection.End = max(0, selection.End-int32(n))
	s.selection = selection
	return true
}
