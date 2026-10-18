package ime

import "sync"

// TextChanges coalesces local presentation invalidations. These are hints to
// resample at a safe UI-loop point, not edits, commits, or a focus token. Native
// edit completion may conservatively set several bits even for a no-op edit.
// Candidate hints may concern another document on the same UI thread; only
// Candidates data is filtered by document ownership.
type TextChanges uint32

const (
	TextContentChanged TextChanges = 1 << iota
	TextSelectionChanged
	TextCompositionChanged
	TextDisplayChanged
	TextLayoutChanged
	TextCandidatesChanged
	TextAllChanged = TextContentChanged | TextSelectionChanged | TextCompositionChanged | TextDisplayChanged | TextLayoutChanged | TextCandidatesChanged
)

// Independent from TextSnapshot.Revision: property-only edits and UI elements
// need to invalidate reads too. No native or application calls under this lock.
type textChangeState struct {
	sync.Mutex
	bits   TextChanges
	serial uint64
	closed bool
}

func (s *textChangeState) mark(v TextChanges) {
	s.Lock()
	defer s.Unlock()
	if s.closed || v == 0 {
		return
	}
	if s.serial == ^uint64(0) {
		s.closed = true
		s.bits = 0
		return
	}
	s.serial++
	s.bits |= v
}
func (s *textChangeState) take() (TextChanges, error) {
	s.Lock()
	defer s.Unlock()
	if s.closed {
		return 0, ErrUnavailable
	}
	v := s.bits
	s.bits = 0
	return v, nil
}
func (s *textChangeState) version() (uint64, error) {
	s.Lock()
	defer s.Unlock()
	if s.closed {
		return 0, ErrUnavailable
	}
	return s.serial, nil
}
func (s *textChangeState) check(v uint64) error {
	n, err := s.version()
	if err != nil {
		return err
	}
	if n != v {
		return ErrChanged
	}
	return nil
}
func (s *textChangeState) close() {
	s.Lock()
	s.closed = true
	s.bits = 0
	s.Unlock()
}
