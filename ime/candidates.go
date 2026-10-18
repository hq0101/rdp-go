package ime

import (
	"github.com/hq0101/rdp-go/rail"
	"unicode/utf16"
)

// CandidateList is a copied TSF UI element for this document. Replace the whole
// set on refresh; Kind identifies a UI type, not an element lifetime or action
// target. Token is for ApplyCandidate only and expires on the next refresh.
// Selection is -1 when the service reports no selection. PageStarts
// contains candidate indices, and CurrentPage indexes PageStarts (0 if empty).
// NativeShown reports the service's actual visibility when sampled.
type CandidateList struct {
	Token CandidateToken
	// SupportsBehavior reports optional select/finalize/abort support.
	SupportsBehavior bool
	Kind             rail.GUID
	NativeShown      bool
	Strings          []string
	Selection        int
	PageStarts       []uint32
	CurrentPage      uint32
}

const (
	maxCandidateElements = 32
	maxCandidateItems    = 4096
	maxCandidateString   = 1024  // UTF-16 units in one BSTR
	maxCandidateUnits    = 65536 // aggregate across one read
)

func candidateString(units []uint16) (string, error) {
	if len(units) > maxCandidateString {
		return "", rail.ErrInvalid
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xd800 && u <= 0xdbff {
			i++
			if i == len(units) || units[i] < 0xdc00 || units[i] > 0xdfff {
				return "", rail.ErrInvalid
			}
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", rail.ErrInvalid
		}
	}
	// BSTR is length-prefixed; embedded NUL is preserved, not used as a terminator.
	return string(utf16.Decode(units)), nil
}
func validCandidatePages(n int, selection int, pages []uint32, current uint32) bool {
	if n < 0 || n > maxCandidateItems || selection < -1 || selection >= n || len(pages) > n {
		return false
	}
	if n == 0 {
		return selection == -1 && len(pages) == 0 && current == 0
	}
	if len(pages) == 0 || pages[0] != 0 || uint64(current) >= uint64(len(pages)) {
		return false
	}
	for i, start := range pages {
		if uint64(start) >= uint64(n) || i > 0 && start <= pages[i-1] {
			return false
		}
	}
	return true
}
