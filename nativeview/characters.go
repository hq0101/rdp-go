package nativeview

import (
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/hq0101/rdp-go/ime"
)

var errCharacterInput = errors.New("nativeview: invalid Unicode character input")

type characterMessage struct {
	value  uint32
	repeat uint16
	scalar bool // WM_UNICHAR is UTF-32; WM_CHAR is one UTF-16 code unit.
}
type characterState struct {
	high   uint16
	repeat uint16
}
type characterRun struct {
	value     rune
	remaining uint16
}
type packetCompletion func() ([]characterMessage, bool)

func (s *characterState) accept(m characterMessage) (characterRun, error) {
	count := m.repeat
	if count == 0 {
		count = 1
	} // directly posted character messages often use lParam=0
	r := rune(m.value)
	if m.scalar {
		if s.high != 0 || m.value > utf8.MaxRune || !utf8.ValidRune(r) {
			return characterRun{}, errCharacterInput
		}
	} else {
		if m.value > 0xffff {
			return characterRun{}, errCharacterInput
		}
		u := uint16(m.value)
		if s.high != 0 {
			if u < 0xdc00 || u > 0xdfff || count != s.repeat {
				return characterRun{}, errCharacterInput
			}
			r = utf16.DecodeRune(rune(s.high), rune(u))
			s.high, s.repeat = 0, 0
		} else if u >= 0xd800 && u <= 0xdbff {
			s.high, s.repeat = u, count
			return characterRun{}, nil
		} else if u >= 0xdc00 && u <= 0xdfff {
			return characterRun{}, errCharacterInput
		}
	}
	if r == 0 || r < 32 && r != '\t' && r != '\r' && r != '\n' || r == 127 {
		return characterRun{}, errCharacterInput
	}
	return characterRun{r, count}, nil
}
func (r characterRun) chunk() (string, uint16) {
	units := 1
	if r.value > 0xffff {
		units = 2
	}
	n := min(int(r.remaining), ime.MaxCommitUnits/units)
	return strings.Repeat(string(r.value), n), uint16(n)
}
