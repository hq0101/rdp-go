package nativeview

import "github.com/hq0101/rdp-go/ime"

// Only the Break/Pause edge belongs to the local shortcut. Modifier edges still
// go through the ordinary input queue, including their releases. No global
// keyboard hook or asynchronous key-state sampling is used.
type fullscreenShortcut struct{ held [2]bool }

func (s *fullscreenShortcut) key(m ime.WindowsKeyMessage, state ime.WindowsKeyboardState) (consume, toggle bool) {
	index := 0
	switch m.WParam {
	case 0x03: // Ctrl+Pause is reported as VK_CANCEL (Break).
	case 0x13:
		index = 1
	default:
		return false, false
	}
	in, err := ime.DecodeWindowsKey(m)
	if err != nil {
		return false, false
	}
	if !in.Down {
		consume, s.held[index] = s.held[index], false
		return consume, false
	}
	if in.WasDown {
		return s.held[index], false
	}
	ctrl := state[0x11]&0x80 != 0 || state[0xa2]&0x80 != 0 || state[0xa3]&0x80 != 0
	alt := state[0x12]&0x80 != 0 || state[0xa4]&0x80 != 0 || state[0xa5]&0x80 != 0
	// Pause can arrive without a matching release. A new first-down is still a
	// new shortcut; a later unmodified Pause must never inherit an old latch.
	s.held[index] = ctrl && alt
	return s.held[index], s.held[index]
}
