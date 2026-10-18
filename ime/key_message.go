package ime

import (
	"github.com/hq0101/rdp-go/keyboard"
	"github.com/hq0101/rdp-go/rail"
)

// DecodeWindowsKey extracts physical input from an original queued Windows
// key message, without translating layouts, characters or IME output. It is
// platform-independent and does not call TestKey/Key or change focus. HWND must
// still be checked against the active native input by the caller/WindowsInput.
// VK_PACKET belongs to the Unicode/IME path and returns rail.ErrUnsupported.
// Reserved bits and upper uintptr bits (possibly sign extension) are ignored.
func DecodeWindowsKey(m WindowsKeyMessage) (keyboard.Input, error) {
	if _, _, err := keySlots(m); err != nil {
		return keyboard.Input{}, err
	}
	if m.WParam == 0xe7 {
		return keyboard.Input{}, rail.ErrUnsupported
	}
	l := uint32(m.LParam)
	down := m.Message == 0x100 || m.Message == 0x104
	in := keyboard.Input{Down: down, WasDown: l&(1<<30) != 0, Count: uint16(l)}
	if down == (l&(1<<31) != 0) || in.Count == 0 || !down && (in.Count != 1 || !in.WasDown) {
		return keyboard.Input{}, rail.ErrInvalid
	}
	if m.WParam == 0x13 { // VK_PAUSE is a pulse; its E1 prefix isn't in bit 24.
		in.Key.Pause = true
	} else {
		in.Key.ScanCode = uint8(l >> 16)
		in.Key.Extended = l&(1<<24) != 0
		if in.Key.ScanCode == 0 || in.Key.ScanCode > 0x7f {
			return keyboard.Input{}, rail.ErrInvalid
		}
	}
	return in, nil
}
