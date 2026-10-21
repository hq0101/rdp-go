package ime

// WindowsKeyboardState is a copy of the UI thread's 256 virtual-key states at
// message removal. It is not global keyboard state and does not control LEDs.
type WindowsKeyboardState [256]byte

// WindowsMessage is an owned MSG value returned by the TSF message pump.
// Pointer-valued WParam/LParam remain borrowed OS values: do not retain them
// beyond the native message's lifetime or dispatch a message more than once.
// This type is not a native MSG layout; use the individual fields in a host.
type WindowsMessage struct {
	HWND           uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	X, Y           int32
	Private        uint32
	// KeyboardValid is true only for a keyboard message removed from the queue.
	// A non-removing peek must never be filtered or forwarded as input.
	Keyboard      WindowsKeyboardState
	KeyboardValid bool
}

// KeyMessage returns the original four key-message fields. The bool describes
// the message kind, not whether TSF has consumed it or the window is focused.
func (m WindowsMessage) KeyMessage() (WindowsKeyMessage, bool) {
	switch m.Message {
	case 0x100, 0x101, 0x104, 0x105:
		return WindowsKeyMessage{HWND: m.HWND, Message: m.Message, WParam: m.WParam, LParam: m.LParam}, true
	default:
		return WindowsKeyMessage{}, false
	}
}
