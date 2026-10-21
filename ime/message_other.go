//go:build !windows

package ime

import "github.com/hq0101/rdp-go/rail"

func (*WindowsAdapter) GetMessage() (WindowsMessage, bool, error) {
	return WindowsMessage{}, false, rail.ErrUnsupported
}
func (*WindowsAdapter) PeekMessage(bool) (WindowsMessage, bool, error) {
	return WindowsMessage{}, false, rail.ErrUnsupported
}
func (*WindowsInput) KeyWithKeyboardState(TextFocus, WindowsKeyMessage, WindowsKeyboardState) (bool, error) {
	return false, rail.ErrUnsupported
}
