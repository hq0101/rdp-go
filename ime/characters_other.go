//go:build !windows

package ime

import "github.com/hq0101/rdp-go/rail"

func (*WindowsInput) InsertText(TextFocus, string) (bool, error) { return false, rail.ErrUnsupported }
func (*WindowsInput) TranslatePacket(TextFocus, WindowsMessage) (bool, error) {
	return false, rail.ErrUnsupported
}
