package ime

import (
	"context"
	"errors"
	"unicode/utf16"

	"github.com/hq0101/rdp-go/rail"
)

// MaxCommitUnits matches the maximum UTF-16 input accepted by Session.SendText.
const MaxCommitUnits = 512

// ErrPendingCommit asks the caller to Flush before processing the next key.
// This rejection happens before TestKeyDown/Up and can be retried after Flush.
var ErrPendingCommit = errors.New("ime: pending text must be delivered before the next key")

// TextDelivery is bound to one connection and remote input target for its whole
// lifetime. Session.SendText can be passed directly. It runs synchronously on
// the UI goroutine for OpenTextInput, or on a worker when explicitly supplied to
// NewInputDispatcher. It never runs inside native callbacks. A failure can follow partial
// delivery; neither the callback nor the caller may replay uncertain input.
type TextDelivery func(context.Context, string) error

type WindowsInputOptions struct {
	// MaxUnits defaults to MaxCommitUnits and must be in [1, MaxCommitUnits].
	MaxUnits int
}

// TextFocus identifies one input ownership interval, independently of RAIL's
// language-state Token. Zero values and tokens from other inputs are invalid.
type TextFocus struct{ lease *textFocusLease }
type textFocusLease struct{ marker byte }

// WindowsKeyMessage contains the original queued keyboard message. Call Key
// before TranslateMessage/DispatchMessage and never again from the window
// procedure for the same message. Only WM_KEYDOWN/UP and WM_SYSKEYDOWN/UP apply.
type WindowsKeyMessage struct {
	HWND           uintptr
	Message        uint32
	WParam, LParam uintptr
}

func inputLimit(o WindowsInputOptions) (int, error) {
	if o.MaxUnits == 0 {
		o.MaxUnits = MaxCommitUnits
	}
	if o.MaxUnits < 1 || o.MaxUnits > MaxCommitUnits {
		return 0, rail.ErrInvalid
	}
	return o.MaxUnits, nil
}

// committedText is deliberately stricter than temporary ACP storage: no
// replacement of malformed surrogate pairs and no unsupported RDP controls.
func committedText(units []uint16) (string, error) {
	if len(units) > MaxCommitUnits {
		return "", rail.ErrInvalid
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u == 0 || (u < 32 && u != '\r' && u != '\n' && u != '\t') || u == 127 {
			return "", rail.ErrInvalid
		}
		if u >= 0xd800 && u <= 0xdbff {
			i++
			if i == len(units) || units[i] < 0xdc00 || units[i] > 0xdfff {
				return "", rail.ErrInvalid
			}
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", rail.ErrInvalid
		}
	}
	return string(utf16.Decode(units)), nil
}

func keySlots(m WindowsKeyMessage) (int, int, error) {
	if m.HWND == 0 || m.WParam == 0 || m.WParam > 255 {
		return 0, 0, rail.ErrInvalid
	}
	switch m.Message {
	case 0x100, 0x104:
		return 6, 8, nil
	case 0x101, 0x105:
		return 7, 9, nil
	default:
		return 0, 0, rail.ErrInvalid
	}
}
