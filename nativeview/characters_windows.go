package nativeview

import (
	"github.com/hq0101/rdp-go/ime"
)

const packetBeginMarker = 0x8051
const packetMarker = 0x8052

var postPacketMarker = user32.NewProc("PostMessageW")

type packetTranslation struct {
	sequence                uintptr
	characters              []characterMessage
	started, done, canceled bool
}

// The marker follows TranslateMessage's posted character messages. While it
// is pending, maintenance messages remain serviceable, while later keys stay
// in the native queue to preserve Windows' transient Unicode packet metadata.
// No scan-code bit guessing occurs.
func (w *desktopWindow) translatePacket(m ime.WindowsMessage) (packetCompletion, error) {
	if w.packet != nil || w.packetSequence == ^uintptr(0) {
		return nil, ErrInvalid
	}
	w.packetSequence++
	p := &packetTranslation{sequence: w.packetSequence}
	w.packet = p
	// Existing posted characters must remain independent queued input, not be
	// mistaken for this packet's output. Only collect between our two markers.
	if ok, _, postErr := postPacketMarker.Call(w.hwnd, packetBeginMarker, p.sequence, 0); ok == 0 {
		w.packet = nil
		return nil, nativeError("PostMessage packet start", postErr)
	}
	invoked, err := w.input.TranslatePacket(w.focus, m)
	if !invoked {
		w.packet = nil
		return nil, err
	}
	wait := func() ([]characterMessage, bool) { return p.characters, p.done }
	if err != nil {
		p.canceled = true
	}
	if ok, _, postErr := postPacketMarker.Call(w.hwnd, packetMarker, p.sequence, 0); ok == 0 {
		return wait, nativeError("PostMessage packet boundary", postErr)
	}
	return wait, err
}

// Called only for messages removed from the queue, not synchronous SendMessage
// calls. Synchronous character messages are ordinary independent host input.
func (w *desktopWindow) packetCharacter(m ime.WindowsMessage) bool {
	if w.packet == nil || !w.packet.started || (m.Message != 0x102 && m.Message != 0x106) {
		return false
	}
	if !w.packet.canceled {
		if len(w.packet.characters) >= 256 {
			w.err = errInputOverflow
			w.closing = true
			return true
		}
		if uint64(m.WParam) > 0xffff {
			w.packet.characters = append(w.packet.characters, characterMessage{value: 0x110000, repeat: 1})
			return true
		}
		w.packet.characters = append(w.packet.characters, characterMessage{value: uint32(m.WParam), repeat: uint16(m.LParam)})
	}
	return true
}

func (w *desktopWindow) character(message uint32, wp, lp uintptr) uintptr {
	if message == 0x109 && wp == 0xffff {
		return 1
	} // UNICODE_NOCHAR capability probe
	if w.loop == nil || w.closing || w.blurRequested {
		return 0
	}
	if uint64(wp) > 0x10ffff {
		w.blurRequested = true
		return 0
	}
	w.enqueue(inputItem{character: &characterMessage{value: uint32(wp), repeat: uint16(lp), scalar: message == 0x109}})
	return 0
}

var waitMaintenance = user32.NewProc("MsgWaitForMultipleObjectsEx")

// Preserve native packet state while the ordered input loop is busy.
// Character results, TSF helpers, timers, mouse and close remain live.
// Never use PM_NOREMOVE on a later key: even peeking can change packet state.
func (w *desktopWindow) nextMessage() (ime.WindowsMessage, bool, error) {
	if w.loop == nil || len(w.loop.queue) == 0 && w.loop.pending == nil {
		m, more, err := w.adapter.GetMessage()
		return m, more || err == nil && m.Message == 0x12, err
	}
	m, found, err := w.adapter.PeekMaintenanceMessage()
	if err != nil || found {
		return m, found, err
	}
	// Wake on non-key input, posted/sent messages, paint or timers. Excluding
	// QS_KEY avoids spinning on the deliberately retained keyboard messages.
	if result, _, err := waitMaintenance.Call(0, 0, 16, 0xfe, 4); uint32(result) == 0xffffffff {
		return ime.WindowsMessage{}, false, nativeError("MsgWaitForMultipleObjectsEx", err)
	}
	return ime.WindowsMessage{}, false, nil
}
