package nativeview

import (
	"errors"
	"unsafe"

	"github.com/hq0101/rdp-go/ime"
)

// Check live input at the UI-thread barrier as well as when offering a target.
// A composition may have begun since the last painted presentation; automatic
// resizing must wait instead of canceling newly typed text during retirement.
func (w *desktopWindow) displaySuspended() (bool, error) {
	if w.sizing || w.minimized || w.packet != nil || w.pressed[0] || w.pressed[1] || w.pressed[2] {
		return true, nil
	}
	if w.loop == nil {
		return false, nil
	}
	if w.loop.pending != nil || len(w.loop.queue) != 0 {
		return true, nil
	}
	snapshot, err := w.input.Snapshot(w.focus)
	if busy(err) || errors.Is(err, ime.ErrNotFocused) || errors.Is(err, ime.ErrStale) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	// Confirmed text also remains in the transient document until QueueFlush
	// delivers it. Retiring between commit and flush would silently lose it.
	if len(snapshot.Text) != 0 || len(snapshot.Compositions) != 0 {
		return true, nil
	}
	var state ime.WindowsKeyboardState
	if ok, _, err := getKeyboardState.Call(uintptr(unsafe.Pointer(&state[0]))); ok == 0 {
		return false, nativeError("GetKeyboardState", err)
	}
	for _, key := range state[8:] {
		if key&0x80 != 0 {
			return true, nil
		}
	}
	return false, nil
}
