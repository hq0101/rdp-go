package ime

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/hq0101/rdp-go/rail"
)

var iidMessagePump = rail.GUID{Data1: 0x8f1b8ad8, Data2: 0x0b6b, Data3: 0x4874, Data4: [8]byte{0x90, 0xc5, 0xbd, 0x76, 0x01, 0x1e, 0x8f, 0x7c}}

type nativeMessage struct {
	hwnd           uintptr
	message        uint32
	wparam, lparam uintptr
	time           uint32
	x, y           int32
	private        uint32
}

// GetMessage waits for one message from ANY window on the adapter's UI thread,
// including TSF windows and thread messages. It uses ITfMessagePump.GetMessageW,
// not raw GetMessageW. The bool is false for WM_QUIT (whose exit code remains
// in WParam); all failures return a zero message. No key filtering, translation
// or dispatch occurs here. Native sent messages may run while it waits, so
// window procedures must defer adapter/input work until the call returns.
//
// This call cannot be canceled with context. A host must arrange a native wake
// message/timer, or use PeekMessage with its own wait loop. Close the adapter
// before destroying its bound window, and never call this from a callback.
func (a *WindowsAdapter) GetMessage() (WindowsMessage, bool, error) {
	return a.message(false, true)
}

// PeekMessage uses ITfMessagePump.PeekMessageW without waiting. remove selects
// PM_REMOVE; false leaves the message queued and supplies no keyboard snapshot.
// Unlike GetMessage, the bool reports presence, INCLUDING WM_QUIT. Callers must
// inspect Message == 0x12 and exit; never dispatch WM_QUIT. No HWND/range filter
// is installed, so TSF helper-window and thread messages remain serviceable.
func (a *WindowsAdapter) PeekMessage(remove bool) (WindowsMessage, bool, error) {
	return a.message(true, remove)
}

func (a *WindowsAdapter) message(peek, remove bool) (WindowsMessage, bool, error) {
	if a == nil {
		return WindowsMessage{}, false, rail.ErrInvalid
	}
	if err := a.enter(); err != nil {
		return WindowsMessage{}, false, err
	}
	defer func() { a.busy = false }()
	pump, err := queryCOM(a.manager, &iidMessagePump)
	if err != nil {
		return WindowsMessage{}, false, err
	}
	m, ok, err := readWindowsMessage(pump, peek, remove)
	// Release can reenter host code too. Keep the guard through Release and
	// recheck window identity afterwards; no message from a retired host escapes.
	comCall(pump, 2)
	if err != nil {
		return WindowsMessage{}, false, err
	}
	if err = a.window(); err != nil {
		return WindowsMessage{}, false, err
	}
	return m, ok, nil
}

func readWindowsMessage(pump *comObject, peek, remove bool) (WindowsMessage, bool, error) {
	var raw nativeMessage
	var result int32
	var hr uintptr
	if peek {
		var flags uintptr
		if remove {
			flags = 1
		}
		hr = comCall(pump, 5, uintptr(unsafe.Pointer(&raw)), 0, 0, 0, flags, uintptr(unsafe.Pointer(&result)))
	} else {
		hr = comCall(pump, 6, uintptr(unsafe.Pointer(&raw)), 0, 0, 0, uintptr(unsafe.Pointer(&result)))
	}
	if hr != 0 {
		return WindowsMessage{}, false, hresult("ITfMessagePump", hr)
	}
	if peek && result == 0 {
		return WindowsMessage{}, false, nil
	}
	if !peek && (result < 0 || (result == 0) != (raw.message == 0x12)) {
		return WindowsMessage{}, false, fmt.Errorf("ime: GetMessage result %d: %w", result, ErrUnavailable)
	}
	m := WindowsMessage{HWND: raw.hwnd, Message: raw.message, WParam: raw.wparam, LParam: raw.lparam, Time: raw.time, X: raw.x, Y: raw.y, Private: raw.private}
	if _, key := m.KeyMessage(); key && (!peek || remove) {
		// Read immediately after dequeue, before another message can advance the
		// UI thread's modifier state. No OS keyboard setting is changed here.
		if err := readKeyboardState(&m.Keyboard); err != nil {
			return WindowsMessage{}, false, err
		}
		m.KeyboardValid = true
	}
	return m, peek || result != 0, nil
}

func readKeyboardState(state *WindowsKeyboardState) error {
	if ok, _, err := getKeys.Call(uintptr(unsafe.Pointer(&state[0]))); ok == 0 {
		return fmt.Errorf("ime: GetKeyboardState: %w", err)
	}
	return nil
}
func writeKeyboardState(state *WindowsKeyboardState) error {
	if ok, _, err := setKeys.Call(uintptr(unsafe.Pointer(&state[0]))); ok == 0 {
		return fmt.Errorf("ime: SetKeyboardState: %w", err)
	}
	return nil
}

// withKeyboardState preserves the UI thread's CURRENT state around filtering
// one older message. It never changes another thread, an input locale or LEDs.
// The caller holds the native UI guard; the callback must not pump the queue.
func withKeyboardState(state *WindowsKeyboardState, run func() (bool, error)) (handled bool, err error) {
	var previous WindowsKeyboardState
	if err = readKeyboardState(&previous); err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, writeKeyboardState(&previous)) }()
	if err = writeKeyboardState(state); err != nil {
		return false, err
	}
	return run()
}

// KeyWithKeyboardState filters a queued key using its dequeue-time Keyboard
// snapshot. Use it ONLY when WindowsMessage.KeyboardValid is true and with that
// same message's KeyMessage. This matters when async delivery backpressure lets
// the UI remove later keys before filtering this one. The current UI-thread
// keyboard state is restored on success and failure. All Key focus, exactly-once
// filtering, Pump/QueueFlush-before-QueueKey and retry rules still apply. An
// error other than Busy/PendingCommit is terminal; do not replay the key.
func (i *WindowsInput) KeyWithKeyboardState(t TextFocus, m WindowsKeyMessage, state WindowsKeyboardState) (bool, error) {
	return i.key(t, m, &state)
}
