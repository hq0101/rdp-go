package ime

import (
	"unicode/utf16"
	"unsafe"

	"github.com/hq0101/rdp-go/rail"
)

var translateKeyMessage = user32.NewProc("TranslateMessage")

// InsertText inserts validated UTF-8 character input at the transient document's
// current selection. Unlike SetText, it preserves live composition ranges by
// notifying TSF of the precise replacement. It performs no network I/O: Pump
// and Flush/QueueFlush deliver only the prefix actually committed by TSF.
//
// Use this for unhandled translated character messages, not for raw physical
// keys or a duplicate copy of TSF commits. Call on the UI thread outside native
// callbacks, after draining pending edits/delivery. Busy/PendingCommit with
// applied=false permits retry. applied=true means the document changed, even
// if a subsequent notification failed; never replay that insertion.
func (i *WindowsInput) InsertText(t TextFocus, text string) (applied bool, err error) {
	if !dispatchTextValid(text) {
		return false, rail.ErrInvalid
	}
	if err = i.enter(); err != nil {
		return false, err
	}
	defer i.leave()
	return i.insertText(text, func() error { return i.check(t) })
}

func (i *WindowsInput) insertText(text string, check func() error) (applied bool, err error) {
	if err = check(); err != nil {
		return false, err
	}
	if err = i.asyncReady(); err != nil {
		return false, err
	}
	if i.outbox != "" {
		return false, ErrPendingCommit
	}
	if err = i.document.pendingCommit(); err != nil {
		return false, err
	}
	s, err := i.document.snapshot()
	if err != nil {
		return false, err
	}
	if err = i.document.commitRevision(s.Revision); err != nil {
		return false, err
	}
	u := utf16.Encode([]rune(text))
	start, end := s.Selection.Start, s.Selection.End
	state := &i.document.store.state
	if !state.canReplace(start, end, uint32(len(u))) {
		return false, rail.ErrInvalid
	}
	// A host insertion cannot split an existing valid surrogate pair. Temporary
	// fragments already inside a TSF composition remain the provider's state.
	for _, at := range []int32{start, end} {
		if at > 0 && int(at) < len(s.Text) && s.Text[at-1] >= 0xd800 && s.Text[at-1] <= 0xdbff && s.Text[at] >= 0xdc00 && s.Text[at] <= 0xdfff {
			return false, rail.ErrInvalid
		}
	}
	if err = check(); err != nil {
		return false, err
	}
	if err = i.document.commitRevision(s.Revision); err != nil {
		return false, err
	}
	if !state.replace(start, end, u) {
		return false, rail.ErrBusy
	}
	change := nativeChange{start: start, oldEnd: end, newEnd: start + int32(len(u))}
	if err = i.document.store.notify(&change, true, true); err != nil {
		return true, i.stop(err)
	}
	if err = check(); err != nil {
		return true, err
	}
	return true, nil
}

// TranslatePacket translates one original, already-filtered unconsumed
// VK_PACKET down message. It posts WM_CHAR/WM_SYSCHAR through Windows rather
// than interpreting undocumented scan-code bits. The host must retain/order
// those resulting character messages ahead of later input and use InsertText.
// consumed keys and packet key-up messages must not be passed here.
//
// The captured keyboard state is restored around TranslateMessage. invoked
// reports the call, not whether Windows generated any character (the API's
// BOOL is not such a guarantee). Once invoked, never retry. Even on a later
// focus error, the host must retire any characters already posted by Windows.
// Do not remove another key message between retrieving m and this call:
// Windows retains Unicode packet metadata outside MSG/Keyboard, and later
// keyboard reads overwrite it. PeekMaintenanceMessage can service UI messages
// while preceding edits/delivery complete.
func (i *WindowsInput) TranslatePacket(t TextFocus, m WindowsMessage) (invoked bool, err error) {
	// VK_PACKET's high LPARAM word is opaque to us; do not apply ordinary
	// scancode/transition-bit validation to the Unicode packet representation.
	if !m.KeyboardValid || m.WParam != 0xe7 || (m.Message != 0x100 && m.Message != 0x104) || uint16(m.LParam) == 0 {
		return false, rail.ErrInvalid
	}
	if err = i.enter(); err != nil {
		return false, err
	}
	defer i.leave()
	if err = i.check(t); err != nil {
		return false, err
	}
	if m.HWND != i.adapter.wnd {
		return false, ErrStale
	}
	if err = i.asyncReady(); err != nil {
		return false, err
	}
	if i.outbox != "" {
		return false, ErrPendingCommit
	}
	if err = i.document.pendingCommit(); err != nil {
		return false, err
	}
	raw := nativeMessage{hwnd: m.HWND, message: m.Message, wparam: m.WParam, lparam: m.LParam, time: m.Time, x: m.X, y: m.Y, private: m.Private}
	_, err = withKeyboardState(&m.Keyboard, func() (bool, error) {
		invoked = true
		translateKeyMessage.Call(uintptr(unsafe.Pointer(&raw)))
		return false, i.check(t)
	})
	if err != nil {
		return invoked, i.stop(err)
	}
	return invoked, nil
}
