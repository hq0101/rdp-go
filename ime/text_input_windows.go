package ime

import (
	"context"
	"errors"
	"unsafe"

	"github.com/hq0101/rdp-go/rail"
)

var iidKeystrokes = rail.GUID{Data1: 0xaa80e7f0, Data2: 0x2021, Data3: 0x11d2, Data4: [8]byte{0x93, 0xe0, 0, 0x60, 0xb0, 0x67, 0xb8, 0x6e}}

// WindowsInput owns a transient TSF document and its text delivery target.
// Native key filtering does not translate or forward unhandled physical keys;
// use keyboard.Router for raw key ownership and release on blur/failure.
// Focus, keys, Pump, Flush, layout and raw-key delivery must be UI-serialized.
// On a target change, Blur first and use an input bound to the new target.
type WindowsInput struct {
	adapter                     *WindowsAdapter
	document                    *WindowsDocument
	keys                        *comObject
	deliver                     TextDelivery
	lease                       *textFocusLease
	max                         int
	closed                      bool
	dispatcher                  *InputDispatcher
	dispatchFocus, retiredFocus DispatchFocus
	delivery, cleanup           *DeliveryReceipt
	outbox                      string
}

// OpenTextInput reserves the adapter's document slot. No HWND focus, layout,
// keyboard mode or native document is changed until Focus is called.
func (a *WindowsAdapter) OpenTextInput(o WindowsInputOptions, deliver TextDelivery) (*WindowsInput, error) {
	return a.openTextInput(o, deliver, nil)
}
func (a *WindowsAdapter) openTextInput(o WindowsInputOptions, deliver TextDelivery, dispatcher *InputDispatcher) (*WindowsInput, error) {
	limit, err := inputLimit(o)
	if err != nil {
		return nil, err
	}
	if (deliver == nil) == (dispatcher == nil) {
		return nil, rail.ErrInvalid
	}
	if err = a.enter(); err != nil {
		return nil, err
	}
	defer func() { a.busy = false }()
	if a.input != nil || a.document != nil {
		return nil, rail.ErrBusy
	}
	keys, err := queryCOM(a.manager, &iidKeystrokes)
	if err != nil {
		return nil, err
	}
	i := &WindowsInput{adapter: a, keys: keys, deliver: deliver, dispatcher: dispatcher, max: limit}
	a.input = i
	return i, nil
}
func (i *WindowsInput) enter() error {
	tid, _, _ := getThread.Call()
	if tid != i.adapter.thread {
		return ErrThread
	}
	if i.closed || i.adapter.closed {
		return rail.ErrClosed
	}
	err := i.adapter.enter()
	if errors.Is(err, ErrStale) {
		// enter already established thread and non-reentrancy before checking
		// the window marker. Retire a destroyed/reused HWND's native context.
		i.adapter.busy = true
		err = i.stop(err)
		i.adapter.busy = false
	}
	return err
}
func (i *WindowsInput) leave() { i.adapter.busy = false }
func (i *WindowsInput) valid(t TextFocus) bool {
	return t.lease != nil && t.lease == i.lease && i.document != nil
}
func (i *WindowsInput) focused() error {
	if err := i.adapter.focused(); err != nil {
		return err
	}
	own, err := i.document.ownsFocus()
	if err != nil {
		return err
	}
	if !own {
		return ErrNotFocused
	}
	return i.adapter.focused()
}
func (i *WindowsInput) discard() error {
	i.lease = nil
	d := i.document
	i.document = nil
	i.delivery, i.outbox = nil, ""
	var err error
	if d != nil {
		err = d.closeNative()
		if i.adapter.document == d {
			i.adapter.document = nil
		}
	}
	if i.dispatchFocus.lease != nil {
		i.retiredFocus, i.dispatchFocus = i.dispatchFocus, DispatchFocus{}
		receipt, cleanupErr := i.dispatcher.Blur(context.Background(), i.retiredFocus)
		i.cleanup = receipt
		err = errors.Join(err, cleanupErr)
	}
	return err
}
func (i *WindowsInput) stop(err error) error { return errors.Join(err, i.discard()) }
func (i *WindowsInput) check(t TextFocus) error {
	if !i.valid(t) {
		return ErrStale
	}
	if err := i.focused(); err != nil {
		return i.stop(err)
	}
	if i.document.store.closed.Load() {
		return i.stop(ErrUnavailable)
	}
	return nil
}

// Focus creates a new empty native context for a new input ownership interval.
// Blur the previous interval before refocusing, even when the HWND is unchanged.
func (i *WindowsInput) Focus() (TextFocus, error) {
	if err := i.enter(); err != nil {
		return TextFocus{}, err
	}
	defer i.leave()
	if i.lease != nil {
		return TextFocus{}, rail.ErrBusy
	}
	if i.cleanup != nil {
		result, ready := i.cleanup.Result()
		if !ready {
			return TextFocus{}, rail.ErrBusy
		}
		if result.Err != nil {
			return TextFocus{}, result.Err
		}
	}
	if err := i.adapter.focused(); err != nil {
		return TextFocus{}, err
	}
	d, err := i.adapter.openDocument(WindowsDocumentOptions{MaxUnits: i.max})
	if err != nil {
		return TextFocus{}, err
	}
	i.document = d
	if err = d.focus(); err != nil {
		return TextFocus{}, i.stop(err)
	}
	if i.dispatcher != nil {
		token, err := i.dispatcher.Focus()
		if err != nil {
			return TextFocus{}, i.stop(err)
		}
		i.dispatchFocus = token
	}
	i.cleanup, i.delivery, i.outbox, i.retiredFocus = nil, nil, "", DispatchFocus{}
	i.lease = &textFocusLease{}
	return TextFocus{lease: i.lease}, nil
}

// Key passes one queued key through TestKeyDown/Up and, only when accepted,
// KeyDown/Up. true means TSF handled it: do not TranslateMessage, DispatchMessage
// or directly forward it as raw RDP input. Still pass its consumed result to
// keyboard.Router so a previously remote-owned key gets its release.
// Native errors must not be retried/forwarded;
// ErrPendingCommit and rail.ErrBusy happen before dispatch and permit a retry
// after draining Pump/Flush at a safe loop point.
// Drain Pump and Flush before forwarding an unhandled key, since it may end a
// composition. DecodeWindowsKey and keyboard.Router handle physical identity
// and held-key pairing; do not route again if delivery becomes uncertain.
func (i *WindowsInput) Key(t TextFocus, m WindowsKeyMessage) (bool, error) {
	if _, _, err := keySlots(m); err != nil {
		return false, err
	}
	if err := i.enter(); err != nil {
		return false, err
	}
	defer i.leave()
	if err := i.check(t); err != nil {
		return false, err
	}
	if m.HWND != i.adapter.wnd {
		return false, ErrStale
	}
	if err := i.asyncReady(); err != nil {
		return false, err
	}
	if i.outbox != "" {
		return false, ErrPendingCommit
	}
	if i.document.store.pending != 0 {
		return false, rail.ErrBusy
	}
	if err := i.document.pendingCommit(); err != nil {
		return false, err
	}
	handled, err := filterKey(i.keys, m, func() error { return i.check(t) })
	if err != nil {
		return false, i.stop(err)
	}
	return handled, nil
}

func filterKey(keys *comObject, m WindowsKeyMessage, check func() error) (bool, error) {
	test, apply, err := keySlots(m)
	if err != nil {
		return false, err
	}
	if err = check(); err != nil {
		return false, err
	}
	var eaten int32
	hr := comCall(keys, test, m.WParam, m.LParam, uintptr(unsafe.Pointer(&eaten)))
	if int32(hr) < 0 {
		return false, hresult("TSF.TestKey", hr)
	}
	if err = check(); err != nil {
		return false, err
	}
	if hr != 0 || eaten == 0 {
		return false, nil
	}
	eaten = 0
	hr = comCall(keys, apply, m.WParam, m.LParam, uintptr(unsafe.Pointer(&eaten)))
	if int32(hr) < 0 {
		return false, hresult("TSF.Key", hr)
	}
	if err = check(); err != nil {
		return false, err
	}
	return hr == 0 && eaten != 0, nil
}

// Pump services one asynchronous native lock. Schedule another UI-loop turn
// while more is true; Snapshot, layout and Flush require an empty lock queue.
func (i *WindowsInput) Pump(t TextFocus) (bool, error) {
	if err := i.enter(); err != nil {
		return false, err
	}
	defer i.leave()
	if err := i.check(t); err != nil {
		return false, err
	}
	more, err := i.document.pump()
	if err != nil {
		return false, i.stop(err)
	}
	if err = i.check(t); err != nil {
		return false, err
	}
	return more, nil
}
func (i *WindowsInput) Snapshot(t TextFocus) (TextSnapshot, error) {
	if err := i.enter(); err != nil {
		return TextSnapshot{}, err
	}
	defer i.leave()
	if err := i.check(t); err != nil {
		return TextSnapshot{}, err
	}
	s, err := i.document.snapshot()
	if err != nil {
		return TextSnapshot{}, err
	}
	if err = i.check(t); err != nil {
		return TextSnapshot{}, err
	}
	return s, nil
}
func (i *WindowsInput) SetLayout(t TextFocus, revision uint64, layout TextLayout) error {
	if err := i.enter(); err != nil {
		return err
	}
	defer i.leave()
	if err := i.check(t); err != nil {
		return err
	}
	if err := i.document.setLayout(revision, layout); err != nil {
		return err
	}
	return i.check(t)
}

// Flush delivers the prefix before the earliest active composition after all
// locks have ended. It retains active text and following gaps/suffixes in order,
// and never splits a known surrogate pair or CRLF across deliveries. With no
// compositions it delivers the whole buffer. The owned transient store starts
// empty; it never represents remote application content. The committed prefix
// is removed and focus is rechecked before calling TextDelivery.
// invoked reports that delivery was attempted, even if it failed partway.
// Prefix validation, removal or delivery failures discard the focus interval.
// Snapshot read errors leave input intact. Never replay an uncertain delivery.
// Pre-canceled calls leave the buffer intact.
func (i *WindowsInput) Flush(ctx context.Context, t TextFocus) (invoked bool, err error) {
	if i.dispatcher != nil {
		return false, rail.ErrUnsupported
	}
	if ctx == nil {
		return false, rail.ErrInvalid
	}
	if err = i.enter(); err != nil {
		return false, err
	}
	defer i.leave()
	if err = i.check(t); err != nil {
		return false, err
	}
	return i.flush(ctx, func() error { return i.check(t) })
}
func (i *WindowsInput) flush(ctx context.Context, check func() error) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s, err := i.document.snapshot()
	if err != nil {
		return false, err
	}
	n, err := committedPrefix(s)
	if err != nil {
		return false, i.stop(err)
	}
	if n == 0 {
		return false, nil
	}
	text, err := committedText(s.Text[:n])
	if err != nil {
		return false, i.stop(err)
	}
	if err = i.document.trimCommitted(s, n); err != nil {
		return false, i.stop(err)
	}
	if err = check(); err != nil {
		return false, err
	}
	if err = ctx.Err(); err != nil {
		return false, i.stop(err)
	}
	err = i.deliver(ctx, text)
	if err != nil {
		return true, i.stop(err)
	}
	if err = check(); err != nil {
		return true, err
	}
	return true, nil
}

// Blur invalidates the token before native teardown; pending edits/preedit are
// discarded. The caller releases any raw RDP keys against the old target.
func (i *WindowsInput) Blur(t TextFocus) error {
	if err := i.enterCleanup(); err != nil {
		return err
	}
	defer i.leave()
	if !i.valid(t) {
		return ErrStale
	}
	return i.discard()
}
func (i *WindowsInput) enterCleanup() error {
	tid, _, _ := getThread.Call()
	if tid != i.adapter.thread {
		return ErrThread
	}
	if i.closed || i.adapter.closed {
		return rail.ErrClosed
	}
	if i.adapter.busy || i.adapter.documentBusy() {
		return rail.ErrBusy
	}
	i.adapter.busy = true
	return nil
}
func (i *WindowsInput) closeNative() error {
	if i.closed {
		return nil
	}
	i.closed = true
	err := i.discard()
	if i.keys != nil {
		comCall(i.keys, 2)
		i.keys = nil
	}
	i.deliver = nil
	return err
}
func (i *WindowsInput) Close() error {
	tid, _, _ := getThread.Call()
	if tid != i.adapter.thread {
		return ErrThread
	}
	if i.closed {
		return nil
	}
	if err := i.enterCleanup(); err != nil {
		return err
	}
	defer i.leave()
	err := i.closeNative()
	if i.adapter.input == i {
		i.adapter.input = nil
	}
	return err
}
