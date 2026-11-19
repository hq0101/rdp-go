//go:build windows && (amd64 || arm64)

package clipole

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	clipboardOwner    = user.NewProc("GetClipboardOwner")
	clipboardSequence = user.NewProc("GetClipboardSequenceNumber")
	windowStation     = user.NewProc("GetProcessWindowStation")
	openClipboard     = user.NewProc("OpenClipboard")
	closeClipboard    = user.NewProc("CloseClipboard")
)

// Observe captures metadata under the native clipboard lock. It neither reads
// content nor takes ownership. Do not call while already holding the clipboard.
// Keep the process window station alive and unchanged while using the snapshot.
func Observe() (Snapshot, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	wnd, err := clipboardWindow()
	if err != nil {
		return Snapshot{}, err
	}
	defer user.NewProc("DestroyWindow").Call(wnd)
	if ok, _, _ := openClipboard.Call(wnd); ok == 0 {
		return Snapshot{}, ErrBusy
	}
	s := stamp()
	if ok, _, e := closeClipboard.Call(); ok == 0 {
		return Snapshot{}, fmt.Errorf("clipole: CloseClipboard observation: %w", e)
	}
	return s, nil
}

// Use a distinct window instead of NULL. Windows can treat another open with
// the same HWND (including NULL) as a reopen even on a different thread.
func clipboardWindow() (uintptr, error) {
	class, _ := syscall.UTF16FromString("STATIC")
	hwnd, _, e := user.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(&class[0])), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	if hwnd == 0 {
		return 0, fmt.Errorf("clipole: CreateWindowEx clipboard guard: %w", e)
	}
	return hwnd, nil
}

func stamp() Snapshot {
	o, _, _ := clipboardOwner.Call()
	seq, _, _ := clipboardSequence.Call()
	station, _, _ := windowStation.Call()
	return Snapshot{owner: o, sequence: uint32(seq), station: station, valid: station != 0}
}

// OwnsCurrent recognizes our OLE window without requiring a cross-apartment COM
// call. Materializing a format can change the sequence without changing owner.
// This is an observation, not permission to mutate the clipboard.
func (s *Offer) OwnsCurrent() bool {
	if s.ctx.Err() != nil {
		return false
	}
	s.mu.Lock()
	own := s.ownership
	s.mu.Unlock()
	now := stamp()
	return own.valid && own.owner != 0 && own.owner == now.owner && own.station == now.station
}

func (n *nativeOffer) checkExpected() error {
	if err := n.s.ctx.Err(); err != nil {
		return err
	}
	if n.s.expected != nil && *n.s.expected != stamp() {
		return ErrChanged
	}
	return nil
}

func (n *nativeOffer) captureOwner() error {
	wnd, err := clipboardWindow()
	if err != nil {
		return err
	}
	defer user.NewProc("DestroyWindow").Call(wnd)
	if ok, _, _ := openClipboard.Call(wnd); ok == 0 {
		return ErrBusy
	}
	defer closeClipboard.Call()
	hr, _, _ := isCurrent.Call(n.data)
	if hr != 0 {
		return ErrChanged
	}
	n.s.mu.Lock()
	n.s.ownership = stamp()
	n.s.mu.Unlock()
	return nil
}

func (n *nativeOffer) publish() error {
	if n.s.expected == nil {
		hr, _, _ := setClipboard.Call(n.data)
		n.installed = true
		if failed(hr) {
			return hresult("OleSetClipboard", hr)
		}
		return n.captureOwner()
	}
	// OLE opens the clipboard using its own private window. Holding it open for
	// a different window prevents OLE from opening it, before EmptyClipboard.
	// An unsuccessful attempt also initializes OLE's thread-owned window. Then
	// try this STA's windows under the same native lock. No private class names,
	// OLE memory layouts, injection, or cross-thread window access are used.
	// Every attempt checks the expected stamp after OpenClipboard, before OLE.
	wnd, err := clipboardWindow()
	if err != nil {
		return err
	}
	defer user.NewProc("DestroyWindow").Call(wnd)
	ok, err := n.tryPublish(wnd)
	if ok || err != nil {
		return err
	}
	tid, _, _ := threadID.Call()
	seen := make(map[uintptr]bool)
	for _, parent := range []uintptr{0, ^uintptr(2)} { // desktop and HWND_MESSAGE
		var after uintptr
		for range 4096 {
			hwnd, _, _ := user.NewProc("FindWindowExW").Call(parent, after, 0, 0)
			if hwnd == 0 {
				break
			}
			after = hwnd
			if seen[hwnd] {
				continue
			}
			seen[hwnd] = true
			ownerThread, _, _ := user.NewProc("GetWindowThreadProcessId").Call(hwnd, 0)
			if ownerThread != tid {
				continue
			}
			ok, err = n.tryPublish(hwnd)
			if ok || err != nil {
				return err
			}
		}
	}
	return ErrUnsupported // preserve the clipboard if a suitable window is absent
}

func (n *nativeOffer) tryPublish(hwnd uintptr) (bool, error) {
	if ok, _, _ := openClipboard.Call(hwnd); ok == 0 {
		return false, ErrBusy
	}
	if err := n.checkExpected(); err != nil {
		closeClipboard.Call()
		return false, err
	}
	before := stamp()
	hr, _, _ := setClipboard.Call(n.data)
	if hr == 0 {
		n.installed = true
		// OleSetClipboard closed its successful nested OpenClipboard. A second
		// Close reports ERROR_CLIPBOARD_NOT_OPEN on Windows; do not treat it as
		// an installation failure, or claim the lock is still held afterwards.
		closeClipboard.Call()
		actualOwner, _, _ := clipboardOwner.Call()
		if hwnd != 0 && actualOwner == hwnd {
			n.s.mu.Lock()
			n.s.ownership = Snapshot{owner: hwnd, station: before.station, valid: true}
			n.s.mu.Unlock()
			return true, nil
		}
		return true, n.captureOwner()
	}
	after := stamp()
	closed, _, closeErr := closeClipboard.Call()
	if hr == 0x800401d0 && before == after && closed != 0 {
		return false, nil
	} // CLIPBRD_E_CANT_OPEN: no write
	// Other HRESULTs may follow partial installation. Cleanup is owner-checked.
	n.installed = true
	if closed == 0 {
		return false, fmt.Errorf("clipole: CloseClipboard publication: %w", closeErr)
	}
	return false, hresult("OleSetClipboard", hr)
}
