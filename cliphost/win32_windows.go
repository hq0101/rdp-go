package cliphost

import (
	"fmt"
	"syscall"
)

var user = syscall.NewLazyDLL("user32.dll")
var kernel = syscall.NewLazyDLL("kernel32.dll")
var (
	registerClass   = user.NewProc("RegisterClassExW")
	createWindow    = user.NewProc("CreateWindowExW")
	destroyWindow   = user.NewProc("DestroyWindow")
	defWindow       = user.NewProc("DefWindowProcW")
	peekMessage     = user.NewProc("PeekMessageW")
	dispatchMessage = user.NewProc("DispatchMessageW")
	openClipboard   = user.NewProc("OpenClipboard")
	closeClipboard  = user.NewProc("CloseClipboard")
	emptyClipboard  = user.NewProc("EmptyClipboard")
	getData         = user.NewProc("GetClipboardData")
	setData         = user.NewProc("SetClipboardData")
	getOwner        = user.NewProc("GetClipboardOwner")
	getSequence     = user.NewProc("GetClipboardSequenceNumber")
	enumFormats     = user.NewProc("EnumClipboardFormats")
	formatName      = user.NewProc("GetClipboardFormatNameW")
	registerFormat  = user.NewProc("RegisterClipboardFormatW")
	formatAvailable = user.NewProc("IsClipboardFormatAvailable")
	addListener     = user.NewProc("AddClipboardFormatListener")
	removeListener  = user.NewProc("RemoveClipboardFormatListener")
	getDesktop      = user.NewProc("GetThreadDesktop")
	setDesktop      = user.NewProc("SetThreadDesktop")
	threadID        = kernel.NewProc("GetCurrentThreadId")
	module          = kernel.NewProc("GetModuleHandleW")
	alloc           = kernel.NewProc("GlobalAlloc")
	free            = kernel.NewProc("GlobalFree")
	lock            = kernel.NewProc("GlobalLock")
	unlock          = kernel.NewProc("GlobalUnlock")
	size            = kernel.NewProc("GlobalSize")
	copyMemory      = kernel.NewProc("RtlMoveMemory")
	multiByteToWide = kernel.NewProc("MultiByteToWideChar")
)

type winClass struct {
	Size, Style                                               uint32
	Proc                                                      uintptr
	ClassExtra, WindowExtra                                   int32
	Instance, Icon, Cursor, Background, Menu, Name, SmallIcon uintptr
}
type winMessage struct {
	HWND           uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	X, Y           int32
	Private        uint32
}

func winerr(name string, err error) error {
	if err == nil || err == syscall.Errno(0) {
		return fmt.Errorf("cliphost: %s failed", name)
	}
	return fmt.Errorf("cliphost: %s: %w", name, err)
}
