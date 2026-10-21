package nativeview

import (
	"fmt"
	"syscall"
	"unsafe"
)

var user32 = syscall.NewLazyDLL("user32.dll")
var gdi32 = syscall.NewLazyDLL("gdi32.dll")
var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var usp10 = syscall.NewLazyDLL("usp10.dll")
var (
	registerClass    = user32.NewProc("RegisterClassExW")
	createWindow     = user32.NewProc("CreateWindowExW")
	defWindow        = user32.NewProc("DefWindowProcW")
	destroyWindow    = user32.NewProc("DestroyWindow")
	showWindow       = user32.NewProc("ShowWindow")
	getMessage       = user32.NewProc("GetMessageW")
	translateMessage = user32.NewProc("TranslateMessage")
	dispatchMessage  = user32.NewProc("DispatchMessageW")
	setTimer         = user32.NewProc("SetTimer")
	killTimer        = user32.NewProc("KillTimer")
	getClientRect    = user32.NewProc("GetClientRect")
	clientToScreen   = user32.NewProc("ClientToScreen")
	screenToClient   = user32.NewProc("ScreenToClient")
	getForeground    = user32.NewProc("GetForegroundWindow")
	getFocus         = user32.NewProc("GetFocus")
	getKeyState      = user32.NewProc("GetKeyState")
	getKeyboardState = user32.NewProc("GetKeyboardState")
	setCapture       = user32.NewProc("SetCapture")
	releaseCapture   = user32.NewProc("ReleaseCapture")
	getCapture       = user32.NewProc("GetCapture")
	setCursor        = user32.NewProc("SetCursor")
	loadCursor       = user32.NewProc("LoadCursorW")
	getCursorPos     = user32.NewProc("GetCursorPos")
	setCursorPos     = user32.NewProc("SetCursorPos")
	setWindowPos     = user32.NewProc("SetWindowPos")
	setThreadDPI     = user32.NewProc("SetThreadDpiAwarenessContext")
	getWindowDPI     = user32.NewProc("GetDpiForWindow")
	invalidateRect   = user32.NewProc("InvalidateRect")
	updateWindow     = user32.NewProc("UpdateWindow")
	beginPaint       = user32.NewProc("BeginPaint")
	endPaint         = user32.NewProc("EndPaint")
	getDC            = user32.NewProc("GetDC")
	releaseDC        = user32.NewProc("ReleaseDC")
	fillRect         = user32.NewProc("FillRect")
	getSysColor      = user32.NewProc("GetSysColor")
	moduleHandle     = kernel32.NewProc("GetModuleHandleW")
	currentThread    = kernel32.NewProc("GetCurrentThreadId")
	copyNative       = kernel32.NewProc("RtlMoveMemory")
	createFont       = gdi32.NewProc("CreateFontW")
	selectObject     = gdi32.NewProc("SelectObject")
	deleteObject     = gdi32.NewProc("DeleteObject")
	createBrush      = gdi32.NewProc("CreateSolidBrush")
	createPen        = gdi32.NewProc("CreatePen")
	polyline         = gdi32.NewProc("Polyline")
	setTextColor     = gdi32.NewProc("SetTextColor")
	setBkMode        = gdi32.NewProc("SetBkMode")
	setTextAlign     = gdi32.NewProc("SetTextAlign")
	getTextExtent    = gdi32.NewProc("GetTextExtentPoint32W")
	saveDC           = gdi32.NewProc("SaveDC")
	restoreDC        = gdi32.NewProc("RestoreDC")
	intersectClip    = gdi32.NewProc("IntersectClipRect")
	stretchDIBits    = gdi32.NewProc("StretchDIBits")
	scriptAnalyse    = usp10.NewProc("ScriptStringAnalyse")
	scriptFree       = usp10.NewProc("ScriptStringFree")
	scriptSize       = usp10.NewProc("ScriptString_pSize")
	scriptCPtoX      = usp10.NewProc("ScriptStringCPtoX")
	scriptOut        = usp10.NewProc("ScriptStringOut")
)

type winPoint struct{ X, Y int32 }
type winRect struct{ Left, Top, Right, Bottom int32 }
type winSize struct{ CX, CY int32 }
type winMessage struct {
	HWND           uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Point          winPoint
	Private        uint32
}
type winClass struct {
	Size, Style                                               uint32
	Proc                                                      uintptr
	ClassExtra, WindowExtra                                   int32
	Instance, Icon, Cursor, Background, Menu, Name, SmallIcon uintptr
}
type winPaint struct {
	DC                   uintptr
	Erase                int32
	Rect                 winRect
	Restore, Incremental int32
	Reserved             [32]byte
}
type bitmapHeader struct {
	Size                   uint32
	Width, Height          int32
	Planes, Bits           uint16
	Compression, ImageSize uint32
	XPels, YPels           int32
	Used, Important        uint32
}

func wstr(s string) ([]uint16, error) { return syscall.UTF16FromString(s) }
func signed(v int32) uintptr          { return uintptr(int64(v)) }
func nativeError(name string, err error) error {
	if err == nil || err == syscall.Errno(0) {
		return fmt.Errorf("nativeview: %s failed", name)
	}
	return fmt.Errorf("nativeview: %s: %w", name, err)
}
func hrError(name string, hr uintptr) error {
	if uint32(hr) == 0 {
		return nil
	}
	return fmt.Errorf("nativeview: %s HRESULT 0x%08x", name, uint32(hr))
}
func brushRect(dc uintptr, r winRect, color uint32) error {
	brush, _, err := createBrush.Call(uintptr(color))
	if brush == 0 {
		return nativeError("CreateSolidBrush", err)
	}
	defer deleteObject.Call(brush)
	ok, _, err := fillRect.Call(dc, uintptr(unsafe.Pointer(&r)), brush)
	if ok == 0 {
		return nativeError("FillRect", err)
	}
	return nil
}
func rgb(color uint32) uint32 { return (color&255)<<16 | color&0xff00 | (color>>16)&255 }
