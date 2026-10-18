package rdpdr

import (
	"runtime"
	"syscall"
	"unsafe"
)

var directoryLockFile = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
var directoryUnlockFile = syscall.NewLazyDLL("kernel32.dll").NewProc("UnlockFileEx")

func directoryLockAvailable() bool { return true }

func directoryLockNative(f *directoryFile, r LockRegion, exclusive bool) uint32 {
	flags := uintptr(1) // Always fail immediately; Dispatch/Poll owns waiting.
	if exclusive {
		flags |= 2
	}
	ov := syscall.Overlapped{Offset: uint32(r.Offset), OffsetHigh: uint32(r.Offset >> 32)}
	h := f.ioFile()
	ok, _, err := directoryLockFile.Call(h.Fd(), flags, 0, uintptr(uint32(r.Length)), uintptr(uint32(r.Length>>32)), uintptr(unsafe.Pointer(&ov)))
	runtime.KeepAlive(h)
	if ok != 0 {
		return 0
	}
	if err == syscall.Errno(33) {
		return StatusLockNotGranted
	}
	return directoryStatus(err)
}

func directoryUnlockNative(f *directoryFile, r LockRegion) uint32 {
	ov := syscall.Overlapped{Offset: uint32(r.Offset), OffsetHigh: uint32(r.Offset >> 32)}
	h := f.ioFile()
	ok, _, err := directoryUnlockFile.Call(h.Fd(), 0, uintptr(uint32(r.Length)), uintptr(uint32(r.Length>>32)), uintptr(unsafe.Pointer(&ov)))
	runtime.KeepAlive(h)
	if ok != 0 {
		return 0
	}
	if err == syscall.Errno(158) {
		return StatusRangeNotLocked
	}
	return directoryStatus(err)
}
