package rdpdr

import (
	"math"
	"os"
	"syscall"
	"unsafe"
)

func directoryOpenFlags() int { return 0 }

var directoryFreeSpace = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

func directoryVolume(path string, _ *os.File) (int64, int64, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var available, total, free uint64
	ok, _, e := directoryFreeSpace.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&available)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&free)))
	if ok == 0 {
		return 0, 0, e
	}
	if total > math.MaxInt64 || available > math.MaxInt64 {
		return 0, 0, ErrLimit
	}
	return int64(total), int64(available), nil
}
