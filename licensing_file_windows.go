package rdp

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func fileLicenseSupported() bool { return true }
func fileLicenseOpenFlags() int  { return 0 }

var fileLicenseLockProc = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
var fileLicenseUnlockProc = syscall.NewLazyDLL("kernel32.dll").NewProc("UnlockFileEx")

func unlockFileLicense(f *os.File) error {
	var overlap syscall.Overlapped
	ok, _, _ := fileLicenseUnlockProc.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	runtime.KeepAlive(f)
	if ok != 0 {
		return nil
	}
	return ErrLicenseStoreIO
}
func lockFileLicense(f *os.File) error {
	var overlap syscall.Overlapped
	ok, _, e := fileLicenseLockProc.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	runtime.KeepAlive(f)
	if ok != 0 {
		return nil
	}
	if e == syscall.Errno(33) {
		return ErrLicenseStoreBusy
	}
	return ErrLicenseStoreIO
}

// Windows has no portable directory-fsync through os.Root. File data is synced
// before rename; do not claim POSIX rename/power-loss guarantees on this path.
func syncFileLicenseDirectory(*os.Root) error { return nil }
