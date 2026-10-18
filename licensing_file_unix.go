//go:build linux || darwin

package rdp

import (
	"errors"
	"os"
	"runtime"
	"syscall"
)

func fileLicenseSupported() bool { return true }
func fileLicenseOpenFlags() int  { return syscall.O_NONBLOCK }
func unlockFileLicense(f *os.File) error {
	e := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	runtime.KeepAlive(f)
	return e
}
func lockFileLicense(f *os.File) error {
	e := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	runtime.KeepAlive(f)
	if e == nil {
		return nil
	}
	if errors.Is(e, syscall.EWOULDBLOCK) || errors.Is(e, syscall.EAGAIN) {
		return ErrLicenseStoreBusy
	}
	return ErrLicenseStoreIO
}
func syncFileLicenseDirectory(r *os.Root) error {
	f, e := r.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
