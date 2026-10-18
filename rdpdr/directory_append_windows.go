package rdpdr

import (
	"os"
	"runtime"
	"syscall"
)

// DirectoryDrive opens synchronous I/O handles. WriteFile with a non-nil
// OVERLAPPED therefore completes before returning. The all-ones offset selects
// EOF within the kernel write on the existing identity handle; no path reopen,
// stat/seek race, or change to the handle's granted access is needed.
func directoryAppend(f *os.File, data []byte) (int, error) {
	o := syscall.Overlapped{Offset: ^uint32(0), OffsetHigh: ^uint32(0)}
	var n uint32
	err := syscall.WriteFile(syscall.Handle(f.Fd()), data, &n, &o)
	runtime.KeepAlive(f)
	return int(n), err
}
