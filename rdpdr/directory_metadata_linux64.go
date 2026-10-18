//go:build linux && (amd64 || arm64)

package rdpdr

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func directoryMetadataAvailable() bool { return true }

func directorySetTimes(f *os.File, plan [4]directoryUnixTime) error {
	const utimeOmit = (1 << 30) - 2
	var times [2]syscall.Timespec
	for i, t := range plan[1:3] {
		times[i].Nsec = utimeOmit
		if t.set {
			times[i] = syscall.Timespec{Sec: t.seconds, Nsec: t.nanos}
		}
	}
	err := directoryWithFD(f, func(fd uintptr) error {
		// Linux accepts a NULL pathname with a real FD (the futimens kernel
		// operation). UTIME_OMIT preserves a concurrently changed other field.
		_, _, errno := syscall.Syscall6(syscall.SYS_UTIMENSAT, fd, 0, uintptr(unsafe.Pointer(&times[0])), 0, 0, 0)
		if errno != 0 {
			return errno
		}
		return nil
	})
	runtime.KeepAlive(times)
	return err
}
