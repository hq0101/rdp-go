package rdpdr

import (
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

func directoryMetadataAvailable() bool { return true }
func directorySupportedTimes() uint32 {
	return directoryTimeCreate | directoryTimeAccess | directoryTimeWrite
}

func directoryBasicInfo(info fs.FileInfo) BasicInformation {
	b := directoryFallbackBasic(info)
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		b.CreationTime = directoryTime(time.Unix(st.Birthtimespec.Sec, st.Birthtimespec.Nsec))
		b.LastAccessTime = directoryTime(time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec))
		b.LastWriteTime = directoryTime(time.Unix(st.Mtimespec.Sec, st.Mtimespec.Nsec))
		b.ChangeTime = directoryTime(time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec))
	}
	return b
}

func directorySetTimes(f *os.File, plan [4]directoryUnixTime) error {
	attrs, times := directoryDarwinTimeAttributes(plan)
	if len(times) == 0 {
		return nil
	}
	err := directoryWithFD(f, func(fd uintptr) error {
		_, _, errno := syscall.Syscall6(syscall.SYS_FSETATTRLIST, fd, uintptr(unsafe.Pointer(&attrs[0])), uintptr(unsafe.Pointer(&times[0])), uintptr(len(times)), 0, 0)
		if errno != 0 {
			return errno
		}
		return nil
	})
	runtime.KeepAlive(attrs)
	runtime.KeepAlive(times)
	return err
}
