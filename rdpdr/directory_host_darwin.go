package rdpdr

import (
	"math"
	"os"
	"syscall"
)

func directoryOpenFlags() int { return syscall.O_NONBLOCK }
func directoryVolume(_ string, f *os.File) (int64, int64, error) {
	var st syscall.Statfs_t
	raw, err := f.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var statErr error
	err = raw.Control(func(fd uintptr) { statErr = syscall.Fstatfs(int(fd), &st) })
	if err != nil {
		return 0, 0, err
	}
	if statErr != nil {
		return 0, 0, statErr
	}
	unit := uint64(st.Bsize)
	if unit == 0 || uint64(st.Blocks) > math.MaxInt64/unit || uint64(st.Bavail) > math.MaxInt64/unit {
		return 0, 0, ErrLimit
	}
	return int64(uint64(st.Blocks) * unit), int64(uint64(st.Bavail) * unit), nil
}
