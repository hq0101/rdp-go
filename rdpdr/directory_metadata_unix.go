//go:build linux || darwin

package rdpdr

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"syscall"
)

func directoryBasicHandle(_ *directoryFile, info fs.FileInfo) (BasicInformation, uint32) {
	// execute obtains a fresh Stat from the already-open descriptor.
	return directoryBasicInfo(info), 0
}

func directoryUnixStorage(info fs.FileInfo) (int64, uint32, uint32) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, StatusNotSupported
	}
	if st.Blocks < 0 || st.Blocks > math.MaxInt64/512 || uint64(st.Nlink) > math.MaxUint32 {
		return 0, 0, StatusInvalidParameter
	}
	// st_blocks is measured in 512-byte units, not st_blksize units. Sparse
	// files may have an allocation smaller than EOF; never round EOF here.
	return st.Blocks * 512, uint32(st.Nlink), 0
}

func directoryAllocation(info fs.FileInfo) int64 {
	allocation, _, _ := directoryUnixStorage(info)
	return allocation // zero denotes unavailable in a directory snapshot
}

func directoryStandard(_ *directoryFile, info fs.FileInfo) (StandardInformation, uint32) {
	allocation, links, status := directoryUnixStorage(info)
	return StandardInformation{EndOfFile: directorySize(info), AllocationSize: allocation, Links: links, Directory: info.IsDir()}, status
}

func directorySetMetadata(f *directoryFile, set SetInformation) uint32 {
	if set.Class != FileBasicInformation {
		return StatusNotSupported
	}
	if set.Basic == nil {
		return StatusInvalidParameter
	}
	plan, status := directoryPlanTimes(*set.Basic, directorySupportedTimes())
	if status != 0 {
		return status
	}
	if plan == [4]directoryUnixTime{} {
		return 0 // A no-op must not refresh the inode change time.
	}
	return directoryUnixMetadataStatus(directorySetTimes(f.ioFile(), plan))
}

func directoryUnixMetadataStatus(err error) uint32 {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, fs.ErrClosed), errors.Is(err, syscall.EBADF):
		return statusInvalidHandle
	case errors.Is(err, syscall.ENOSYS), errors.Is(err, syscall.ENOTSUP):
		return StatusNotSupported
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.EOVERFLOW):
		return StatusInvalidParameter
	default:
		return directoryStatus(err)
	}
}

// Control pins the descriptor against concurrent Close/reuse while the OS
// performs the operation. No path lookup or /proc/self/fd dependency is used.
func directoryWithFD(f *os.File, call func(uintptr) error) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var callErr error
	if err := raw.Control(func(fd uintptr) { callErr = call(fd) }); err != nil {
		return err
	}
	return callErr
}
