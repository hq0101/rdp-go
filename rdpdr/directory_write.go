package rdpdr

import (
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"runtime"
	"syscall"
)

const (
	statusNameCollision uint32 = 0xc0000035
	statusDiskFull      uint32 = 0xc000007f
)

func directoryWriteAccess(q *CreateRequest) (uint32, uint32) {
	// Reuse the read-only validator for structural flags and synchronous I/O
	// requirements. Generic access is expanded before checking granted rights.
	probe := *q
	probe.Disposition = 1
	if directoryNamespaceAvailable() {
		probe.Options &^= 0x1000
	}
	probe.DesiredAccess = 0x1200a9
	if _, s := directoryReadAccess(&probe); s != 0 {
		if q.Options&0x1000 != 0 {
			return 0, StatusNotSupported
		}
		return 0, s
	}
	if q.Disposition > 5 {
		return 0, StatusInvalidParameter
	}
	if q.Disposition == 0 {
		return 0, StatusNotSupported
	} // supersede != truncate
	access := q.DesiredAccess
	for _, m := range [][2]uint32{{0x80000000, 0x120089}, {0x40000000, 0x120116}, {0x20000000, 0x1200a0}, {0x10000000, 0x1f01ff}, {0x02000000, 0x1201bf}} {
		if access&m[0] != 0 {
			access = access&^m[0] | m[1]
		}
	}
	allowed := uint32(0x1201bf)
	if directoryNamespaceAvailable() {
		allowed |= 0x10000
	}
	// DELETE_CHILD, WRITE_DAC and WRITE_OWNER are not granted yet.
	if access&^allowed != 0 {
		return 0, StatusAccessDenied
	}
	if q.Options&0x1000 != 0 && access&0x10000 == 0 {
		return 0, StatusInvalidParameter
	}
	if q.Options&0x30 != 0 && access&0x100000 == 0 {
		return 0, StatusInvalidParameter
	}
	if q.Disposition == 4 || q.Disposition == 5 {
		if q.Options&1 != 0 {
			return 0, StatusInvalidParameter
		}
		if access&2 == 0 {
			return 0, StatusAccessDenied
		}
		if s := directoryCreationPolicy(q); s != 0 {
			return 0, s
		}
	}
	return access, StatusSuccess
}

// Reject unsupported allocation/attributes BEFORE creating or truncating. A
// reservation is not a logical file length; never emulate it with Truncate.
func directoryCreationPolicy(q *CreateRequest) uint32 {
	if q.AllocationSize > math.MaxInt64 {
		return StatusInvalidParameter
	}
	attributes := uint32(0xa0)
	if directoryNamespaceAvailable() {
		attributes = 0x1a7 // READONLY/HIDDEN/SYSTEM/ARCHIVE/NORMAL/TEMPORARY
		if q.Options&1 != 0 {
			attributes |= 0x10
		}
		if q.Attributes&1 != 0 && q.Options&0x1000 != 0 {
			return StatusInvalidParameter
		}
	}
	if (!directoryNamespaceAvailable() && q.AllocationSize != 0) || q.Attributes&^attributes != 0 {
		return StatusNotSupported
	}
	if q.Options&1 != 0 && !directoryNamespaceAvailable() {
		return StatusNotSupported
	}
	return StatusSuccess
}

func directoryShareConflict(access, share, oldAccess, oldShare uint32) bool {
	// Metadata-only opens do not participate in data/delete share accounting.
	// FILE_READ_EA/WRITE_EA/READ_ATTRIBUTES/WRITE_ATTRIBUTES are not data I/O.
	const participating = 0x10000 | 0x21 | 6
	if access&participating == 0 || oldAccess&participating == 0 {
		return false
	}
	for _, pair := range [][2]uint32{{0x21, 1}, {6, 2}, {0x10000, 4}} {
		if access&pair[0] != 0 && oldShare&pair[1] == 0 || oldAccess&pair[0] != 0 && share&pair[1] == 0 {
			return true
		}
	}
	return false
}

// Existing files are always opened without truncation. Windows uses a pinned,
// no-reparse native walk so initial attributes/allocation are part of CREATE.
// Other platforms retain exclusive os.Root creation and bounded collision retry.
func (d *DirectoryDrive) openWritable(name string, q *CreateRequest, access uint32) (*os.File, bool, uint32, func() error) {
	if directoryNamespaceAvailable() {
		return d.openNativeWritable(name, q, access)
	}
	flags := os.O_RDONLY | directoryRequestedFlags(q.Options)
	if q.Options&1 == 0 && access&6 != 0 {
		flags = os.O_WRONLY | directoryRequestedFlags(q.Options)
		if access&1 != 0 {
			flags = os.O_RDWR | directoryRequestedFlags(q.Options)
		}
		if access&6 == 4 {
			flags |= os.O_APPEND
		}
	}
	create := func() (*os.File, bool, uint32) {
		if s := directoryCreationPolicy(q); s != 0 {
			return nil, false, s
		}
		f, err := d.root.OpenFile(name, flags|os.O_CREATE|os.O_EXCL, 0600)
		return f, err == nil, directoryStatus(err)
	}
	if q.Disposition == 2 {
		f, created, status := create()
		return f, created, status, nil
	}
	for attempt := 0; attempt < 4; attempt++ {
		f, err := d.root.OpenFile(name, flags, 0)
		if err == nil {
			return f, false, StatusSuccess, nil
		}
		if !errors.Is(err, fs.ErrNotExist) || q.Disposition == 1 || q.Disposition == 4 {
			return nil, false, directoryStatus(err), nil
		}
		f, created, status := create()
		if status != statusNameCollision {
			return f, created, status, nil
		}
	}
	return nil, false, statusSharingViolation, nil
}

func (d *DirectoryDrive) write(f *directoryFile, q *WriteRequest) (uint32, FileResult, error) {
	empty := FileResult{}
	if !d.opts.Writable {
		return statusWriteProtected, empty, nil
	}
	if f.access&6 == 0 {
		return StatusAccessDenied, empty, nil
	}
	if f.info.IsDir() {
		return statusFileIsDirectory, empty, nil
	}
	if len(q.Data) > MaxFileData || !q.Append && !f.appendOnly && (q.Offset > math.MaxInt64 || uint64(len(q.Data)) > math.MaxInt64-q.Offset) {
		return StatusInvalidParameter, empty, nil
	}
	if len(q.Data) == 0 {
		return StatusSuccess, empty, nil
	}
	var n int
	var err error
	if f.appendOnly {
		// O_APPEND or native FILE_APPEND_DATA chooses EOF with the write, even if
		// another local writer changes the file. The request offset is ignored.
		n, err = f.ioFile().Write(q.Data)
	} else if q.Append {
		n, err = directoryAppend(f.ioFile(), q.Data)
		if errors.Is(err, ErrUnsupported) && !errors.Is(err, errDirectoryAppendState) {
			return StatusNotSupported, empty, nil
		}
	} else {
		n, err = f.ioFile().WriteAt(q.Data, int64(q.Offset))
	}
	return directoryWriteResult(f, n, len(q.Data), err)
}

// An uncertain descriptor mode is fatal even when bytes were written. The
// caller must close the backend instead of allowing a later positional write
// to append unexpectedly or replaying the ambiguous operation.
func directoryWriteResult(f *directoryFile, n, requested int, err error) (uint32, FileResult, error) {
	if n < 0 || n > requested {
		return StatusUnsuccessful, FileResult{}, errors.Join(ErrProtocol, err)
	}
	result := FileResult{Written: uint32(n)}
	if errors.Is(err, errDirectoryAppendState) {
		return StatusUnsuccessful, result, err
	}
	if err == nil && n != requested {
		err = io.ErrShortWrite
	}
	if err == nil && f.writeThrough {
		err = f.ioFile().Sync()
	}
	return directoryStatus(err), result, nil
}

func (d *DirectoryDrive) setInformation(f *directoryFile, q *InformationRequest) (uint32, FileResult, error) {
	empty := FileResult{}
	if !d.opts.Writable {
		return statusWriteProtected, empty, nil
	}
	set, err := DecodeSetInformation(q.Class, q.Buffer)
	if errors.Is(err, ErrFileOperation) {
		return StatusInvalidInfoClass, empty, nil
	}
	if err != nil {
		return StatusInvalidParameter, empty, nil
	}
	if q.Class == FileRenameInformation || q.Class == FileDispositionInformation {
		return d.setNamespace(f, set)
	}
	if q.Class == FileBasicInformation || q.Class == FileAllocationInformation {
		return d.setMetadata(f, set)
	}
	if q.Class != FileEndOfFileInformation {
		return StatusNotSupported, empty, nil
	}
	if f.access&2 == 0 {
		return StatusAccessDenied, empty, nil
	}
	if f.info.IsDir() {
		return statusFileIsDirectory, empty, nil
	}
	if set.Size < 0 {
		return StatusInvalidParameter, empty, nil
	}
	err = f.ioFile().Truncate(set.Size)
	if err == nil && f.writeThrough {
		err = f.ioFile().Sync()
	}
	return directoryStatus(err), empty, nil
}

func directoryIOStatus(err error) uint32 {
	if runtime.GOOS == "windows" {
		// Win32 errors differ from the POSIX-compatible errno constants in Go.
		for _, m := range []struct {
			code   syscall.Errno
			status uint32
		}{{112, statusDiskFull}, {39, statusDiskFull}, {32, statusSharingViolation}, {33, StatusFileLockConflict}, {19, statusWriteProtected}, {267, statusNotDirectory}, {303, statusDeletePending}} {
			if errors.Is(err, m.code) {
				return m.status
			}
		}
	}
	switch {
	case errors.Is(err, syscall.ENOSPC):
		return statusDiskFull
	case errors.Is(err, syscall.EROFS):
		return statusWriteProtected
	case errors.Is(err, syscall.ENOTDIR):
		return statusNotDirectory
	case errors.Is(err, syscall.EISDIR):
		return statusFileIsDirectory
	case errors.Is(err, io.ErrShortWrite):
		return StatusUnsuccessful
	default:
		return StatusAccessDenied
	}
}
