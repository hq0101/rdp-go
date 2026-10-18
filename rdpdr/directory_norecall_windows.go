package rdpdr

import "os"

// Go's os.Root open flags do not expose FILE_OPEN_NO_RECALL. Pass the actual
// native option through a handle-relative, no-reparse path walk. It controls
// recall caused by this open; it is not a promise of no provider/network I/O.
func (d *DirectoryDrive) openNoRecall(name string, q *CreateRequest, access uint32) (*os.File, bool, uint32, func() error) {
	return d.openNativeWritable(name, q, access)
}

// Native access is granted on the first handle, including for a newly created
// READONLY file whose creator may still have write rights. Reopening after
// creation would incorrectly lose those rights. Existing files are never
// overwritten here: open() first validates type and both sharing directions.
func (d *DirectoryDrive) openNativeWritable(name string, q *CreateRequest, access uint32) (*os.File, bool, uint32, func() error) {
	parent, leaf, pins, status := d.namespaceParentOptions(name, q.Options&0x400000)
	cleanup := func() error { return closeDirectoryParents(pins) }
	if status != 0 {
		return nil, false, status, cleanup
	}
	if name == "." {
		if q.Disposition == 2 {
			return nil, false, statusNameCollision, cleanup
		}
		info, err := d.rootFile.Stat()
		if err != nil {
			return nil, false, directoryStatus(err), cleanup
		}
		f, status := directoryReopenIdentity(&directoryFile{file: d.rootFile, info: info, access: access, openOptions: q.Options}, 0)
		return f, false, status, cleanup
	}
	options := uint32(0x200000) | (q.Options & (1 | 2 | 4 | 0x40 | 0x800 | 0x400000))
	create := func() (*os.File, bool, uint32) {
		if status := directoryCreationPolicy(q); status != 0 {
			return nil, false, status
		}
		attributes := q.Attributes
		createOptions := options
		if q.Options&1 != 0 {
			attributes |= 0x10
		} else {
			createOptions |= 0x40
		}
		return directoryNativeCreate(parent, leaf, access, 7, 2, createOptions, attributes, q.AllocationSize)
	}
	if q.Disposition == 2 {
		f, created, status := create()
		return f, created, status, cleanup
	}
	for attempt := 0; attempt < 4; attempt++ {
		// Windows rejects DIRECTORY_FILE combined with NO_RECALL. An existing
		// object can be opened without type enforcement, then checked through
		// that same handle by open(). CREATE retains DIRECTORY_FILE and lets
		// the host reject incompatible options instead of silently dropping them.
		openOptions := options
		if options&0x400000 != 0 {
			openOptions &^= 1
		}
		f, _, status := directoryNativeOpen(parent, leaf, access, 7, 1, openOptions, 0)
		if status == 0 {
			return f, false, 0, cleanup
		}
		if !d.opts.Writable || (q.Disposition != 3 && q.Disposition != 5) || (status != StatusNoSuchFile && status != 0xc0000034) {
			return nil, false, status, cleanup
		}
		f, created, status := create()
		if status != statusNameCollision {
			return f, created, status, cleanup
		}
	}
	return nil, false, statusSharingViolation, cleanup
}
