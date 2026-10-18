package rdpdr

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	statusInvalidHandle    uint32 = 0xc0000008
	statusSharingViolation uint32 = 0xc0000043
	statusNotDirectory     uint32 = 0xc0000103
	statusFileIsDirectory  uint32 = 0xc00000ba
	statusWriteProtected   uint32 = 0xc00000a2
	statusTooManyFiles     uint32 = 0xc000011f
)

type DirectoryOptions struct {
	// Writable explicitly allows regular-file creation, writing and EOF changes.
	// On Windows hosts it also enables directory creation, identity-based
	// rename, deletion, delete-on-close, basic metadata and allocation setters,
	// and initial CREATE/OVERWRITE attributes and allocation. Linux amd64/arm64
	// also supports access/write time setters; macOS supports creation/access/write
	// time setters. Unix setters use the open descriptor, with zero meaning omit;
	// DOS attribute changes and -1/-2 timestamp suppression remain unsupported.
	// Other namespace/allocation operations remain Windows-only. Default is
	// read-only; this is not an OS ACL sandbox or a disk quota.
	Writable bool
	// Zero selects 128 handles and 4096 directory entries. Maximums are 4096.
	// MaxEntries is an aggregate retained-snapshot budget across all handles.
	MaxHandles, MaxEntries int
	// MaxLocks bounds held plus queued lock regions (default/maximum 4096).
	// MaxPendingLocks bounds waiting requests (default 64, maximum 128).
	MaxLocks, MaxPendingLocks int
	// MaxWatches bounds native directory watchers, including idle ones retained
	// between requests (default 64, maximum 128). One pending notify per FileID.
	MaxWatches int
	// WindowsLockFlagCompatibility interprets the LOCK request F bit as
	// fail-immediately, as observed with our Windows 10 server. The default
	// follows MS-RDPEFS 2.2.3.3.12 (F set means wait). Decoding is unchanged.
	WindowsLockFlagCompatibility bool
	// VolumeLabel is metadata, not the drive/share name. Empty uses OPENRDP.
	VolumeLabel string
}

type directoryFile struct {
	identity                 *os.File // native overwrite handle; original remains owned until close
	closeDelete              *os.File // optional native FILE_FLAG_DELETE_ON_CLOSE handle
	deleteOnClose            bool
	deletePending            bool
	locks                    []directoryLock
	watch                    *directoryWatch
	file                     *os.File
	path                     string
	info                     fs.FileInfo
	access, share            uint32
	openOptions              uint32
	entries                  []DirectoryEntry
	cursor                   int
	enumerated               bool
	appendOnly, writeThrough bool
}

// DirectoryDrive exposes one explicitly selected host directory for RDPEFS
// operations, read-only unless DirectoryOptions.Writable is set. Construction opens the root; no channel is advertised.
// Windows/Linux/macOS use os.Root (Go 1.25+) to anchor the selected root. Only
// regular files and directories are served. Windows writable/NoRecall opens use
// a pinned native path walk that rejects every reparse component. Other opens
// use os.Root, which may follow relative symlinks contained within the root.
// This does not isolate hard links, mounted filesystems, or privileged
// local actors. Select a tree whose contents the user intends to share.
//
// Handle serializes physical I/O and uses FileHandles ownership/close rules.
// Keep DriveOptions.AsyncIO=false, and serialize the associated DriveClient
// around Handle and its other methods. Send each returned reply before processing
// another request. Use Dispatch/Poll for waiting locks and directory notifications; Handle only completes
// immediate requests. Errors require teardown and Close; never replay a request.
// Context cancellation is checked between operations; it cannot interrupt a
// blocked host filesystem syscall. Lock waits are polled; Windows notifications use asynchronous OS requests.
// Cancellation/Close wait for native notification completion before freeing buffers.
// Close waits for current I/O before cleanup and discards queued requests;
// then Reset/Remove the DriveClient to invalidate their protocol tokens.
// Windows hosts support directory creation and identity-based rename/delete.
// Namespace destinations are resolved with pinned ancestors and no reparse
// traversal. Windows byte-range locks use the I/O handle and also constrain
// ordinary independent local file I/O, but not memory-mapped views. Other hosts
// do not yet support namespace mutations, locks or notifications. Windows
// watchers retain changes between requests; security descriptors remain unsupported. Sharing checks apply to handles owned by this backend,
// not independent local processes. Basic metadata is available on every open
// handle; data reads and enumeration require FILE_READ_DATA/LIST_DIRECTORY.
// Writable changes use the opened file identity, never a subsequent pathname
// lookup. Rejected sharing/access requests do not truncate files. Host write,
// truncate, sync or close failures can have partial effects; no rollback is
// promised. Linux/macOS explicit EOF writes temporarily use O_APPEND on the
// exclusively owned descriptor under the backend mutex, then restore its flags;
// a restoration failure poisons the backend and requires Close. A newly created
// file may remain after a later I/O failure. Local
// filesystem permissions apply under the client's OS identity, not the remote
// account. No remote Windows ACL impersonation is performed.
// Windows identity handles serve both metadata and data I/O, preserving
// per-handle timestamp suppression. They can own up to three OS handles per FileID, all
// closed by the same owner. Each watched directory additionally owns one
// native directory handle, one event and a 32 KiB buffer (MaxWatches).
// Native path operations temporarily pin up to 127
// ancestors in addition to the configured FileID budget. A cleanup failure is
// retained even after other owned handles have been successfully closed.
// Use a new backend after reconnect.
// Do not copy a DirectoryDrive.
type DirectoryDrive struct {
	mu                            sync.Mutex
	root                          *os.Root
	rootFile                      *os.File
	rootPath                      string
	device                        uint32
	opts                          DirectoryOptions
	handles                       *FileHandles
	files                         map[uint32]*directoryFile
	entries                       int
	lockCount, pendingLockRegions int
	pendingLocks                  []directoryPendingLock
	pendingNotifies               []directoryPendingNotify
	watchCount                    int
	closed                        bool
	failure                       error
}

func OpenDirectoryDrive(deviceID uint32, rootPath string, opts DirectoryOptions) (*DirectoryDrive, error) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil, ErrUnsupported
	}
	if rootPath == "" {
		return nil, ErrDevice
	}
	if opts.MaxHandles == 0 {
		opts.MaxHandles = 128
	}
	if opts.MaxEntries == 0 {
		opts.MaxEntries = 4096
	}
	if opts.MaxHandles < 1 || opts.MaxHandles > 4096 || opts.MaxEntries < 1 || opts.MaxEntries > 4096 {
		return nil, ErrLimit
	}
	if opts.MaxLocks == 0 {
		opts.MaxLocks = MaxFileLocks
	}
	if opts.MaxPendingLocks == 0 {
		opts.MaxPendingLocks = 64
	}
	if opts.MaxLocks < 1 || opts.MaxLocks > MaxFileLocks || opts.MaxPendingLocks < 1 || opts.MaxPendingLocks > 128 {
		return nil, ErrLimit
	}
	if opts.MaxWatches == 0 {
		opts.MaxWatches = 64
	}
	if opts.MaxWatches < 1 || opts.MaxWatches > 128 {
		return nil, ErrLimit
	}
	if opts.VolumeLabel == "" {
		opts.VolumeLabel = "OPENRDP"
	}
	if _, err := EncodeVolumeInformation(VolumeInformation{Label: opts.VolumeLabel}); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	return newDirectoryDrive(deviceID, root, abs, opts)
}

// NewSession creates an independent backend anchored to the same directory
// identity. It does not inherit FileIDs, locks, notifications or protocol state.
// The source must be open; each backend must be closed separately. Close/join
// the old connection's backend before exposing the new one. Keeping a separate
// unused source backend permits reconnect without re-resolving a replaced path.
func (d *DirectoryDrive) NewSession() (*DirectoryDrive, error) {
	if d == nil {
		return nil, ErrFileHandle
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.failure != nil {
		return nil, ErrFileHandle
	}
	root, err := d.root.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	return newDirectoryDrive(d.device, root, d.rootPath, d.opts)
}

// Takes ownership of root, including on error. Options have been validated.
func newDirectoryDrive(deviceID uint32, root *os.Root, path string, opts DirectoryOptions) (*DirectoryDrive, error) {
	f, err := root.Open(".")
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	h, _ := NewFileHandles(FileHandleLimits{Handles: opts.MaxHandles, Uses: 1})
	return &DirectoryDrive{root: root, rootFile: f, rootPath: path, device: deviceID, opts: opts, handles: h, files: make(map[uint32]*directoryFile)}, nil
}

func (d *DirectoryDrive) Status() FileHandleStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.handles.Status()
}

// Close is idempotent. A cleanup failure poisons the backend and remains visible
// on repeated calls; it does not blindly retry a possibly released OS handle.
func (d *DirectoryDrive) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return d.failure
	}
	d.closed = true
	d.pendingLocks = nil
	d.pendingNotifies = nil
	d.pendingLockRegions = 0
	d.handles.Stop()
	d.failure = errors.Join(d.failure, d.drain(), d.rootFile.Close(), d.root.Close())
	return d.failure
}

func (d *DirectoryDrive) drain() error {
	var errs []error
	for {
		job, ok := d.handles.NextClose()
		if !ok {
			break
		}
		f := job.Resource().(*directoryFile)
		err := d.closeWatch(f)
		err = errors.Join(err, d.rollbackLocks(f, 0))
		err = errors.Join(err, f.file.Close())
		if f.identity != nil {
			err = errors.Join(err, f.identity.Close())
		}
		if f.closeDelete != nil {
			err = errors.Join(err, f.closeDelete.Close())
		}
		_, id := job.IDs()
		if err == nil {
			if f.deleteOnClose || f.deletePending {
				for _, other := range d.files {
					if other != f && os.SameFile(other.info, f.info) {
						standard, status := directoryStandard(other, other.info)
						if status == 0 {
							other.deletePending = standard.DeletePending
						}
					}
				}
			}
			d.entries -= len(f.entries)
			delete(d.files, id)
		}
		errs = append(errs, err, d.handles.CompleteClose(job, err))
	}
	return errors.Join(errs...)
}

// Handle validates the live immutable token before touching the filesystem and
// consumes it through CompleteFile exactly once. Contended wait requests return
// STATUS_NOT_SUPPORTED here, as do directory notifications; use Dispatch/Poll
// to support deferred completion.
// Stale/foreign/mismatched tokens
// never cause a host open. Caller must serialize client access as documented.
func (d *DirectoryDrive) Handle(ctx context.Context, c *DriveClient, request Request) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.handle(ctx, c, request, false)
}

func (d *DirectoryDrive) handle(ctx context.Context, c *DriveClient, request Request, deferred bool) ([]byte, error) {
	if ctx == nil {
		return nil, ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.closed || d.failure != nil {
		return nil, errors.Join(ErrFileHandle, d.failure)
	}
	if !c.initialized() || request.owner != c || request.entry == nil {
		return nil, ErrRequest
	}
	h := request.entry.header
	if c.pending[requestKey{h.DeviceID, h.CompletionID}] != request.entry {
		return nil, ErrRequest
	}
	if h.DeviceID != d.device {
		return nil, ErrDevice
	}
	for _, pending := range d.pendingLocks {
		if pending.request.owner != c {
			return nil, ErrRequest
		}
		if pending.request.entry == request.entry {
			return nil, ErrRequest
		}
	}
	for _, pending := range d.pendingNotifies {
		if pending.request.owner != c || pending.request.entry == request.entry {
			return nil, ErrRequest
		}
	}
	q, err := request.DecodeFile()
	if errors.Is(err, ErrFileOperation) {
		return c.CompleteFile(request, StatusNotSupported, FileResult{})
	}
	if err != nil {
		return nil, err
	}
	if q.Notify != nil {
		return d.notify(ctx, c, request, q, deferred)
	}
	status, result, err := d.execute(ctx, q)
	if err != nil {
		d.failure = errors.Join(d.failure, err)
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		// I/O may already have mutated the host. Do not allow the still-pending
		// token to replay after an ambiguous cancellation.
		d.failure = errors.Join(d.failure, err)
		return nil, err
	}
	if q.Lock != nil && d.waitForLock(q.Lock) && (q.Lock.Operation == 2 || q.Lock.Operation == 3) && status == StatusLockNotGranted {
		if deferred {
			status = d.queueLock(ctx, request, q.Lock)
			if status == StatusPending {
				return nil, nil
			}
		} else {
			status = StatusNotSupported
		} // use Dispatch/Poll for waiting
	}
	reply, err := c.CompleteFile(request, status, result)
	if err != nil {
		d.failure = errors.Join(d.failure, err)
	}
	return reply, err
}

func (d *DirectoryDrive) execute(ctx context.Context, q FileRequest) (uint32, FileResult, error) {
	empty := FileResult{}
	if q.Header.MajorFunction == MajorCreate {
		return d.open(q.Create)
	}
	lease, err := d.handles.Acquire(d.device, q.Header.FileID)
	if err != nil {
		return statusInvalidHandle, empty, nil
	}
	f := lease.Resource().(*directoryFile)
	defer lease.Release()
	if q.Header.MajorFunction == MajorClose {
		lease.Release()
		if err = d.handles.Retire(d.device, q.Header.FileID); err != nil {
			return StatusUnsuccessful, empty, err
		}
		return StatusSuccess, empty, d.drain()
	}
	switch q.Header.MajorFunction {
	case MajorLockControl:
		return d.lock(f, q.Lock)
	case MajorWrite:
		return d.write(f, q.Write)
	case MajorSetInformation:
		return d.setInformation(f, q.Information)
	case MajorSetVolume:
		if !d.opts.Writable {
			return statusWriteProtected, empty, nil
		}
		return StatusNotSupported, empty, nil
	case MajorRead:
		if f.access&1 == 0 {
			return StatusAccessDenied, empty, nil
		}
		if f.info.IsDir() {
			return statusFileIsDirectory, empty, nil
		}
		r := q.Read
		if r.Offset > math.MaxInt64 || uint64(r.Length) > uint64(math.MaxInt64)-r.Offset {
			return StatusInvalidParameter, empty, nil
		}
		if r.Length > MaxFileData {
			return StatusInvalidParameter, empty, nil
		}
		if r.Length == 0 {
			return StatusSuccess, empty, nil
		}
		data := make([]byte, int(r.Length))
		n, err := f.ioFile().ReadAt(data, int64(r.Offset))
		if err != nil && !errors.Is(err, io.EOF) {
			return directoryStatus(err), empty, nil
		}
		if n == 0 {
			return StatusEndOfFile, empty, nil
		}
		return StatusSuccess, FileResult{Data: data[:n]}, nil
	case MajorQueryInformation:
		info, err := f.ioFile().Stat()
		if err != nil {
			return directoryStatus(err), empty, nil
		}
		var data []byte
		switch q.Information.Class {
		case FileBasicInformation:
			basic, status := directoryBasicHandle(f, info)
			if status != 0 {
				return status, empty, nil
			}
			data, err = EncodeBasicInformation(d.basicView(basic))
		case FileStandardInformation:
			standard, s := directoryStandard(f, info)
			if s != 0 {
				return s, empty, nil
			}
			data, err = EncodeStandardInformation(standard)
		case FileAttributeTagInformation:
			basic, status := directoryBasicHandle(f, info)
			if status != 0 {
				return status, empty, nil
			}
			data = EncodeAttributeTagInformation(d.basicView(basic).Attributes, 0)
		default:
			return StatusInvalidInfoClass, empty, nil
		}
		if err != nil {
			return StatusUnsuccessful, empty, err
		}
		return StatusSuccess, FileResult{Data: data}, nil
	case MajorQueryVolume:
		return d.volume(q.Information.Class)
	case MajorDirectoryControl:
		if q.Header.MinorFunction != MinorQueryDirectory {
			return StatusNotSupported, empty, nil
		}
		if f.access&1 == 0 {
			return StatusAccessDenied, empty, nil
		}
		if !f.info.IsDir() {
			return statusNotDirectory, empty, nil
		}
		return d.enumerate(ctx, f, q.Directory)
	default:
		return StatusNotSupported, empty, nil
	}
}

func directoryReadAccess(q *CreateRequest) (uint32, uint32) {
	if q.SharedAccess&^uint32(7) != 0 || q.Disposition > 5 {
		return 0, StatusInvalidParameter
	}
	if q.Disposition != 1 && q.Disposition != 3 {
		return 0, statusWriteProtected
	}
	if q.Options&0x1000 != 0 {
		return 0, statusWriteProtected
	}
	supportedOptions := uint32(0x1 | 0x2 | 0x4 | 0x10 | 0x20 | 0x40 | 0x800 | 0x4000)
	if directoryNamespaceAvailable() {
		supportedOptions |= 0x200000 | 0x400000
	}
	if q.Options&^uint32(supportedOptions) != 0 {
		return 0, StatusNotSupported
	}
	if q.Options&0x41 == 0x41 || q.Options&0x30 == 0x30 {
		return 0, StatusInvalidParameter
	}
	access := q.DesiredAccess
	if access&0x80000000 != 0 {
		access = access&^0x80000000 | 0x120089
	}
	if access&0x20000000 != 0 {
		access = access&^0x20000000 | 0x1200a0
	}
	if access&0x02000000 != 0 {
		access = access&^0x02000000 | 0x1200a9
	}
	if access&^uint32(0x1200a9) != 0 {
		return 0, StatusAccessDenied
	}
	if q.Options&0x30 != 0 && access&0x100000 == 0 {
		return 0, StatusInvalidParameter
	}
	return access, StatusSuccess
}

func (d *DirectoryDrive) open(q *CreateRequest) (status uint32, result FileResult, fatal error) {
	empty := FileResult{}
	access, status := directoryReadAccess(q)
	if d.opts.Writable {
		access, status = directoryWriteAccess(q)
	}
	if status != 0 {
		return status, empty, nil
	}
	name, err := directoryPath(q.Path)
	if err != nil {
		return StatusAccessDenied, empty, nil
	}
	if name == "." && access&0x10000 != 0 {
		return StatusAccessDenied, empty, nil
	}
	reservation, err := d.handles.Reserve(d.device)
	if err != nil {
		return statusTooManyFiles, empty, nil
	}
	var f *os.File
	created := false
	if d.opts.Writable || q.Options&0x400000 != 0 {
		var cleanup func() error
		if q.Options&0x400000 != 0 {
			f, created, status, cleanup = d.openNoRecall(name, q, access)
		} else {
			f, created, status, cleanup = d.openWritable(name, q, access)
		}
		if cleanup != nil {
			defer func() { fatal = errors.Join(fatal, cleanup()) }()
		}
	} else {
		f, err = d.root.OpenFile(name, os.O_RDONLY|directoryRequestedFlags(q.Options), 0)
		status = directoryStatus(err)
	}
	if status != 0 {
		_, done := d.handles.CompleteOpen(reservation, nil)
		return status, empty, done
	}
	entry := &directoryFile{file: f, path: name, openOptions: q.Options, access: access, share: q.SharedAccess, appendOnly: access&6 == 4, writeThrough: q.Options&2 != 0}
	opened, err := d.handles.CompleteOpen(reservation, entry)
	if err != nil {
		return StatusUnsuccessful, empty, errors.Join(err, f.Close())
	}
	// All successful OS opens are registered before validation so every failure
	// path closes through the same ownership/failed-close accounting.
	reject := func(s uint32) (uint32, FileResult, error) {
		e := d.handles.Retire(d.device, opened.ID)
		return s, empty, errors.Join(e, d.drain())
	}
	info, err := f.Stat()
	if err != nil {
		return reject(directoryStatus(err))
	}
	entry.info = info
	if info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return reject(StatusAccessDenied)
	}
	if q.Options&1 != 0 && !info.IsDir() {
		return reject(statusNotDirectory)
	}
	if q.Options&0x40 != 0 && info.IsDir() {
		return reject(statusFileIsDirectory)
	}
	for _, old := range d.files {
		if os.SameFile(old.info, info) && directoryShareConflict(access, q.SharedAccess, old.access, old.share) {
			return reject(statusSharingViolation)
		}
	}
	if access&0x10000 != 0 {
		// Root aliases must not turn the shared root into a namespace target.
		if info.IsDir() {
			rootInfo, e := d.rootFile.Stat()
			if e != nil {
				return reject(directoryStatus(e))
			}
			if os.SameFile(info, rootInfo) {
				return reject(StatusAccessDenied)
			}
		}
	}
	// No O_TRUNC is used by openWritable. Truncation is delayed until type,
	// identity and BOTH directions of sharing/access validation have passed.
	if d.opts.Writable && !created && (q.Disposition == 4 || q.Disposition == 5) {
		if info.IsDir() {
			return reject(statusFileIsDirectory)
		}
		if s := directoryOverwrite(entry, q); s != 0 {
			return reject(s)
		}
	}
	// Flush actual truncation; a new empty file can legitimately be opened
	// with read-only access, which does not grant FlushFileBuffers on Windows.
	if d.opts.Writable && entry.writeThrough && !created && (q.Disposition == 4 || q.Disposition == 5) {
		if err = entry.ioFile().Sync(); err != nil {
			return reject(directoryStatus(err))
		}
	}
	if q.Options&0x1000 != 0 {
		if s := directoryPrepareDeleteOnClose(entry); s != 0 {
			return reject(s)
		}
		entry.deleteOnClose = true
	}
	d.files[opened.ID] = entry
	// MS-RDPEFS 2.2.1.5.1 uses its disposition table, not native NT's
	// FILE_CREATED=2. In particular FILE_OPEN/CREATE/OVERWRITE reply with 0.
	var information byte
	if q.Disposition == 3 {
		information = 1
	}
	if q.Disposition == 5 {
		information = 3
	}
	return StatusSuccess, FileResult{FileID: opened.ID, Information: information}, nil
}

func (d *DirectoryDrive) enumerate(ctx context.Context, f *directoryFile, q *DirectoryRequest) (uint32, FileResult, error) {
	empty := FileResult{}
	switch q.Class {
	case FileDirectoryInformation, FileFullDirectoryInformation, FileBothDirectoryInformation, FileNamesInformation:
	default:
		return StatusInvalidInfoClass, empty, nil
	}
	if q.Initial {
		pattern, err := directoryPattern(f.path, q.Path)
		if err != nil {
			return StatusInvalidParameter, empty, nil
		}
		// Rewind the already-open directory handle, not its possibly replaced
		// original pathname.
		if _, err = f.ioFile().Seek(0, io.SeekStart); err != nil {
			return directoryStatus(err), empty, nil
		}
		capacity := d.opts.MaxEntries - d.entries + len(f.entries)
		list, err := f.ioFile().Readdir(capacity + 1)
		if err != nil && !errors.Is(err, io.EOF) {
			return directoryStatus(err), empty, nil
		}
		if len(list) > capacity {
			return statusTooManyFiles, empty, nil
		}
		entries := make([]DirectoryEntry, 0, len(list))
		bytes := 0
		for _, info := range list {
			if err := ctx.Err(); err != nil {
				return StatusCancelled, empty, err
			}
			if !directoryComponent(info.Name()) || (!info.IsDir() && !info.Mode().IsRegular()) || !directoryMatch(pattern, info.Name()) {
				continue
			}
			// The snapshot is metadata only; later opens repeat confined resolution.
			bytes += 128 + len(info.Name())*2
			if bytes > MaxFileData {
				return statusTooManyFiles, empty, nil
			}
			entries = append(entries, DirectoryEntry{Name: info.Name(), Basic: d.basic(info), EndOfFile: directorySize(info), AllocationSize: directoryAllocation(info)})
		}
		d.entries += len(entries) - len(f.entries)
		f.entries = entries
		f.cursor = 0
		f.enumerated = true
	}
	if !f.enumerated {
		return StatusInvalidParameter, empty, nil
	}
	if f.cursor == len(f.entries) {
		if q.Initial {
			return StatusNoSuchFile, empty, nil
		}
		return StatusNoMoreFiles, empty, nil
	}
	// RDPEFS continuation asks for the next file (2.2.3.3.10). Return
	// one record; the Windows peer does not accept our multi-record replies.
	// Cursor advances only after successful encoding.
	end := f.cursor + 1
	data, err := EncodeDirectoryInformation(q.Class, f.entries[f.cursor:end])
	if err != nil {
		return StatusUnsuccessful, empty, err
	}
	f.cursor = end
	return StatusSuccess, FileResult{Data: data}, nil
}

func (d *DirectoryDrive) volume(class uint32) (uint32, FileResult, error) {
	var data []byte
	var err error
	attributes, characteristics := uint32(0x80006), uint32(0x12)
	if d.opts.Writable {
		attributes &^= 0x80000
		characteristics &^= 2
	}
	switch class {
	case FileFsVolumeInformation:
		data, err = EncodeVolumeInformation(VolumeInformation{Label: d.opts.VolumeLabel})
	case FileFsAttributeInformation:
		data, err = EncodeVolumeAttributeInformation(VolumeAttributeInformation{Attributes: attributes, MaximumComponentLength: 255, FileSystemName: "OPENRDP"})
	case FileFsDeviceInformation:
		data, err = EncodeVolumeDeviceInformation(7, characteristics)
	case FileFsSizeInformation, FileFsFullSizeInformation:
		total, available, e := directoryVolume(d.rootPath, d.rootFile)
		if e != nil {
			return StatusNotSupported, FileResult{}, nil
		}
		// Virtual allocation units are 4096 bytes. This describes the host volume,
		// not a storage reservation or quota for this shared subtree.
		callerAvailable := int64(0)
		if d.opts.Writable {
			callerAvailable = available / 4096
		}
		if class == FileFsSizeInformation {
			data, err = EncodeVolumeSizeInformation(VolumeSizeInformation{TotalAllocationUnits: total / 4096, AvailableAllocationUnits: callerAvailable, SectorsPerAllocationUnit: 8, BytesPerSector: 512})
		} else {
			data, err = EncodeVolumeFullSizeInformation(VolumeFullSizeInformation{TotalAllocationUnits: total / 4096, CallerAvailableAllocationUnits: callerAvailable, ActualAvailableAllocationUnits: available / 4096, SectorsPerAllocationUnit: 8, BytesPerSector: 512})
		}
	default:
		return StatusInvalidInfoClass, FileResult{}, nil
	}
	if err != nil {
		return StatusUnsuccessful, FileResult{}, err
	}
	return StatusSuccess, FileResult{Data: data}, nil
}

func directoryStatus(err error) uint32 {
	switch {
	case err == nil:
		return StatusSuccess
	case errors.Is(err, fs.ErrExist):
		return statusNameCollision
	case errors.Is(err, fs.ErrNotExist):
		return StatusNoSuchFile
	case errors.Is(err, fs.ErrPermission):
		return StatusAccessDenied
	case errors.Is(err, fs.ErrInvalid):
		return StatusInvalidParameter
	default:
		return directoryIOStatus(err)
	}
}
func directorySize(i fs.FileInfo) int64 {
	if i.IsDir() {
		return 0
	}
	return max(i.Size(), 0)
}
func directoryFallbackAllocation(i fs.FileInfo) int64 {
	n := directorySize(i)
	if n > math.MaxInt64-4095 {
		return n
	}
	return (n + 4095) / 4096 * 4096
}
func (d *DirectoryDrive) basic(i fs.FileInfo) BasicInformation {
	return d.basicView(directoryBasicInfo(i))
}
func (d *DirectoryDrive) basicView(info BasicInformation) BasicInformation {
	if !d.opts.Writable {
		info.Attributes = (info.Attributes &^ 0x80) | 1
	}
	return info
}
func directoryFallbackBasic(i fs.FileInfo) BasicInformation {
	attributes := uint32(0x20)
	if i.IsDir() {
		attributes = 0x10
	}
	if i.Mode().Perm()&0222 == 0 {
		attributes |= 1
	}
	return BasicInformation{LastWriteTime: directoryTime(i.ModTime()), Attributes: attributes}
}

func directoryTime(t time.Time) int64 {
	sec := t.Unix()
	const epoch = 11644473600
	if sec < -epoch || sec > math.MaxInt64/10000000-epoch {
		return 0
	}
	ticks := (sec + epoch) * 10000000
	fraction := int64(t.Nanosecond() / 100)
	if ticks > math.MaxInt64-fraction {
		return 0
	}
	return ticks + fraction
}
