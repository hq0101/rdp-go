package cliprdr

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type FileBatchOptions struct {
	MaxOpenFiles int // zero defaults to four, maximum 64
}

// FileBatch stages files by generated numeric names, never remote paths. parent
// must be an existing application-controlled directory whose permissions exclude
// untrusted local writers. It and its ancestors must remain stable during use;
// this is not a sandbox against concurrent local filesystem attackers.
//
// Methods synchronize internally; target WriteAt calls may run concurrently.
// Close and WriteZIP can block on I/O. Cancel downloads and wait for active
// writes before closing a batch. A FileBatch must not be copied.
type FileBatch struct {
	mu              sync.Mutex
	plan            *FilePlan
	parent, root    string
	identity        os.FileInfo
	maxOpen         int
	files           map[uint32]*batchFile
	closed, removed bool
}

type batchFile struct {
	mu               sync.RWMutex
	f                *os.File
	path             string
	size             uint64
	identity         os.FileInfo
	closed, complete bool
}

func NewFileBatch(parent string, plan *FilePlan, options FileBatchOptions) (*FileBatch, error) {
	if plan == nil || plan.byIndex == nil || parent == "" {
		return nil, ErrFile
	}
	if options.MaxOpenFiles == 0 {
		options.MaxOpenFiles = 4
	}
	if options.MaxOpenFiles < 1 || options.MaxOpenFiles > MaxFileRequests {
		return nil, ErrFileLimit
	}
	abs, err := filepath.Abs(parent)
	if err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp(abs, ".rdpgo-files-")
	if err != nil {
		return nil, err
	}
	// File.Stat captures the identity from an open handle. Windows Lstat may
	// otherwise defer its identity lookup until SameFile, after replacement.
	handle, err := os.Open(root)
	if err != nil {
		_ = os.Remove(root)
		return nil, err
	}
	info, err := handle.Stat()
	err = errors.Join(err, handle.Close())
	if err != nil {
		_ = os.Remove(root)
		return nil, err
	}
	return &FileBatch{plan: plan, parent: abs, root: root, identity: info, maxOpen: options.MaxOpenFiles, files: make(map[uint32]*batchFile)}, nil
}

func (b *FileBatch) checkRoot() error {
	rel, err := filepath.Rel(b.parent, b.root)
	if err != nil || rel == "." || filepath.IsAbs(rel) || strings.ContainsAny(rel, "/\\") || !strings.HasPrefix(rel, ".rdpgo-files-") {
		return ErrFilePath
	}
	info, err := os.Lstat(b.root)
	if err != nil {
		return err
	}
	if !info.IsDir() || !os.SameFile(info, b.identity) {
		return ErrChanged
	}
	return nil
}

// OpenFile creates an empty bounded target for an original descriptor index.
// Pass it to Client.NewFileDownload with the SAME set and index. Completion is
// acknowledged with CompleteFile. Directory and repeated opens are rejected.
func (b *FileBatch) OpenFile(index uint32) (io.WriterAt, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, os.ErrClosed
	}
	i, ok := b.plan.byIndex[index]
	if !ok || b.plan.entries[i].Directory {
		return nil, ErrFile
	}
	if _, ok = b.files[index]; ok {
		return nil, ErrBusy
	}
	open := 0
	for _, f := range b.files {
		if !f.closed {
			open++
		}
	}
	if open >= b.maxOpen {
		return nil, ErrFileLimit
	}
	if err := b.checkRoot(); err != nil {
		return nil, err
	}
	path := filepath.Join(b.root, fmt.Sprintf("%04d.part", index))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	target := &batchFile{f: f, path: path, size: b.plan.entries[i].Size, identity: info}
	b.files[index] = target
	return target, nil
}

func (f *batchFile) WriteAt(p []byte, off int64) (int, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	if off < 0 || uint64(off) > f.size || uint64(len(p)) > f.size-uint64(off) || len(p) > MaxFileChunk {
		return 0, ErrFile
	}
	return f.f.WriteAt(p, off)
}

// CompleteFile requires the bound download to have fully succeeded. It checks
// the actual length, syncs and closes the target before making it exportable.
// Writer errors/cancellation do not become complete just because a file exists.
func (b *FileBatch) CompleteFile(index uint32, download *FileDownload) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return os.ErrClosed
	}
	f := b.files[index]
	if f == nil || download == nil || download.set != b.plan.set || download.index != index || download.target != f {
		return ErrChanged
	}
	st := download.Status()
	if !st.Complete || st.Size != f.size {
		return ErrFileIncomplete
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.complete {
		return nil
	}
	if f.closed {
		return os.ErrClosed
	}
	info, err := f.f.Stat()
	if err == nil && (info.Size() < 0 || uint64(info.Size()) != f.size) {
		err = ErrFileIncomplete
	}
	if err == nil {
		err = f.f.Sync()
	}
	err = errors.Join(err, f.f.Close())
	f.closed = true
	if err == nil {
		f.complete = true
	}
	return err
}

// WriteZIP exports only after EVERY regular file is complete. Implicit parents
// and empty directories are included; stored names use forward slashes. Remote
// permissions, timestamps, symlink attributes and executable modes are not used.
// The caller owns w and must discard partial output on error. Use a private
// temporary output and publish it only after this method and its close succeed.
// Context is checked between bounded copies; a blocking writer needs its own
// deadline. This method does not close w or delete the staged input files.
func (b *FileBatch) WriteZIP(ctx context.Context, w io.Writer) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return os.ErrClosed
	}
	if w == nil {
		return ErrFile
	}
	for _, e := range b.plan.entries {
		if !e.Directory {
			if f := b.files[uint32(e.Index)]; f == nil || !f.complete {
				return ErrFileIncomplete
			}
		}
	}
	if err := b.checkRoot(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	z := zip.NewWriter(w)
	buf := make([]byte, 64<<10)
	for _, e := range b.plan.entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		h := &zip.FileHeader{Name: e.Path, Method: zip.Deflate}
		h.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
		h.SetMode(0644)
		if e.Directory {
			h.Name += "/"
			h.Method = zip.Store
			h.SetMode(os.ModeDir | 0755)
		}
		entry, err := z.CreateHeader(h)
		if err != nil {
			return err
		}
		if !e.Directory {
			if err = b.copyEntry(ctx, entry, b.files[uint32(e.Index)], buf); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return z.Close()
}

func (b *FileBatch) copyEntry(ctx context.Context, w io.Writer, staged *batchFile, buf []byte) error {
	f, err := os.Open(staged.path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, staged.identity) || info.Size() < 0 || uint64(info.Size()) != staged.size {
		return ErrChanged
	}
	for remaining := staged.size; remaining > 0; {
		if err = ctx.Err(); err != nil {
			return err
		}
		n := int(min(remaining, uint64(len(buf))))
		if _, err = io.ReadFull(f, buf[:n]); err != nil {
			return err
		}
		written, writeErr := w.Write(buf[:n])
		if writeErr != nil {
			return writeErr
		}
		if written != n {
			return io.ErrShortWrite
		}
		remaining -= uint64(n)
	}
	return nil
}

// Close closes all owned handles and removes ONLY this batch's generated
// directory after checking its parent-relative path and original identity.
// It is retryable after a filesystem removal error and never removes the parent.
func (b *FileBatch) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	var err error
	for _, f := range b.files {
		f.mu.Lock()
		if !f.closed {
			err = errors.Join(err, f.f.Close())
			f.closed = true
		}
		f.mu.Unlock()
	}
	if b.removed {
		return err
	}
	if check := b.checkRoot(); check != nil {
		if os.IsNotExist(check) {
			b.removed = true
			return err
		}
		return errors.Join(err, check)
	}
	removeErr := os.RemoveAll(b.root)
	if removeErr == nil {
		b.removed = true
	}
	return errors.Join(err, removeErr)
}
