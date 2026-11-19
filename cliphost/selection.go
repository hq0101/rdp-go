package cliphost

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"

	"github.com/hq0101/rdp-go/cliprdr"
)

// FileSelectionOptions bounds an explicitly acquired local clipboard selection.
// MaxTotalSize is required: zero permits directories and empty files only.
// MaxFiles counts both files and directories; zero uses cliprdr.MaxFiles.
type FileSelectionOptions struct {
	MaxTotalSize uint64
	MaxFiles     int
}

// AcquireFileSource acquires a local selection as an owned FileSourceOffer for
// adapters such as clipsync. On success its Release must eventually be called;
// on failure no ownership is transferred. Like AcquireFiles, native acquisition
// may outlive cancellation and must be joined separately from Host.Done.
// Windows prefers CF_HDROP when available; otherwise it acquires Unicode OLE
// virtual files. AcquireFiles itself remains limited to filesystem selections.
// Both paths report the observed PreferredDropEffect: OLE sources and CF_HDROP
// selections observe the "Preferred DropEffect" format when present (an absent
// format means copy); a present but malformed value fails acquisition. Nothing
// here moves or deletes files.
func (h *Host) AcquireFileSource(ctx context.Context, token Token, options FileSelectionOptions) (cliprdr.FileSourceOffer, error) {
	if ctx == nil || token.id == nil {
		return cliprdr.FileSourceOffer{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return cliprdr.FileSourceOffer{}, err
	}
	var err error
	if options, err = selectionOptions(options); err != nil {
		return cliprdr.FileSourceOffer{}, err
	}
	return h.acquireFileSource(ctx, token, options)
}

func (h *Host) acquireDropSource(ctx context.Context, token Token, options FileSelectionOptions) (cliprdr.FileSourceOffer, error) {
	s, err := h.AcquireFiles(ctx, token, options)
	if err != nil {
		return cliprdr.FileSourceOffer{}, err
	}
	offer, err := s.SourceOffer()
	if err != nil {
		return cliprdr.FileSourceOffer{}, errors.Join(err, s.Close())
	}
	return offer, nil
}

func selectionOptions(o FileSelectionOptions) (FileSelectionOptions, error) {
	if o.MaxFiles == 0 {
		o.MaxFiles = cliprdr.MaxFiles
	}
	if o.MaxTotalSize > math.MaxInt64 || o.MaxFiles < 1 || o.MaxFiles > cliprdr.MaxFiles {
		return o, ErrInvalid
	}
	return o, nil
}

type selectionSource interface {
	io.ReaderAt
	io.Closer
}

type selectedFile struct {
	descriptor cliprdr.FileDescriptor
	source     selectionSource // directories retain a handle but have no reader
}

// FileSelection owns the handles acquired from one external CF_HDROP item.
// A later clipboard change does not close these handles: remote clipboard locks
// may still retain an earlier offer. The caller must Close or transfer ownership
// to cliprdr.FileSources using SourceOffer. Never copy a FileSelection.
//
// Close waits for actual running reads and handle cleanup. Native filesystem I/O
// may block; use a separate worker, not a GUI callback or a transport receive loop.
// No files are created, modified, moved, deleted, or loaded into temporary copies.
type FileSelection struct {
	mu        sync.RWMutex
	files     []selectedFile
	preferred uint32
	closed    bool
	closeErr  error
}

// SourceOffer returns copied metadata and read-only readers with original indices.
// Directories have nil readers. On successful FileSources.Publish, transfer this
// selection's ownership to that store; do not Close or publish it elsewhere.
// On publication failure the caller still owns it and must Close it.
func (s *FileSelection) SourceOffer() (cliprdr.FileSourceOffer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return cliprdr.FileSourceOffer{}, ErrClosed
	}
	if len(s.files) == 0 {
		return cliprdr.FileSourceOffer{}, ErrInvalid
	}
	o := cliprdr.FileSourceOffer{Files: make([]cliprdr.FileDescriptor, len(s.files)), Readers: make([]io.ReaderAt, len(s.files)), Release: s.Close, PreferredDropEffect: s.preferred}
	for i, f := range s.files {
		o.Files[i] = f.descriptor
		if !f.descriptor.IsDirectory() {
			o.Readers[i] = selectionReader{s, i}
		}
	}
	return o, nil
}

func (s *FileSelection) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		for i := len(s.files) - 1; i >= 0; i-- {
			if s.files[i].source != nil {
				s.closeErr = errors.Join(s.closeErr, s.files[i].source.Close())
			}
		}
	}
	return s.closeErr
}

type selectionReader struct {
	s     *FileSelection
	index int
}

func (r selectionReader) ReadAt(p []byte, off int64) (int, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	if r.s.closed {
		return 0, ErrClosed
	}
	f := &r.s.files[r.index]
	if off < 0 {
		return 0, ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if uint64(off) >= f.descriptor.Size {
		return 0, io.EOF
	}
	n := min(uint64(len(p)), f.descriptor.Size-uint64(off))
	read, err := f.source.ReadAt(p[:n], off)
	if err == nil && read != len(p) {
		err = io.EOF
	}
	return read, err
}
