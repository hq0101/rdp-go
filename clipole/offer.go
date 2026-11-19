// Package clipole acquires and publishes explicitly selected virtual files through Windows
// OLE. It is a native adapter, not an automatic RDP clipboard synchronizer.
// It never opens descriptor paths, creates temporary files, or deletes sources.
package clipole

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hq0101/rdp-go/cliprdr"
)

var (
	ErrUnsupported = errors.New("clipole: native file clipboard unavailable on this platform")
	ErrInvalid     = errors.New("clipole: invalid file offer or options")
	ErrChanged     = errors.New("clipole: clipboard ownership changed")
	ErrBusy        = errors.New("clipole: clipboard is held by another window")
)

// Shell DROPEFFECT values used by the Preferred/Performed DropEffect formats
// and by OLE drag-and-drop effect negotiation.
const (
	DropEffectNone uint32 = 0
	DropEffectCopy uint32 = 1
	DropEffectMove uint32 = 2
	DropEffectLink uint32 = 4
)

// Operation reports one native Shell copy outcome observed on the data object.
// Result is the EndOperation HRESULT (zero on success); Effects carries the
// target's DROPEFFECT flags and never authorizes deleting or mutating the
// source. Performed/PasteSucceeded are the consumer's SetData write-backs
// ("Performed DropEffect" / "Paste Succeeded"), valid only when their Valid
// flag is set. Feedback is cleared when the next operation starts.
type Operation struct {
	Result         uint32
	Effects        uint32
	Performed      uint32
	PerformedValid bool
	PasteSucceeded bool
	PasteValid     bool
}

// Canceled reports the two conventional copy-cancellation HRESULTs: E_ABORT
// and HRESULT_FROM_WIN32(ERROR_CANCELLED). Other failures are not cancellations.
func (op Operation) Canceled() bool {
	return op.Result == 0x80004004 || op.Result == 0x800704c7
}

// Moved reports a successful operation whose consumer wrote back
// DROPEFFECT_MOVE. It is the consumer's claim only: this package never
// deletes or mutates the source. A real backing store's owner must perform
// the removal itself, after the operation and its reads have completed.
func (op Operation) Moved() bool {
	return op.Result == 0 && op.PerformedValid && op.Performed == DropEffectMove
}

// Snapshot is an opaque ownership/sequence observation, not clipboard content.
// It retains no OS handles. Only Observe can create a usable snapshot.
type Snapshot struct {
	owner, station uintptr
	sequence       uint32
	valid          bool
}

// ReadFunc supplies exactly length immutable bytes at offset in the original
// descriptor index. Requests never cross EOF and are bounded by ChunkSize.
// Calls are serial on the OLE thread. Honor ctx; never call this offer, pump COM,
// or wait for its Done from a callback. Keep network reception on another thread.
// The source must remain immutable until Done closes. Empty reads need no call.
type ReadFunc func(ctx context.Context, index uint32, offset uint64, length uint32) ([]byte, error)

type Options struct {
	// RetainOnChange keeps existing IDataObject/IStream/enumerator consumers
	// alive after clipboard replacement. The STA and source remain owned until
	// those consumers release their references, or context/Close cancels them.
	// The source must itself support this lifetime (for RDP, hold its file lock).
	// Also enables IDataObjectAsyncCapability for Shell background copying.
	// An active operation retains the source until EndOperation or cancellation.
	RetainOnChange bool
	// MaxTotalSize is explicit: zero permits only empty files/directories.
	MaxTotalSize uint64
	// ChunkSize defaults to 256 KiB, maximum cliprdr.MaxFileChunk.
	ChunkSize uint32
	// ReadTimeout gives all provider chunks in one native Read or CopyTo a
	// shared deadline. Default five seconds, range 100ms..one minute. ReadFunc
	// must honor it. A foreign CopyTo target's blocking Write cannot be canceled;
	// Done waits for that native call to actually return.
	ReadTimeout time.Duration
	// MaxObjects bounds retained streams/enumerators plus the data object.
	// Default 128, range 4..256. A process-wide limit of 512 also applies.
	MaxObjects int
	// PreferredDropEffect advertises drop intent through the "Preferred
	// DropEffect" format: DropEffectCopy (the default when zero),
	// DropEffectMove, or both. Advertising move deletes nothing here; the
	// ReadFunc owner must act on Operation.Performed itself. Cross-RDP file
	// clipboard remains copy-only regardless of this option.
	PreferredDropEffect uint32
	// DescriptorsFunc, when non-nil, defers all file metadata: Publish accepts
	// an empty files slice and installs only the format skeleton. The first
	// native consumer that enumerates or reads a file format invokes this once
	// to resolve descriptors; the result is validated (paths, collisions,
	// MaxFiles, MaxTotalSize) and cached. An error retires the offer and fails
	// that request. The callback runs on the offer STA and may block on a
	// bounded upstream fetch; it must honor ctx. read is still required and is
	// never invoked before descriptors resolve.
	DescriptorsFunc func(ctx context.Context) ([]cliprdr.FileDescriptor, error)
	// DragSource exposes IDropSource on the same data object (shared identity and
	// reference count), so a consumer can obtain it by QueryInterface and pass it
	// to DoDragDrop together with the IDataObject. QueryContinueDrag cancels on
	// Escape or offer retirement and drops when no mouse button remains held;
	// GiveFeedback requests the default OLE cursors. This only enables the drag
	// source contract: it never moves or deletes the source, and the interactive
	// DoDragDrop loop itself is driven by the consumer. Off by default.
	DragSource bool
}

// Offer owns a dedicated OLE STA and its message pump. Publish replaces the
// clipboard explicitly; PublishIfCurrent checks an Observe snapshot while the
// clipboard is exclusively open before OLE replaces it.
// By default ownership loss retires every stream. RetainOnChange instead waits
// for outstanding consumers after replacement. Parent cancellation and Close
// always retire all streams, including clones. Move intent can be advertised
// and performed effects observed, but no source is ever deleted or moved here.
// Use one coordinated producer per clipboard endpoint. Do not run it alongside
// an automatic cliphost/clipsync producer until their ownership is integrated.
type Offer struct {
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	errors      chan error
	operations  chan Operation
	mu          sync.Mutex
	err         error
	files       []cliprdr.FileDescriptor
	descriptors []byte
	read        ReadFunc
	o           Options
	expected    *Snapshot
	ownership   Snapshot // protected by mu; sequence is not used to recognize self
	resolveOnce sync.Once
	resolveErr  error
	finishOnce  sync.Once
}

// Publish exposes the format skeleton and content only on a consumer's read.
// Metadata is encoded immediately unless Options.DescriptorsFunc defers it to
// the first native enumeration. ctx controls the whole offer lifetime.
// Validation precedes any clipboard changes. Cancellation after dispatch may
// race publication; never blindly replay. On success, Close and await Done
// before releasing provider resources. Caller must keep its Windows desktop
// open until Done. Other platforms return ErrUnsupported; the same API can
// still be imported and compiled there.
func Publish(ctx context.Context, files []cliprdr.FileDescriptor, read ReadFunc, o Options) (*Offer, error) {
	return publish(ctx, nil, files, read, o)
}

// PublishIfCurrent replaces only the clipboard observed by Observe. A change
// while validation or STA startup is pending returns ErrChanged before writing.
// A busy clipboard returns ErrBusy. Once OLE installation begins, any other
// failure can be partial: do not replay blindly. Providers are retired on error.
func PublishIfCurrent(ctx context.Context, expected Snapshot, files []cliprdr.FileDescriptor, read ReadFunc, o Options) (*Offer, error) {
	if !expected.valid {
		return nil, ErrInvalid
	}
	return publish(ctx, &expected, files, read, o)
}

func publish(ctx context.Context, expected *Snapshot, files []cliprdr.FileDescriptor, read ReadFunc, o Options) (*Offer, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := prepare(files, read, o)
	if err != nil {
		return nil, err
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})
	s.errors = make(chan error, 1)
	s.operations = make(chan Operation, 4)
	s.expected = expected
	if err = s.start(); err != nil {
		s.cancel()
		return nil, err
	}
	return s, nil
}

// Validate checks a file offer without reading content or accessing the OS.
// This lets a coordinated clipboard host reject bad inputs before retiring its
// preceding provider. Publish and PublishIfCurrent repeat validation themselves.
func Validate(files []cliprdr.FileDescriptor, read ReadFunc, o Options) error {
	_, err := prepare(files, read, o)
	return err
}

func prepare(files []cliprdr.FileDescriptor, read ReadFunc, o Options) (*Offer, error) {
	if o.ChunkSize == 0 {
		o.ChunkSize = 256 << 10
	}
	if o.ReadTimeout == 0 {
		o.ReadTimeout = 5 * time.Second
	}
	if o.MaxObjects == 0 {
		o.MaxObjects = 128
	}
	if o.ChunkSize > cliprdr.MaxFileChunk || o.ReadTimeout < 100*time.Millisecond || o.ReadTimeout > time.Minute || o.MaxObjects < 4 || o.MaxObjects > 256 || o.PreferredDropEffect > DropEffectCopy|DropEffectMove {
		return nil, ErrInvalid
	}
	if o.DescriptorsFunc != nil {
		if read == nil {
			return nil, ErrInvalid
		}
		return &Offer{read: read, o: o}, nil
	}
	files, b, err := prepareFiles(files, read, o)
	if err != nil {
		return nil, err
	}
	return &Offer{files: files, descriptors: b, read: read, o: o}, nil
}

// prepareFiles validates and normalizes a resolved descriptor set, shared by
// eager publication and lazy resolution so both enforce identical limits.
func prepareFiles(files []cliprdr.FileDescriptor, read ReadFunc, o Options) ([]cliprdr.FileDescriptor, []byte, error) {
	if _, err := cliprdr.PlanFileOffer(files, cliprdr.FilePlanOptions{MaxFileSize: o.MaxTotalSize, MaxTotalSize: o.MaxTotalSize}); err != nil {
		return nil, nil, err
	}
	files = append([]cliprdr.FileDescriptor(nil), files...)
	for i := range files {
		f := &files[i]
		if !f.IsDirectory() && f.Size != 0 && read == nil {
			return nil, nil, ErrInvalid
		}
		f.Name = strings.ReplaceAll(f.Name, "/", "\\")
		f.Flags &= cliprdr.FileAttributesValid | cliprdr.FileWriteTimeValid | cliprdr.FileSizeValid | cliprdr.FileShowProgress
		f.Flags |= 0x80000000 // FD_UNICODE
	}
	b, err := cliprdr.EncodeFileList(files)
	if err != nil {
		return nil, nil, err
	}
	return files, b, nil
}

// ensureDescriptors resolves lazy metadata exactly once. A resolution failure
// retires the offer immediately; the STA's deferred finish is then a no-op.
func (s *Offer) ensureDescriptors() error {
	if s.o.DescriptorsFunc == nil {
		return nil
	}
	s.resolveOnce.Do(func() {
		if err := s.ctx.Err(); err != nil {
			s.resolveErr = err
			return
		}
		fs, err := s.o.DescriptorsFunc(s.ctx)
		if err != nil {
			s.resolveErr = err
			return
		}
		files, b, err := prepareFiles(fs, s.read, s.o)
		if err != nil {
			s.resolveErr = err
			return
		}
		s.files, s.descriptors = files, b
	})
	if s.resolveErr != nil {
		s.finish(s.resolveErr)
		return s.resolveErr
	}
	return nil
}

// Close cancels reads immediately; Done waits for the actual native cleanup.
// Unlike plain byte clipboard data, virtual file streams are never flushed to
// the clipboard on shutdown. Provider contents are not retained in temporary files.
func (s *Offer) Close()                { s.cancel() }
func (s *Offer) Done() <-chan struct{} { return s.done }
func (s *Offer) Err() error            { s.mu.Lock(); defer s.mu.Unlock(); return s.err }

// Errors coalesces provider failures; caller-provided errors may contain details.
func (s *Offer) Errors() <-chan error { return s.errors }
func (s *Offer) report(err error) {
	if err != nil {
		select {
		case s.errors <- err:
		default:
		}
	}
}

// Operations reports native Shell copy outcomes for this publication, including
// success, failure and cancellation. It is bounded to four outcomes; when full,
// the oldest outcome is dropped. The channel closes at Done. Only retained
// offers (RetainOnChange) expose the async interface that produces outcomes;
// a synchronous consumer that never calls EndOperation reports nothing.
func (s *Offer) Operations() <-chan Operation { return s.operations }
func (s *Offer) reportOperation(op Operation) {
	if s.operations == nil {
		return
	}
	select {
	case s.operations <- op:
		return
	default:
	}
	select {
	case <-s.operations:
	default:
	}
	select {
	case s.operations <- op:
	default:
	}
}
func (s *Offer) finish(err error) {
	s.finishOnce.Do(func() { s.finishInner(err) })
}

func (s *Offer) finishInner(err error) {
	s.cancel()
	// Only the owning STA accesses these fields. Native references can outlive
	// it, but their callbacks reject cancellation before reading source state.
	s.read = nil
	s.files = nil
	s.descriptors = nil
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
	close(s.errors)
	if s.operations != nil {
		close(s.operations)
	}
	close(s.done)
}

func (s *Offer) chunk(ctx context.Context, index uint32, offset uint64, length uint32) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if int(index) >= len(s.files) || s.files[index].IsDirectory() || length > s.o.ChunkSize {
		return nil, ErrInvalid
	}
	f := s.files[index]
	if offset > f.Size || uint64(length) > f.Size-offset {
		return nil, ErrInvalid
	}
	if length == 0 {
		return []byte{}, nil
	}
	b, err := s.read(ctx, index, offset, length)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err == nil && len(b) != int(length) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		s.report(err)
		return nil, err
	}
	return b, nil
}

func seekPosition(position, size, move uint64, origin uint32) (uint64, bool) {
	if origin == 0 {
		return move, true
	}
	base := position
	if origin == 2 {
		base = size
	} else if origin != 1 {
		return 0, false
	}
	if int64(move) < 0 {
		delta := ^move + 1
		if delta > base {
			return 0, false
		}
		return base - delta, true
	}
	if move > ^uint64(0)-base {
		return 0, false
	}
	return base + move, true
}
