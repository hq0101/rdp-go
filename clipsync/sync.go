// Package clipsync joins the cliprdr wire state machine to an explicit system
// clipboard host. It keeps native operations outside the protocol event loop.
package clipsync

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/hq0101/rdp-go/cliphost"
	"github.com/hq0101/rdp-go/clipole"
	"github.com/hq0101/rdp-go/cliprdr"
)

type Mode uint8

const (
	Off      Mode = 0
	ToRemote Mode = 1
	ToLocal  Mode = 2
	Both     Mode = ToRemote | ToLocal
)

func ParseMode(s string) (Mode, error) {
	switch s {
	case "off":
		return Off, nil
	case "both":
		return Both, nil
	case "to-remote":
		return ToRemote, nil
	case "to-local":
		return ToLocal, nil
	}
	return Off, ErrInvalid
}

var (
	ErrInvalid      = errors.New("clipsync: invalid configuration")
	ErrClosed       = errors.New("clipsync: stopped")
	ErrDrainTimeout = errors.New("clipsync: timed out draining a clipboard response")
)

// Host is implemented by cliphost.Host. Read/OfferIfCurrent must return when
// ctx is canceled, while Done must wait for actual native resource cleanup.
// Provider callbacks must execute outside Current's lock; keep Feed running.
type Host interface {
	Current() (cliphost.Snapshot, error)
	Changes() <-chan struct{}
	Errors() <-chan error
	Read(context.Context, cliphost.Token, cliprdr.Format) ([]byte, error)
	OfferIfCurrent(context.Context, cliphost.Token, []cliprdr.Format, cliphost.Provider) (cliphost.Token, error)
	Close()
	Done() <-chan struct{}
	Err() error
}

// FileHost optionally installs remote virtual files. Like OfferIfCurrent, ctx
// bounds installation only. The host owns a successful offer until replacement
// or Close, and must not read file content before a native consumer requests it.
type FileHost interface {
	Host
	OfferFilesIfCurrent(context.Context, cliphost.Token, []cliprdr.FileDescriptor, clipole.ReadFunc, clipole.Options) (cliphost.Token, error)
}

// RetainedFileHost optionally lets an application's file consumers survive a
// clipboard replacement. Host owns all successful leases and must cancel/join
// them on Close/Done, including a successful installation racing ctx expiry.
// The source remains owned until lease.Done; native consumers must not create
// unbounded references or retain more than cliprdr.MaxFileSets publications.
type RetainedFileHost interface {
	FileHost
	OfferRetainedFilesIfCurrent(context.Context, cliphost.Token, []cliprdr.FileDescriptor, clipole.ReadFunc, clipole.Options) (cliphost.Token, cliphost.FileLease, error)
}

// LocalFileHost optionally acquires external files selected by the user. It
// must honor token/ownership and the supplied aggregate limits; it must not read
// content until the returned readers are used. It transfers an immutable offer
// on success, with Release for all owned resources; on error it returns no owned
// resources. Acquisition may block in native I/O past cancellation. Sync.Done
// waits for it and for actual reader/Release completion, independently of Host.
type LocalFileHost interface {
	Host
	AcquireFileSource(context.Context, cliphost.Token, cliphost.FileSelectionOptions) (cliprdr.FileSourceOffer, error)
}

// FileOptions enables file transfer in one explicitly configured direction.
// Zero MaxTotalSize permits only empty files/directories. Each direction's
// quota covers its pending and retained groups, not just the latest copy.
// A file offer takes precedence over accompanying byte formats.
type FileOptions struct {
	MaxTotalSize uint64
	// DeferMetadata defers the remote file list, lock and unknown-size queries
	// until a native consumer first enumerates or reads the offered files. The
	// format skeleton is installed and acknowledged immediately; metadata is
	// fetched on demand through the offer's descriptor callback. A group that
	// is superseded before its first enumeration cannot resolve afterwards and
	// fails with ErrChanged. When false (default), metadata is fetched and
	// validated eagerly before installation, as before.
	DeferMetadata bool
}

type Options struct {
	Mode Mode
	// RemoteFiles is off when nil; requires ToLocal and a FileHost. By default
	// metadata is fetched and validated before native installation and its
	// format-list ACK; DeferMetadata instead installs the skeleton immediately
	// and fetches metadata on the first native enumeration. Contents are always
	// fetched on demand, in bounded ranges. With a RetainedFileHost and
	// negotiated remote locks, old native consumers survive a new copy.
	// The byte/file/set quotas include those retained publications. Options copy.
	// When the lease exposes Shell copy outcomes, FileOperations reports them.
	RemoteFiles *FileOptions
	// LocalFiles is off when nil; requires ToRemote and a LocalFileHost. Local
	// metadata/handles are acquired before publication, contents only on request.
	// Remote locks retain old sources until unlock or connection shutdown.
	LocalFiles *FileOptions
	// NativeTimeout defaults to five seconds. Writes default to three seconds.
	// DrainTimeout defaults to 15 seconds; if an untagged reply never arrives,
	// the connection must end rather than reuse the slot for a different read.
	NativeTimeout, WriteTimeout, DrainTimeout time.Duration
}

type packetInput struct {
	ctx    context.Context
	data   []byte
	result chan error
}
type renderRequest struct {
	ctx      context.Context
	epoch    *epoch
	format   cliprdr.Format
	reply    chan dataResult
	answered bool
}
type dataResult struct {
	data []byte
	err  error
}

// Sync owns its Host after New succeeds. Clipboard directions are session-wide,
// including while a viewer is unfocused. No content is read until requested.
// Stop the enclosing connection on a terminal error, not just this state machine.
type Sync struct {
	ctx       context.Context
	cancel    context.CancelFunc
	host      Host
	write     func(context.Context, []byte) error
	o         Options
	packets   chan packetInput
	renders   chan *renderRequest
	fileReads chan *fileReadRequest
	fileMeta  chan *fileMetaRequest
	fileOps   chan fileOpEvent
	errors    chan error
	done      chan struct{}
	mu        sync.Mutex
	err       error
	status    cliprdr.Status

	fileOperations chan FileOperation
}

// New starts one clipboard coordinator. write sends a complete CLIPRDR message
// through the session's channel writer and must honor its context deadline.
// After success the caller must keep feeding that channel until shutdown.
func New(ctx context.Context, host Host, write func(context.Context, []byte) error, o Options) (*Sync, error) {
	if ctx == nil || host == nil || write == nil || o.Mode == Off || o.Mode > Both {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if o.RemoteFiles != nil {
		if _, ok := host.(FileHost); !ok || o.Mode&ToLocal == 0 || o.RemoteFiles.MaxTotalSize > math.MaxInt64 {
			return nil, ErrInvalid
		}
		files := *o.RemoteFiles
		o.RemoteFiles = &files
	}
	if o.LocalFiles != nil {
		if _, ok := host.(LocalFileHost); !ok || o.Mode&ToRemote == 0 || o.LocalFiles.MaxTotalSize > math.MaxInt64 {
			return nil, ErrInvalid
		}
		files := *o.LocalFiles
		o.LocalFiles = &files
	}
	if o.NativeTimeout == 0 {
		o.NativeTimeout = 5 * time.Second
	}
	if o.WriteTimeout == 0 {
		o.WriteTimeout = 3 * time.Second
	}
	if o.DrainTimeout == 0 {
		o.DrainTimeout = 15 * time.Second
	}
	for _, d := range []time.Duration{o.NativeTimeout, o.WriteTimeout, o.DrainTimeout} {
		if d < 10*time.Millisecond || d > time.Minute {
			return nil, ErrInvalid
		}
	}
	c, cancel := context.WithCancel(ctx)
	s := &Sync{ctx: c, cancel: cancel, host: host, write: write, o: o, packets: make(chan packetInput), renders: make(chan *renderRequest), fileReads: make(chan *fileReadRequest), errors: make(chan error, 1), done: make(chan struct{})}
	if o.RemoteFiles != nil {
		s.fileMeta = make(chan *fileMetaRequest)
		s.fileOps = make(chan fileOpEvent, 8)
		s.fileOperations = make(chan FileOperation, 8)
	}
	go s.run()
	return s, nil
}

// Feed consumes one session-owned, decompressed virtual-channel chunk. Do not
// mutate chunk before return. Feed performs no native clipboard calls. A write
// error or protocol error is terminal, including uncertain partial writes.
func (s *Sync) Feed(ctx context.Context, chunk []byte) error {
	if ctx == nil {
		return ErrInvalid
	}
	p := packetInput{ctx, chunk, make(chan error, 1)}
	select {
	case <-s.ctx.Done():
		return ErrClosed
	default:
	}
	select {
	case s.packets <- p:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return ErrClosed
	}
	// Once accepted, consumption must be observed even if caller cancellation
	// races it. Returning early would allow mutation of chunk during decoding.
	return <-p.result
}
func (s *Sync) Close()                    { s.cancel() }
func (s *Sync) Stopping() <-chan struct{} { return s.ctx.Done() }
func (s *Sync) Done() <-chan struct{}     { return s.done }
func (s *Sync) Err() error                { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *Sync) Status() cliprdr.Status    { s.mu.Lock(); defer s.mu.Unlock(); return s.status }
func (s *Sync) Errors() <-chan error      { return s.errors }
func (s *Sync) report(err error) {
	if err != nil {
		select {
		case s.errors <- err:
		default:
		}
	}
}

func (s *Sync) request(ctx context.Context, e *epoch, f cliprdr.Format) ([]byte, error) {
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(e.ctx, cancel)
	defer stop()
	r := &renderRequest{ctx: c, epoch: e, format: f, reply: make(chan dataResult, 1)}
	select {
	case s.renders <- r:
	case <-c.Done():
		return nil, c.Err()
	case <-s.ctx.Done():
		return nil, ErrClosed
	}
	select {
	case v := <-r.reply:
		return v.data, v.err
	case <-c.Done():
		return nil, c.Err()
	case <-s.ctx.Done():
		return nil, ErrClosed
	}
}

func (r *renderRequest) finish(data []byte, err error) {
	if r == nil || r.answered {
		return
	}
	r.answered = true
	if r.ctx.Err() != nil {
		data, err = nil, r.ctx.Err()
	}
	r.reply <- dataResult{data, err}
}

type epoch struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (s *Sync) epoch() *epoch { c, cancel := context.WithCancel(s.ctx); return &epoch{c, cancel} }
