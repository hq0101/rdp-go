package cliprdr

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
)

// FileSourceOptions bounds all registered groups together, including retired
// groups with active readers, running cleanup, or failed cleanup. Zero bytes
// permits only empty files. Zero set/file counts choose 8/1024 respectively.
type FileSourceOptions struct {
	MaxTotalSize      uint64
	MaxSets, MaxFiles int
}

// FileSourceOffer pairs descriptors with explicitly selected immutable sources.
// Readers uses the same indices as Files; directories must have nil readers.
// Empty files may have nil readers. No path is opened or copied by this API.
// Release, if supplied, closes/removes the group's owned resources. It runs at
// most once, outside all library locks, only through Collect. On Publish error
// ownership stays with the caller and Release is NOT called. Do not independently
// close, mutate, or share owned resources with another group after success.
type FileSourceOffer struct {
	Files      []FileDescriptor
	Readers    []io.ReaderAt
	Additional []Data
	Release    func() error
}

type FileSourceStatus struct {
	Sets, Files, Retired, Releasing, Failed, Reads int
	Bytes, ReadBytes                               uint64
	Stopped                                        bool
}

// FileSources manages the application sources behind one Client's file offers.
// Create after EnableFileStreaming. The constructor, Publish, Acquire, and
// Reconcile inspect the Client, so callers MUST hold their usual Client lock.
// All other methods synchronize internally and never inspect Client state.
//
// Reconcile after every Handle, Publish (including text/rich offers), and
// CompleteFileRequest. Collect performs cleanup separately, outside the Client
// lock. A typical application notifies a cleanup worker after reconciliation.
// On connection shutdown, stop admission with Retire, cancel/finish every read,
// then Collect. ReaderAt and Release may block; the application owns their I/O
// deadlines and worker lifetime. This type never starts goroutines or timers,
// never modifies the system clipboard, and must not be copied.
type FileSources struct {
	mu               sync.Mutex
	client           *Client
	owner            *fileState
	options          FileSourceOptions
	groups           map[FileSet]*sourceGroup
	used             map[FileRequestToken]*FileSourceRead
	files, reads     int
	bytes, readBytes uint64
	stopped          bool
}

type sourceGroup struct {
	readers                    []io.ReaderAt
	sizes                      []uint64
	bytes                      uint64
	release                    func() error
	active                     int
	retired, releasing, failed bool
	err                        error
}

func NewFileSources(c *Client, options FileSourceOptions) (*FileSources, error) {
	if c == nil || c.files == nil {
		return nil, ErrNotReady
	}
	if options.MaxSets == 0 {
		options.MaxSets = MaxFileSets
	}
	if options.MaxFiles == 0 {
		options.MaxFiles = MaxFiles
	}
	if options.MaxSets < 1 || options.MaxSets > MaxFileSets || options.MaxFiles < 1 || options.MaxFiles > MaxFileSets*MaxFiles || options.MaxTotalSize > math.MaxInt64 {
		return nil, ErrFileLimit
	}
	return &FileSources{client: c, owner: c.files, options: options, groups: make(map[FileSet]*sourceGroup), used: make(map[FileRequestToken]*FileSourceRead)}, nil
}

// Publish validates sources, portable relative names and aggregate budgets
// before advancing the Client. All regular sizes must be known. Send the
// returned PDU in order; a send failure requires terminating this connection,
// then retiring/collecting its sources. Wait for OfferResult before reporting
// that the remote accepted the offer. Publication does not prove a remote paste.
func (s *FileSources) Publish(formatID uint32, offer FileSourceOffer) ([]byte, FileSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcileLocked()
	if s.stopped {
		return nil, FileSet{}, ErrChanged
	}
	if len(offer.Files) == 0 || len(offer.Files) != len(offer.Readers) {
		return nil, FileSet{}, ErrFile
	}
	if len(s.groups) >= s.options.MaxSets || len(offer.Files) > s.options.MaxFiles-s.files {
		return nil, FileSet{}, ErrFileLimit
	}
	plan, err := planFiles(FileSet{}, offer.Files, FilePlanOptions{MaxFileSize: s.options.MaxTotalSize, MaxTotalSize: s.options.MaxTotalSize - s.bytes})
	if err != nil {
		return nil, FileSet{}, err
	}
	for i, d := range offer.Files {
		if d.IsDirectory() {
			if offer.Readers[i] != nil {
				return nil, FileSet{}, ErrFile
			}
		} else if d.Size != 0 && offer.Readers[i] == nil {
			return nil, FileSet{}, ErrFile
		}
	}
	packet, set, err := s.client.PublishFiles(formatID, offer.Files, offer.Additional)
	if err != nil {
		return nil, FileSet{}, err
	}
	g := &sourceGroup{readers: append([]io.ReaderAt(nil), offer.Readers...), sizes: make([]uint64, len(offer.Files)), bytes: plan.TotalSize(), release: offer.Release}
	for i, d := range offer.Files {
		g.sizes[i] = d.Size
	}
	s.groups[set] = g
	s.files += len(offer.Files)
	s.bytes += g.bytes
	s.reconcileLocked()
	return packet, set, nil
}

// Reconcile only changes retention bookkeeping; it never runs I/O or Release.
// Reset permanently retires this manager. Use a new manager for a new Client
// generation, even when resetting and reusing the same Client pointer.
func (s *FileSources) Reconcile() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcileLocked()
}

func (s *FileSources) reconcileLocked() {
	if s.client.files != s.owner {
		s.retireLocked()
		clear(s.used)
		return
	}
	for key, g := range s.groups {
		if _, ok := s.owner.local[key.id]; !ok {
			g.retired = true
		}
	}
	pending := make(map[FileRequestToken]bool, len(s.owner.in))
	for _, r := range s.owner.in {
		pending[r.token] = true
	}
	for token := range s.used {
		if !pending[token] {
			delete(s.used, token)
		}
	}
}

// Acquire accepts exactly one still-pending FileContentsNeeded from this
// Client, checking the opaque token, set and all request fields. Acquire each
// event once while holding the Client lock, then Read outside that lock and
// pass its data/error to CompleteFileRequest under the lock. If work cannot
// start, Close the acquired read and explicitly fail the protocol request.
func (s *FileSources) Acquire(request FileRequest) (*FileSourceRead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcileLocked()
	if s.stopped || request.Token.owner != s.owner || request.Set.owner != s.owner || request.Set.remote {
		return nil, ErrChanged
	}
	r := s.owner.in[request.Request.StreamID]
	if r == nil || r.token != request.Token || r.set.key != request.Set || r.request != request.Request {
		return nil, ErrChanged
	}
	g := s.groups[request.Set]
	if g == nil || g.retired || g.releasing || g.failed {
		return nil, ErrChanged
	}
	if _, ok := s.used[request.Token]; ok {
		return nil, ErrBusy
	}
	if s.reads >= MaxFileRequests || uint64(request.Request.Length) > MaxFileRequestBytes-s.readBytes {
		return nil, ErrFileLimit
	}
	read := &FileSourceRead{store: s, group: g, request: request.Request}
	g.active++
	s.reads++
	s.readBytes += uint64(request.Request.Length)
	s.used[request.Token] = read
	return read, nil
}

// Retire permanently prevents new offers/reads and retires all groups. It is
// nonblocking and does not close resources beneath running ReaderAt calls.
// Only use for connection shutdown, after stopping protocol admission; normal
// clipboard ownership changes must use Reconcile so remote locks are respected.
func (s *FileSources) Retire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retireLocked()
}
func (s *FileSources) retireLocked() {
	s.stopped = true
	for _, g := range s.groups {
		g.retired = true
	}
}

// Collect calls each eligible group's Release once, outside all store locks.
// Never call while holding the Client lock. A group is eligible only after it
// is retired AND every acquired read has returned or been closed before use.
// Concurrent Collect calls cannot release the same group twice. Failed cleanup
// retains its quota and error; subsequent Collect calls report that error but
// do not retry a potentially non-idempotent Release. The application must
// report/handle failure and may not assume resources were removed.
func (s *FileSources) Collect() error {
	for {
		s.mu.Lock()
		var key FileSet
		var group *sourceGroup
		for k, g := range s.groups {
			if g.retired && g.active == 0 && !g.releasing && !g.failed {
				key, group = k, g
				break
			}
		}
		if group == nil {
			var result error
			for _, g := range s.groups {
				result = errors.Join(result, g.err)
			}
			s.mu.Unlock()
			return result
		}
		group.releasing = true
		release := group.release
		s.mu.Unlock()
		var err error
		if release != nil {
			err = release()
		}
		s.mu.Lock()
		group.releasing = false
		group.release = nil
		if err != nil {
			group.failed = true
			group.err = err
		} else {
			s.files -= len(group.readers)
			s.bytes -= group.bytes
			group.readers = nil
			delete(s.groups, key)
		}
		s.mu.Unlock()
	}
}

func (s *FileSources) Status() FileSourceStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := FileSourceStatus{Sets: len(s.groups), Files: s.files, Bytes: s.bytes, Reads: s.reads, ReadBytes: s.readBytes, Stopped: s.stopped}
	for _, g := range s.groups {
		if g.retired {
			st.Retired++
		}
		if g.releasing {
			st.Releasing++
		}
		if g.failed {
			st.Failed++
		}
	}
	return st
}

// FileSourceRead is a single-use lease; it must not be copied. Read can block in
// ReaderAt; context cancellation/Close cannot interrupt arbitrary ReaderAt I/O.
// They discard its eventual result and prevent new work. Cleanup cannot run
// until that I/O actually returns. Close unused leases to avoid retaining them.
type FileSourceRead struct {
	store     *FileSources
	group     *sourceGroup
	request   FileContentsRequest
	state     uint8 // 0 acquired, 1 reading, 2 finished; protected by store.mu
	cancelled bool
}

func (r *FileSourceRead) finishLocked() {
	r.state = 2
	r.group.active--
	r.store.reads--
	r.store.readBytes -= uint64(r.request.Length)
}

// Read never inspects Client state. Source changes, early EOF and read errors
// produce no partial data. SIZE and empty RANGE requests do not call ReaderAt.
func (r *FileSourceRead) Read(ctx context.Context) ([]byte, error) {
	s := r.store
	s.mu.Lock()
	if r.state != 0 {
		s.mu.Unlock()
		return nil, ErrBusy
	}
	var err error
	if ctx == nil {
		err = ErrFile
	} else {
		err = ctx.Err()
	}
	if err == nil && (s.stopped || r.group.retired) {
		err = ErrChanged
	}
	if err != nil {
		r.finishLocked()
		s.mu.Unlock()
		return nil, err
	}
	r.state = 1
	source, size := r.group.readers[r.request.Index], r.group.sizes[r.request.Index]
	s.mu.Unlock()
	data, err := ReadFileContents(source, size, r.request)
	s.mu.Lock()
	if ctx.Err() != nil {
		err = ctx.Err()
	} else if r.cancelled {
		err = context.Canceled
	} else if s.stopped || r.group.retired {
		err = ErrChanged
	}
	r.finishLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Close cancels an unused or running lease without touching protocol state.
// The caller must still complete/fail its request or terminate the connection.
func (r *FileSourceRead) Close() error {
	s := r.store
	s.mu.Lock()
	defer s.mu.Unlock()
	r.cancelled = true
	if r.state == 0 {
		r.finishLocked()
	}
	return nil
}
