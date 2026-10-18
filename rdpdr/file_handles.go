package rdpdr

import (
	"context"
	"errors"
	"sync"
)

var ErrFileHandle = errors.New("rdpdr: invalid, retired or consumed file handle token")

type FileHandleLimits struct {
	// Zero selects 128 of each. Opening, retiring and failed-close resources
	// consume Handles until released. Uses bounds all outstanding leases.
	Handles, Uses int
}

type fileHandleEntry struct {
	device, id               uint32
	ctx                      context.Context
	cancel                   context.CancelFunc
	opening, retired, failed bool
	uses                     int
	resource                 any
	closing                  *fileCloseAttempt
}

type fileCloseAttempt struct {
	entry    *fileHandleEntry
	resource any
}

// FileHandles is a bounded, concurrent resource registry for one connection.
// It performs no filesystem operations, invokes no backend methods and starts
// no goroutines. Use NewFileHandles and do not copy it. Reserve BEFORE opening;
// CompleteOpen transfers a successful resource even if Stop raced with open.
// Retire/Stop cancel contexts; they cannot forcibly stop backend I/O. Callers
// must finish opening work, release every lease, and drive NextClose /
// CompleteClose until Status().Total == 0 before discarding the registry.
// File IDs are never reused in a registry. A new connection needs a new registry
// after all old work is drained; never route old requests to the new registry.
// Coordinate wire completions with device/connection retirement: Ready is a
// point-in-time result, not a promise that a later concurrent Stop cannot occur.
// DriveClient still requires its own serialization; this is not a dispatcher.
type FileHandles struct {
	mu      sync.Mutex
	limits  FileHandleLimits
	entries map[uint32]*fileHandleEntry
	nextID  uint64
	uses    int
	stopped bool
}

func NewFileHandles(limits FileHandleLimits) (*FileHandles, error) {
	if limits.Handles == 0 {
		limits.Handles = 128
	}
	if limits.Uses == 0 {
		limits.Uses = 128
	}
	if limits.Handles < 1 || limits.Handles > 4096 || limits.Uses < 1 || limits.Uses > 4096 {
		return nil, ErrLimit
	}
	return &FileHandles{limits: limits, entries: make(map[uint32]*fileHandleEntry), nextID: 1}, nil
}

// FileOpen is a single-use reservation, bound to its registry and entry.
type FileOpen struct {
	owner *FileHandles
	entry *fileHandleEntry
}

// Context is canceled by retirement or Stop. A zero token has no context.
func (o FileOpen) Context() context.Context {
	if o.entry == nil {
		return nil
	}
	return o.entry.ctx
}

func (h *FileHandles) Reserve(deviceID uint32) (FileOpen, error) {
	if h == nil {
		return FileOpen{}, ErrFileHandle
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.entries == nil || h.stopped {
		return FileOpen{}, ErrFileHandle
	}
	if len(h.entries) >= h.limits.Handles || h.nextID > 0xffffffff {
		return FileOpen{}, ErrLimit
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &fileHandleEntry{device: deviceID, id: uint32(h.nextID), ctx: ctx, cancel: cancel, opening: true}
	h.nextID++
	h.entries[e.id] = e
	return FileOpen{h, e}, nil
}

type FileOpenResult struct {
	ID uint32
	// Ready alone permits publication in a successful CREATE reply. If false,
	// any transferred resource will be returned by NextClose for cleanup.
	Ready bool
}

// CompleteOpen consumes a reservation. Pass nil when open failed (no resource
// to release); typed nil values count as resources and must not be passed.
// On nil error, ownership of a non-nil resource transfers even if Ready=false.
// On error no ownership transfers: the caller must dispose of its resource.
func (h *FileHandles) CompleteOpen(o FileOpen, resource any) (FileOpenResult, error) {
	if h == nil {
		return FileOpenResult{}, ErrFileHandle
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e := o.entry
	if o.owner != h || e == nil || h.entries[e.id] != e || !e.opening {
		return FileOpenResult{}, ErrFileHandle
	}
	e.opening = false
	if resource == nil {
		e.cancel()
		delete(h.entries, e.id)
		return FileOpenResult{}, nil
	}
	e.resource = resource
	return FileOpenResult{ID: e.id, Ready: !e.retired}, nil
}

// FileLease keeps a resource alive until Release. Copies share a release token.
// Do not use its resource after release; all backend work must finish first.
// A lease context signals retirement, not completion of backend operations.
type FileLease struct {
	state *fileLeaseState
}

type fileLeaseState struct {
	owner    *FileHandles
	entry    *fileHandleEntry
	resource any
	released bool // protected by owner.mu
}

func (l *FileLease) Resource() any {
	if l == nil || l.state == nil {
		return nil
	}
	return l.state.resource
}
func (l *FileLease) Context() context.Context {
	if l == nil || l.state == nil {
		return nil
	}
	return l.state.entry.ctx
}

func (h *FileHandles) Acquire(deviceID, fileID uint32) (*FileLease, error) {
	if h == nil {
		return nil, ErrFileHandle
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.entries[fileID]
	if e == nil || e.device != deviceID || e.opening || e.retired {
		return nil, ErrFileHandle
	}
	if h.uses >= h.limits.Uses {
		return nil, ErrLimit
	}
	h.uses++
	e.uses++
	return &FileLease{state: &fileLeaseState{owner: h, entry: e, resource: e.resource}}, nil
}

// Release is idempotent, including concurrent calls on the same lease pointer.
func (l *FileLease) Release() {
	if l == nil || l.state == nil {
		return
	}
	s := l.state
	h := s.owner
	h.mu.Lock()
	defer h.mu.Unlock()
	if s.released {
		return
	}
	s.released = true
	s.entry.uses--
	h.uses--
}

// Retire makes a handle inaccessible and cancels its work context. Repeated
// retirement before final cleanup is harmless. It does not physically close.
// Send a successful CLOSE completion only after backend close has succeeded.
func (h *FileHandles) Retire(deviceID, fileID uint32) error {
	if h == nil {
		return ErrFileHandle
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.entries[fileID]
	if e == nil || e.device != deviceID {
		return ErrFileHandle
	}
	e.retired = true
	e.cancel()
	return nil
}

// RetireDevice also cancels in-progress opens. The caller must prevent new
// Reserve calls for removed devices; only Stop prohibits all future opens.
func (h *FileHandles) RetireDevice(deviceID uint32) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.entries {
		if e.device == deviceID {
			e.retired = true
			e.cancel()
		}
	}
}

// Stop is terminal and idempotent. Continue draining opens, leases and closes.
func (h *FileHandles) Stop() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopped = true
	for _, e := range h.entries {
		e.retired = true
		e.cancel()
	}
}

// FileClose is an opaque, single-use close job. Execute the backend's release
// operation outside registry/protocol locks, then call CompleteClose exactly
// once. Copies share the same attempt identity and cannot complete a retry.
type FileClose struct {
	owner   *FileHandles
	attempt *fileCloseAttempt
}

func (c FileClose) Resource() any {
	if c.attempt == nil {
		return nil
	}
	return c.attempt.resource
}
func (c FileClose) IDs() (deviceID, fileID uint32) {
	if c.attempt == nil {
		return 0, 0
	}
	return c.attempt.entry.device, c.attempt.entry.id
}

func (h *FileHandles) NextClose() (FileClose, bool) {
	if h == nil {
		return FileClose{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.entries {
		if e.retired && !e.opening && e.uses == 0 && e.closing == nil && !e.failed {
			a := &fileCloseAttempt{e, e.resource}
			e.closing = a
			return FileClose{h, a}, true
		}
	}
	return FileClose{}, false
}

// CompleteClose releases capacity only when closeErr is nil. On failure the
// resource stays charged and is NOT retried automatically. Retain the job's
// resource for backend-specific recovery; the registry does not retain errors.
func (h *FileHandles) CompleteClose(c FileClose, closeErr error) error {
	if h == nil {
		return ErrFileHandle
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if c.owner != h || c.attempt == nil {
		return ErrFileHandle
	}
	e := c.attempt.entry
	if h.entries[e.id] != e || e.closing != c.attempt {
		return ErrFileHandle
	}
	e.closing = nil
	if closeErr != nil {
		e.failed = true
		return nil
	}
	e.resource = nil
	delete(h.entries, e.id)
	return nil
}

// RetryClose enables a fresh job after failure. The caller must first establish
// that another backend release is safe: many OS close operations are NOT
// retryable even when they report an error. It can instead use the fresh job
// to report confirmed release after backend-specific recovery.
func (h *FileHandles) RetryClose(deviceID, fileID uint32) error {
	if h == nil {
		return ErrFileHandle
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.entries[fileID]
	if e == nil || e.device != deviceID || !e.failed {
		return ErrFileHandle
	}
	e.failed = false
	return nil
}

type FileHandleStatus struct {
	Stopped                                              bool
	Total, Opening, Live, Retired, Uses, Closing, Failed int
}

// Opening and Retired can overlap while a canceled open is still running.
// Closing/Failed are subsets of Retired. Total counts every charged resource.
func (h *FileHandles) Status() FileHandleStatus {
	if h == nil {
		return FileHandleStatus{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s := FileHandleStatus{Stopped: h.stopped, Total: len(h.entries), Uses: h.uses}
	for _, e := range h.entries {
		if e.opening {
			s.Opening++
		}
		if e.retired {
			s.Retired++
		} else if !e.opening {
			s.Live++
		}
		if e.closing != nil {
			s.Closing++
		}
		if e.failed {
			s.Failed++
		}
	}
	return s
}
