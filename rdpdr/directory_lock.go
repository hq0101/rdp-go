package rdpdr

import (
	"context"
	"errors"
	"fmt"
	"math"
)

type directoryLock struct {
	region    LockRegion
	exclusive bool
}

type directoryPendingLock struct {
	request Request
	ctx     context.Context
	lock    *LockRequest
}

func (d *DirectoryDrive) waitForLock(q *LockRequest) bool {
	if d.opts.WindowsLockFlagCompatibility {
		return !q.Wait
	}
	return q.Wait
}

func (d *DirectoryDrive) removePendingLock(i int) {
	copy(d.pendingLocks[i:], d.pendingLocks[i+1:])
	last := len(d.pendingLocks) - 1
	d.pendingLocks[last] = directoryPendingLock{}
	d.pendingLocks = d.pendingLocks[:last]
}

// DirectoryLockStatus accounts for held native locks and queued wait requests.
// Regions includes every acquisition, including overlapping/duplicate shared
// locks. QueuedRegions reserves capacity before retrying any OS operation.
type DirectoryLockStatus struct{ Regions, Pending, QueuedRegions int }

func (d *DirectoryDrive) LockStatus() DirectoryLockStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return DirectoryLockStatus{d.lockCount, len(d.pendingLocks), d.pendingLockRegions}
}

// Dispatch accepts a request and returns zero or more final wire completions.
// A contended waiting lock produces no completion until Poll/Dispatch can grant
// it or its context/FileID is canceled. Send ALL returned messages in order.
// Call Poll regularly (for example every 20ms) even without incoming messages,
// so locks released by independent local processes and cancellation progress.
// Serialize Dispatch, Poll and DriveClient access in the same event loop.
// File data I/O remains synchronous; AsyncIO must remain false. Windows
// directory notifications use bounded native pending operations. No per-watch
// worker goroutines or caller callbacks are started for normal dispatch.
func (d *DirectoryDrive) Dispatch(ctx context.Context, c *DriveClient, request Request) ([][]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	wire, err := d.handle(ctx, c, request, true)
	if err != nil {
		return nil, err
	}
	replies, err := d.pollPending(c)
	if err != nil {
		return nil, err
	}
	if len(wire) == 0 {
		return replies, nil
	}
	// Pending operations on a closed FileID complete before its CLOSE reply.
	if request.entry.header.MajorFunction == MajorClose {
		return append(replies, wire), nil
	}
	return append([][]byte{wire}, replies...), nil
}

// Poll retries waiting locks without blocking on a lock conflict. A canceled
// request completes with STATUS_CANCELLED. Reset/Remove-invalidated tokens are
// discarded without executing them; native notifications are canceled and
// drained. Close must precede Reset/Remove
// to release all held resources; a new connection requires a new backend.
func (d *DirectoryDrive) Poll(c *DriveClient) ([][]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.failure != nil {
		return nil, errors.Join(ErrFileHandle, d.failure)
	}
	return d.pollPending(c)
}

func (d *DirectoryDrive) pollLocks(c *DriveClient) ([][]byte, error) {
	if !c.initialized() {
		return nil, ErrRequest
	}
	// A wrong client must not consume or execute another connection's work.
	for _, p := range d.pendingLocks {
		if p.request.owner != c {
			return nil, ErrRequest
		}
	}
	var replies [][]byte
	for i := 0; i < len(d.pendingLocks); {
		p := d.pendingLocks[i]
		h := p.request.entry.header
		d.pendingLockRegions -= len(p.lock.Regions)
		if c.pending[requestKey{h.DeviceID, h.CompletionID}] != p.request.entry {
			d.removePendingLock(i)
			continue
		}
		status := uint32(StatusCancelled)
		if f := d.files[h.FileID]; f != nil && p.ctx.Err() == nil {
			var fatal error
			status, _, fatal = d.lock(f, p.lock)
			if fatal != nil {
				d.pendingLockRegions += len(p.lock.Regions)
				d.failure = errors.Join(d.failure, fatal)
				return nil, fatal
			}
			if status == StatusLockNotGranted {
				d.pendingLockRegions += len(p.lock.Regions)
				i++
				continue
			}
			if p.ctx.Err() != nil && status == 0 {
				// Only this attempt's new acquisitions are rolled back. Their
				// suffix may contain duplicate shared ranges already held before.
				if err := d.rollbackLocks(f, len(f.locks)-len(p.lock.Regions)); err != nil {
					d.pendingLockRegions += len(p.lock.Regions)
					d.failure = errors.Join(d.failure, err)
					return nil, err
				}
				status = StatusCancelled
			}
		}
		wire, err := c.CompleteFile(p.request, status, FileResult{})
		if err != nil {
			d.pendingLockRegions += len(p.lock.Regions)
			d.failure = errors.Join(d.failure, err)
			return nil, err
		}
		replies = append(replies, wire)
		d.removePendingLock(i)
	}
	return replies, nil
}

func (d *DirectoryDrive) queueLock(ctx context.Context, request Request, q *LockRequest) uint32 {
	if len(d.pendingLocks) >= d.opts.MaxPendingLocks || len(q.Regions) > d.opts.MaxLocks-d.lockCount-d.pendingLockRegions {
		return StatusInsufficientResources
	}
	d.pendingLocks = append(d.pendingLocks, directoryPendingLock{request, ctx, q})
	d.pendingLockRegions += len(q.Regions)
	return StatusPending
}

func (d *DirectoryDrive) lock(f *directoryFile, q *LockRequest) (uint32, FileResult, error) {
	empty := FileResult{}
	if q == nil || q.Operation < 2 || q.Operation > 5 || len(q.Regions) == 0 || len(q.Regions) > MaxFileLocks {
		return StatusInvalidParameter, empty, nil
	}
	for _, r := range q.Regions {
		if r.Offset > math.MaxInt64 || r.Length > math.MaxInt64-r.Offset {
			return StatusInvalidParameter, empty, nil
		}
	}
	if !directoryLockAvailable() {
		return StatusNotSupported, empty, nil
	}
	if f.info.IsDir() {
		return statusFileIsDirectory, empty, nil
	}
	if f.access&7 == 0 {
		return StatusAccessDenied, empty, nil
	}
	if q.Operation >= 4 {
		// Validate all exact acquisitions (and multiplicity) before unlock.
		// Exclusive-before-shared matches native exact-range unlock ordering.
		shadow := append([]directoryLock(nil), f.locks...)
		for _, r := range q.Regions {
			i := directoryFindLock(shadow, r)
			if i < 0 {
				return StatusRangeNotLocked, empty, nil
			}
			shadow = append(shadow[:i], shadow[i+1:]...)
		}
		for _, r := range q.Regions {
			i := directoryFindLock(f.locks, r)
			if s := directoryUnlockNative(f, r); s != 0 {
				return s, empty, fmt.Errorf("rdpdr: tracked unlock failed with status %08x", s)
			}
			f.locks = append(f.locks[:i], f.locks[i+1:]...)
			d.lockCount--
		}
		return 0, empty, nil
	}
	if len(q.Regions) > d.opts.MaxLocks-d.lockCount-d.pendingLockRegions {
		return StatusInsufficientResources, empty, nil
	}
	start := len(f.locks)
	for _, r := range q.Regions {
		s := directoryLockNative(f, r, q.Operation == 3)
		if s != 0 {
			return s, empty, d.rollbackLocks(f, start)
		}
		f.locks = append(f.locks, directoryLock{r, q.Operation == 3})
		d.lockCount++
	}
	return 0, empty, nil
}

func directoryFindLock(locks []directoryLock, r LockRegion) int {
	shared := -1
	for i, l := range locks {
		if l.region == r {
			if l.exclusive {
				return i
			}
			if shared < 0 {
				shared = i
			}
		}
	}
	return shared
}

// Roll back only this request's acquisitions. Failed releases remain charged
// and force teardown, where all native handles are still attempted once.
func (d *DirectoryDrive) rollbackLocks(f *directoryFile, start int) error {
	var failures []error
	for i := len(f.locks) - 1; i >= start; i-- {
		// Native unlock removes an exact-range exclusive acquisition before a
		// shared one. Do not accidentally remove a pre-existing exclusive lock
		// when rolling back a newer shared acquisition. Teardown will release
		// all locks, without reporting an ordinary recoverable lock failure.
		if start > 0 && directoryFindLock(f.locks, f.locks[i].region) < start && !f.locks[i].exclusive {
			old := directoryFindLock(f.locks, f.locks[i].region)
			if old >= 0 && f.locks[old].exclusive {
				failures = append(failures, errors.New("rdpdr: partial mixed-lock acquisition requires teardown"))
				continue
			}
		}
		if s := directoryUnlockNative(f, f.locks[i].region); s != 0 {
			failures = append(failures, fmt.Errorf("rdpdr: unlock cleanup status %08x", s))
			continue
		}
		f.locks = append(f.locks[:i], f.locks[i+1:]...)
		d.lockCount--
	}
	return errors.Join(failures...)
}
