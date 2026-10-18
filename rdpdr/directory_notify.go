package rdpdr

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
)

// A watcher stays attached to the opened directory identity between requests.
// The host retains intervening changes; overflow requests re-enumeration.
type directoryNativeWatch interface {
	start() uint32
	poll() (bool, []byte, uint32, error)
	cancel() error
	close() error
}
type directoryWatch struct {
	config NotifyRequest
	native directoryNativeWatch
}
type directoryPendingNotify struct {
	request Request
	ctx     context.Context
	watch   *directoryWatch
}

// DirectoryNotifyStatus counts retained watchers, not just outstanding requests.
// Watchers own one OS directory handle and one event on Windows hosts.
type DirectoryNotifyStatus struct{ Watches, Pending int }

func (d *DirectoryDrive) NotifyStatus() DirectoryNotifyStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return DirectoryNotifyStatus{d.watchCount, len(d.pendingNotifies)}
}

func (d *DirectoryDrive) closeWatch(f *directoryFile) error {
	if f.watch == nil {
		return nil
	}
	if err := f.watch.native.close(); err != nil {
		return err
	}
	f.watch = nil
	d.watchCount--
	return nil
}

func (d *DirectoryDrive) notify(ctx context.Context, c *DriveClient, request Request, q FileRequest, deferred bool) (reply []byte, failure error) {
	defer func() {
		if failure != nil {
			d.failure = errors.Join(d.failure, failure)
		}
	}()
	status := uint32(StatusSuccess)
	lease, err := d.handles.Acquire(d.device, q.Header.FileID)
	if err != nil {
		return c.CompleteFile(request, statusInvalidHandle, FileResult{})
	}
	defer lease.Release()
	f := lease.Resource().(*directoryFile)
	switch {
	case !f.info.IsDir():
		status = statusNotDirectory
	case f.access&1 == 0:
		status = StatusAccessDenied
	case q.Notify.Filter == 0:
		status = StatusInvalidParameter
	case q.Notify.Filter & ^uint32(0x17f) != 0:
		status = StatusNotSupported
	case !deferred:
		status = StatusNotSupported
	}
	if status != 0 {
		return c.CompleteFile(request, status, FileResult{})
	}
	for _, p := range d.pendingNotifies {
		if p.request.entry.header.FileID == q.Header.FileID {
			return c.CompleteFile(request, StatusInvalidParameter, FileResult{})
		}
	}
	if f.watch != nil && f.watch.config != *q.Notify {
		// Native registration fixes filter/tree semantics for the handle.
		return c.CompleteFile(request, StatusInvalidParameter, FileResult{})
	}
	if f.watch == nil {
		if d.watchCount == d.opts.MaxWatches {
			return c.CompleteFile(request, StatusInsufficientResources, FileResult{})
		}
		w, s := newDirectoryNativeWatch(f, *q.Notify)
		status = s
		if w != nil {
			f.watch = &directoryWatch{*q.Notify, w}
			d.watchCount++
		}
	}
	if status == 0 {
		status = f.watch.native.start()
	}
	if status != 0 {
		if err := d.closeWatch(f); err != nil {
			d.failure = errors.Join(d.failure, err)
			return nil, err
		}
		return c.CompleteFile(request, status, FileResult{})
	}
	d.pendingNotifies = append(d.pendingNotifies, directoryPendingNotify{request, ctx, f.watch})
	return nil, nil
}

func (d *DirectoryDrive) pollPending(c *DriveClient) ([][]byte, error) {
	if !c.initialized() {
		return nil, ErrRequest
	}
	// Check every pending owner before either subsystem touches host state.
	for _, p := range d.pendingNotifies {
		if p.request.owner != c {
			return nil, ErrRequest
		}
	}
	for _, p := range d.pendingLocks {
		if p.request.owner != c {
			return nil, ErrRequest
		}
	}
	a, err := d.pollLocks(c)
	if err != nil {
		return nil, err
	}
	b, err := d.pollNotifies(c)
	if err != nil {
		d.failure = errors.Join(d.failure, err)
		return nil, err
	}
	return append(a, b...), nil
}

func (d *DirectoryDrive) pollNotifies(c *DriveClient) ([][]byte, error) {
	var replies [][]byte
	for i := 0; i < len(d.pendingNotifies); {
		p := d.pendingNotifies[i]
		h := p.request.entry.header
		stale := c.pending[requestKey{h.DeviceID, h.CompletionID}] != p.request.entry
		f := d.files[h.FileID]
		closed := f == nil || f.watch != p.watch
		status := uint32(StatusCancelled)
		var data []byte
		if stale || closed || p.ctx.Err() != nil {
			if !closed {
				if err := p.watch.native.cancel(); err != nil {
					return nil, err
				}
			}
		} else {
			done, b, s, err := p.watch.native.poll()
			if err != nil {
				return nil, err
			}
			if !done {
				i++
				continue
			}
			status, data = s, b
			if p.ctx.Err() != nil {
				status = StatusCancelled
				data = nil
			}
		}
		if !stale {
			wire, err := c.CompleteFile(p.request, status, FileResult{Data: data})
			if err != nil {
				return nil, err
			}
			replies = append(replies, wire)
		}
		copy(d.pendingNotifies[i:], d.pendingNotifies[i+1:])
		last := len(d.pendingNotifies) - 1
		d.pendingNotifies[last] = directoryPendingNotify{}
		d.pendingNotifies = d.pendingNotifies[:last]
	}
	return replies, nil
}

// Native FILE_NOTIFY_INFORMATION is validated before being sent remotely.
// A partial rename pair or unusable batch means re-enumerate, never guess names.
func directoryNotifyData(b []byte) ([]byte, error) {
	var entries []NotificationEntry
	for len(b) > 0 {
		if len(b) < 12 || len(entries) >= MaxFileEntries {
			return nil, ErrProtocol
		}
		next, action, n := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint32(b[8:])
		if n == 0 || uint64(n) > uint64(len(b)-12) {
			return nil, ErrProtocol
		}
		name, err := decodeFileText(b[12:12+int(n)], false, false)
		if err != nil {
			return nil, err
		}
		// A notification is relative to the authorized directory, never an
		// absolute path, alternate stream or traversal instruction.
		if strings.ContainsAny(name, "/:\x00") {
			return nil, ErrProtocol
		}
		for _, part := range strings.Split(name, `\`) {
			if part == "" || part == "." || part == ".." {
				return nil, ErrProtocol
			}
		}
		entries = append(entries, NotificationEntry{action, name})
		end := 12 + int(n)
		if next == 0 {
			if len(b)-end > 3 {
				return nil, ErrProtocol
			}
			break
		}
		if next%4 != 0 || uint64(next) < uint64(end) || uint64(next) > uint64(len(b)-12) {
			return nil, ErrProtocol
		}
		b = b[next:]
	}
	if len(entries) == 0 {
		return nil, ErrProtocol
	}
	return EncodeNotifyInformation(entries)
}
