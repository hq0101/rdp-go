package cliprdr

import (
	"context"
	"io"
	"math"
	"sync"
)

// FileDownloadOptions bounds one file transfer. MaxSize is required: zero only
// permits an empty file. ChunkSize defaults to 256 KiB and Window to four. The
// window includes requests waiting for replies AND writes still in progress.
type FileDownloadOptions struct {
	MaxSize   uint64
	ChunkSize uint32
	Window    int
}

type FileDownloadStatus struct {
	SizeKnown       bool
	Size, Written   uint64
	PendingRequests int
	ActiveWrites    int
	Complete        bool
	Err             error
}

type downloadRange struct {
	offset uint64
	length uint32
}

// FileDownload receives one explicitly selected remote file. It never opens,
// truncates, closes, renames, or deletes a destination. Use a new, empty, private
// target; only publish it after Complete and any required flush/close succeed.
// Failure can leave partial bytes. Multiple downloads may share a remote set;
// the caller releases that set after all of them finish or are canceled.
//
// Next must run under the Client's caller-owned synchronization. Accept does
// potentially blocking I/O and must run OUTSIDE that lock. Status and Cancel
// may run concurrently with either method. Do not copy a FileDownload.
// Cancel all downloads on disconnect/reset before disposing their targets.
type FileDownload struct {
	mu      sync.Mutex
	set     FileSet
	index   uint32
	target  io.WriterAt
	options FileDownloadOptions
	pending map[uint32]FileContentsRequest
	retry   []downloadRange
	known   bool
	size    uint64
	next    uint64
	written uint64
	writing int
	err     error
}

// NewFileDownload validates a selected file without sending anything or doing
// I/O. Next first queries SIZE, even when the descriptor already has a size.
// The Client retains ownership/size checks and connection-wide request limits.
func (c *Client) NewFileDownload(set FileSet, index uint32, target io.WriterAt, options FileDownloadOptions) (*FileDownload, error) {
	s, err := c.remoteFileSet(set)
	if err != nil {
		return nil, err
	}
	if target == nil || options.MaxSize > math.MaxInt64 || index >= uint32(len(s.files)) || s.files[index].IsDirectory() {
		return nil, ErrFile
	}
	if options.ChunkSize == 0 {
		options.ChunkSize = 256 << 10
	}
	if options.Window == 0 {
		options.Window = 4
	}
	if options.Window < 1 || options.Window > MaxFileRequests || options.ChunkSize > MaxFileChunk || uint64(options.Window)*uint64(options.ChunkSize) > MaxFileRequestBytes {
		return nil, ErrFileLimit
	}
	if d := s.files[index]; d.Flags&FileSizeValid != 0 && d.Size > options.MaxSize {
		return nil, ErrFileLimit
	}
	return &FileDownload{set: set, index: index, target: target, options: options, pending: make(map[uint32]FileContentsRequest)}, nil
}

func (d *FileDownload) complete() bool {
	return d.err == nil && d.known && d.written == d.size && len(d.pending) == 0 && d.writing == 0 && len(d.retry) == 0
}

func (d *FileDownload) Status() FileDownloadStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return FileDownloadStatus{d.known, d.size, d.written, len(d.pending), d.writing, d.complete(), d.err}
}

func (d *FileDownload) fail(err error) error {
	if d.err == nil {
		d.err = err
		d.retry = nil
	}
	return d.err
}

// Cancel stops new requests and admission of new writes. A nil cause means
// context.Canceled. Already admitted WriteAt calls may still modify the target:
// wait for ActiveWrites == 0 before closing or discarding it. This method does
// not interrupt a blocking WriterAt. The caller owns its deadlines/cancellation.
// Keep feeding Client.Handle to drain issued requests, or close/reset the
// connection. Cancel does not release a shared FileSet or erase Client state.
func (d *FileDownload) Cancel(cause error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.complete() {
		return
	}
	if cause == nil {
		cause = context.Canceled
	}
	d.fail(cause)
}

// Next creates at most one PDU. Send it exactly once, in order, before calling
// Next again; a send failure requires canceling the task and retiring the
// transport. A nil PDU and nil error means complete or currently waiting for
// replies/writes/global request capacity. Retry after progress, not in a loop.
// Send/Next and all other Client operations must be serialized by the caller.
func (d *FileDownload) Next(c *Client) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	if d.complete() {
		return nil, nil
	}
	if d.target == nil || c.files == nil || d.set.owner != c.files {
		return nil, d.fail(ErrChanged)
	}
	if _, err := c.remoteFileSet(d.set); err != nil {
		return nil, d.fail(err)
	}
	if len(d.pending)+d.writing >= d.options.Window {
		return nil, nil
	}
	kind, offset, length := uint32(FileSizeRequest), uint64(0), uint32(8)
	if !d.known {
		if len(d.pending) != 0 {
			return nil, nil
		}
	} else {
		kind = FileRangeRequest
		if len(d.retry) != 0 {
			offset, length = d.retry[0].offset, d.retry[0].length
		} else {
			if d.next == d.size {
				return nil, nil
			}
			offset, length = d.next, uint32(min(uint64(d.options.ChunkSize), d.size-d.next))
		}
	}
	f := c.files
	if f.nextStream >= math.MaxUint32 {
		return nil, d.fail(ErrFileLimit)
	}
	if len(f.out) >= MaxFileRequests || f.outBytes+uint64(length) > MaxFileRequestBytes {
		return nil, nil
	}
	p, err := c.requestFile(d.set, d.index, kind, offset, length)
	if err != nil {
		return nil, d.fail(err)
	}
	r := f.out[uint32(f.nextStream)].request
	d.pending[r.StreamID] = r
	if d.known {
		if len(d.retry) != 0 {
			d.retry = d.retry[1:]
		} else {
			d.next += uint64(length)
		}
	}
	return p, nil
}

// Accept consumes a FileContentsResult produced by the same Client's Handle.
// Unrelated/already consumed events return handled=false without writing. Do
// not mutate event bytes during this call. Ranges can be accepted concurrently
// and out of order; target must support non-overlapping concurrent WriteAt.
//
// A positive short reply schedules its missing suffix after successful writing;
// an empty reply before the known EOF fails with io.ErrUnexpectedEOF. Short
// writes fail with io.ErrShortWrite and are never automatically retried. Written
// counts only fully completed writes, not bytes from a partially failed write.
func (d *FileDownload) Accept(event Event) (handled bool, err error) {
	d.mu.Lock()
	if event.Kind != FileContentsResult || event.FileResult == nil || event.FileResult.Set != d.set {
		d.mu.Unlock()
		return false, nil
	}
	r := event.FileResult
	want, ok := d.pending[r.Request.StreamID]
	if !ok {
		d.mu.Unlock()
		return false, nil
	}
	delete(d.pending, r.Request.StreamID)
	if d.err == nil {
		switch {
		case want != r.Request:
			d.fail(ErrProtocol)
		case event.Err != nil:
			d.fail(event.Err)
		case want.Flags == FileSizeRequest && r.Size > d.options.MaxSize:
			d.fail(ErrFileLimit)
		case want.Flags == FileRangeRequest && len(r.Data) == 0:
			d.fail(io.ErrUnexpectedEOF)
		case want.Flags == FileRangeRequest && uint64(len(r.Data)) > uint64(want.Length):
			d.fail(ErrProtocol)
		}
	}
	if d.err != nil {
		err = d.err
		d.mu.Unlock()
		return true, err
	}
	if want.Flags == FileSizeRequest {
		d.size, d.known = r.Size, true
		d.mu.Unlock()
		return true, nil
	}
	d.writing++
	d.mu.Unlock()

	n, writeErr := d.target.WriteAt(r.Data, int64(want.Offset))
	if n < 0 || n > len(r.Data) {
		writeErr = ErrFile
	} else if writeErr == nil && n != len(r.Data) {
		writeErr = io.ErrShortWrite
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.writing--
	if writeErr != nil {
		d.fail(writeErr)
	}
	if d.err != nil {
		return true, d.err
	}
	d.written += uint64(n)
	if uint32(n) < want.Length {
		d.retry = append(d.retry, downloadRange{want.Offset + uint64(n), want.Length - uint32(n)})
	}
	return true, nil
}
