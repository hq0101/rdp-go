package clipsync

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/hq0101/rdp-go/cliphost"
	"github.com/hq0101/rdp-go/cliprdr"
)

type remoteFiles struct {
	set                       cliprdr.FileSet
	haveSet, requested, ready bool
	descriptors               []cliprdr.FileDescriptor
	next, sizes               int
	deadline                  time.Time
	locked                    bool
	lease                     cliphost.FileLease
	bytes                     uint64
	lazy, wantMeta            bool
	meta                      *fileMetaRequest
}

type fileMetaRequest struct {
	ctx      context.Context
	epoch    *epoch
	reply    chan metaResult
	answered bool
}

type metaResult struct {
	files []cliprdr.FileDescriptor
	err   error
}

func (r *fileMetaRequest) finish(files []cliprdr.FileDescriptor, err error) {
	if r == nil || r.answered {
		return
	}
	r.answered = true
	if r.ctx.Err() != nil {
		files, err = nil, r.ctx.Err()
	}
	r.reply <- metaResult{files, err}
}

type fileReadRequest struct {
	ctx      context.Context
	epoch    *epoch
	index    uint32
	offset   uint64
	length   uint32
	reply    chan dataResult
	answered bool
}

type fileOperation struct {
	epoch    *epoch
	read     *fileReadRequest // nil for a size query
	index    uint32
	deadline time.Time
}

func hasFiles(fs []cliprdr.Format) bool {
	for _, f := range fs {
		if f.Name == cliprdr.FileGroupDescriptorName {
			return true
		}
	}
	return false
}

func (s *Sync) requestFile(ctx context.Context, e *epoch, index uint32, offset uint64, length uint32) ([]byte, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(e.ctx, cancel)
	defer stop()
	r := &fileReadRequest{ctx: c, epoch: e, index: index, offset: offset, length: length, reply: make(chan dataResult, 1)}
	select {
	case s.fileReads <- r:
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

// requestMeta resolves a lazy offer's descriptors on demand. It mirrors
// requestFile: the calling native consumer blocks while the loop drives the
// wire list/size round-trips, so reception must stay on another thread.
func (s *Sync) requestMeta(ctx context.Context, e *epoch) ([]cliprdr.FileDescriptor, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(e.ctx, cancel)
	defer stop()
	r := &fileMetaRequest{ctx: c, epoch: e, reply: make(chan metaResult, 1)}
	select {
	case s.fileMeta <- r:
	case <-c.Done():
		return nil, c.Err()
	case <-s.ctx.Done():
		return nil, ErrClosed
	}
	select {
	case v := <-r.reply:
		return v.files, v.err
	case <-c.Done():
		return nil, c.Err()
	case <-s.ctx.Done():
		return nil, ErrClosed
	}
}

func (r *fileReadRequest) finish(data []byte, err error) {
	if r == nil || r.answered {
		return
	}
	r.answered = true
	if r.ctx.Err() != nil {
		data, err = nil, r.ctx.Err()
	}
	r.reply <- dataResult{data, err}
}

func (st *state) releaseFiles(r *remoteItem) error {
	for _, op := range st.filePending {
		if op.epoch == r.epoch {
			op.read.finish(nil, cliprdr.ErrChanged)
		}
	}
	if r.files == nil {
		return nil
	}
	r.files.meta.finish(nil, cliprdr.ErrChanged)
	if !r.files.haveSet {
		return nil
	}
	p, err := st.client.ReleaseRemoteFiles(r.files.set)
	r.files.haveSet = false
	if errors.Is(err, cliprdr.ErrChanged) {
		return nil
	}
	if err != nil {
		return err
	}
	return st.send(p...)
}

func (st *state) fileList(e cliprdr.Event) error {
	if st.active == nil || st.active.fileEpoch == nil {
		return cliprdr.ErrProtocol
	}
	epoch := st.active.fileEpoch
	st.active = nil
	if st.remote == nil || st.remote.epoch != epoch || epoch.ctx.Err() != nil {
		// A stale version normally has already produced its UNLOCK in Handle.
		// A local ownership change alone does not change the wire version.
		if e.Files != nil {
			p, err := st.client.ReleaseRemoteFiles(e.Files.Set)
			if err != nil {
				return err
			}
			return st.send(p...)
		}
		return nil
	}
	if e.Err != nil {
		return st.rejectRemote(e.Err)
	}
	if e.Files == nil || st.remote.files == nil {
		return cliprdr.ErrProtocol
	}
	f := st.remote.files
	f.set, f.haveSet = e.Files.Set, true
	f.locked = e.Files.Locked
	f.descriptors = append([]cliprdr.FileDescriptor(nil), e.Files.Descriptors...)
	// Validate paths, collisions and known aggregate sizes before querying any
	// missing sizes. Unknown files count as zero only for this preflight.
	preflight := append([]cliprdr.FileDescriptor(nil), f.descriptors...)
	for i := range preflight {
		if preflight[i].Flags&cliprdr.FileSizeValid == 0 {
			preflight[i].Flags |= cliprdr.FileSizeValid
			preflight[i].Size = 0
		}
	}
	limit, availableFiles := st.fileBudget()
	if len(f.descriptors) > availableFiles {
		return st.rejectRemote(cliprdr.ErrFileLimit)
	}
	if _, err := cliprdr.PlanFileOffer(preflight, cliprdr.FilePlanOptions{MaxFileSize: limit, MaxTotalSize: limit}); err != nil {
		return st.rejectRemote(err)
	}
	return nil
}

func (st *state) trackFile(p []byte, op *fileOperation) error {
	// RequestFileSize/Range return a validated complete FileContentsRequest.
	id := binary.LittleEndian.Uint32(p[8:])
	st.filePending[id] = op
	return st.send(p) // any uncertain write is terminal, never retried
}

func (st *state) driveFiles(now time.Time) error {
	if err := st.collectFileLeases(); err != nil {
		return err
	}
	for _, op := range st.filePending {
		if op.read != nil && op.read.ctx.Err() != nil {
			op.read.finish(nil, op.read.ctx.Err())
		}
		if !now.Before(op.deadline) {
			return ErrDrainTimeout
		}
	}
	r := st.remote
	if r == nil || r.files == nil || r.files.ready {
		return nil
	}
	f := r.files
	if f.lazy && !f.wantMeta {
		return nil // fully delayed: nothing fetched until a consumer asks
	}
	if !now.Before(f.deadline) {
		return st.rejectRemote(context.DeadlineExceeded)
	}
	if !f.requested {
		if len(st.retained) >= cliprdr.MaxFileSets {
			return st.rejectRemote(cliprdr.ErrFileLimit)
		}
		if st.active != nil || st.client.Status().Busy {
			return nil
		}
		p, err := st.client.RequestFiles(st.client.FileStatus().Locking)
		if err != nil {
			return st.rejectRemote(err)
		}
		f.requested = true
		st.active = &wireRead{fileEpoch: r.epoch, deadline: now.Add(st.s.o.DrainTimeout)}
		return st.send(p...)
	}
	if !f.haveSet {
		return nil
	}
	// Bound unknown-size queries to eight in flight. All requests, including
	// canceled old epochs, remain subject to the codec's 64 / 8 MiB limits.
	for f.next < len(f.descriptors) && f.sizes < 8 {
		i := f.next
		d := f.descriptors[i]
		if d.IsDirectory() || d.Flags&cliprdr.FileSizeValid != 0 {
			f.next++
			continue
		}
		if st.client.FileStatus().Outgoing >= cliprdr.MaxFileRequests {
			break
		}
		p, err := st.client.RequestFileSize(f.set, uint32(i))
		if errors.Is(err, cliprdr.ErrFileLimit) {
			break
		}
		if err != nil {
			return st.rejectRemote(err)
		}
		f.next++
		f.sizes++
		if err = st.trackFile(p, &fileOperation{epoch: r.epoch, index: uint32(i), deadline: now.Add(st.s.o.DrainTimeout)}); err != nil {
			return err
		}
	}
	if f.next != len(f.descriptors) || f.sizes != 0 {
		return nil
	}
	limit, availableFiles := st.fileBudget()
	if len(f.descriptors) > availableFiles {
		return st.rejectRemote(cliprdr.ErrFileLimit)
	}
	plan, err := st.client.PlanFiles(f.set, cliprdr.FilePlanOptions{MaxFileSize: limit, MaxTotalSize: limit})
	if err != nil {
		return st.rejectRemote(err)
	}
	f.bytes = plan.TotalSize()
	f.ready = true
	f.meta.finish(f.descriptors, nil)
	f.meta = nil
	r.deadline = now.Add(st.s.o.NativeTimeout)
	return nil
}

func (st *state) requestFile(r *fileReadRequest) error {
	remote := st.fileRemote(r.epoch)
	if remote == nil || remote.epoch != r.epoch || r.epoch.ctx.Err() != nil || remote.files == nil || !remote.files.ready {
		r.finish(nil, cliprdr.ErrChanged)
		return nil
	}
	if r.ctx.Err() != nil {
		r.finish(nil, r.ctx.Err())
		return nil
	}
	f := remote.files
	if r.index >= uint32(len(f.descriptors)) || f.descriptors[r.index].IsDirectory() || r.length > cliprdr.MaxFileChunk {
		r.finish(nil, cliprdr.ErrFile)
		return nil
	}
	d := f.descriptors[r.index]
	if r.offset > d.Size || uint64(r.length) > d.Size-r.offset {
		r.finish(nil, cliprdr.ErrFile)
		return nil
	}
	if r.length == 0 {
		r.finish([]byte{}, nil)
		return nil
	}
	p, err := st.client.RequestFileRange(f.set, r.index, r.offset, r.length)
	if err != nil {
		r.finish(nil, err)
		return nil
	}
	return st.trackFile(p, &fileOperation{epoch: r.epoch, read: r, index: r.index, deadline: time.Now().Add(st.s.o.DrainTimeout)})
}

func (st *state) requestMeta(r *fileMetaRequest) {
	remote := st.fileRemote(r.epoch)
	if remote == nil || remote.epoch != r.epoch || r.epoch.ctx.Err() != nil || remote.files == nil {
		r.finish(nil, cliprdr.ErrChanged)
		return
	}
	f := remote.files
	if f.ready {
		r.finish(f.descriptors, nil)
		return
	}
	if r.ctx.Err() != nil {
		r.finish(nil, r.ctx.Err())
		return
	}
	// A lazy group superseded before its first enumeration can no longer fetch
	// a stale remote list; only the current remote may start a metadata fetch.
	if !f.lazy || remote != st.remote {
		r.finish(nil, cliprdr.ErrChanged)
		return
	}
	f.meta.finish(nil, cliprdr.ErrChanged)
	f.meta = r
	f.wantMeta = true
	f.deadline = time.Now().Add(st.s.o.DrainTimeout)
}

func (st *state) fileResult(e cliprdr.Event) error {
	if e.FileResult == nil {
		return cliprdr.ErrProtocol
	}
	f := e.FileResult
	op := st.filePending[f.Request.StreamID]
	if op == nil {
		return cliprdr.ErrProtocol
	}
	delete(st.filePending, f.Request.StreamID)
	r := st.fileRemote(op.epoch)
	if r == nil || r.epoch != op.epoch || op.epoch.ctx.Err() != nil {
		op.read.finish(nil, cliprdr.ErrChanged)
		return nil
	}
	if e.Err != nil {
		op.read.finish(nil, e.Err)
		return st.failFiles(r, e.Err)
	}
	if op.read == nil {
		if r.files == nil || r.files.sizes == 0 || op.index >= uint32(len(r.files.descriptors)) {
			return cliprdr.ErrProtocol
		}
		d := &r.files.descriptors[op.index]
		d.Size, d.Flags = f.Size, d.Flags|cliprdr.FileSizeValid
		r.files.sizes--
		// Recheck known aggregate sizes immediately, before native publication.
		var total uint64
		limit, _ := st.fileBudget()
		for _, d := range r.files.descriptors {
			if !d.IsDirectory() && d.Flags&cliprdr.FileSizeValid != 0 {
				if d.Size > limit-total {
					return st.rejectRemote(cliprdr.ErrFileLimit)
				}
				total += d.Size
			}
		}
		return nil
	}
	if uint32(len(f.Data)) != op.read.length {
		op.read.finish(nil, io.ErrUnexpectedEOF)
		return st.failFiles(r, io.ErrUnexpectedEOF)
	}
	op.read.finish(f.Data, nil)
	return nil
}
