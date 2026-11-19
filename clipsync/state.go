package clipsync

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"time"

	"github.com/hq0101/rdp-go/cliphost"
	"github.com/hq0101/rdp-go/cliprdr"
	"github.com/hq0101/rdp-go/vchan"
)

type localItem struct {
	epoch         *epoch
	snapshot      cliphost.Snapshot
	files, failed bool
}
type remoteItem struct {
	epoch           *epoch
	formats         []cliprdr.Format
	wireFormats     []cliprdr.Format
	expected        cliphost.Snapshot
	ack             []byte
	ackCount        int
	accepted        bool
	supported       bool
	files           *remoteFiles
	deadline, retry time.Time
}
type localRead struct {
	item    *localItem
	request cliprdr.DataRequest
}
type wireRead struct {
	request   *renderRequest
	fileEpoch *epoch
	deadline  time.Time
}

type state struct {
	s                          *Sync
	client                     cliprdr.Client
	decoder                    vchan.Decoder
	last                       cliphost.Snapshot
	haveLast                   bool
	local, desired, advertised *localItem
	remote                     *remoteItem
	reads                      []localRead
	active                     *wireRead
	queued                     *renderRequest
	job                        *nativeJob
	everPublished              bool
	filePending                map[uint32]*fileOperation
	retained                   map[*epoch]*remoteItem
	upload                     *uploads
	deferredFormats            [][]byte
	deferredFormatBytes        int
}

func (st *state) send(packets ...[]byte) error {
	for _, p := range packets {
		ctx, cancel := context.WithTimeout(st.s.ctx, st.s.o.WriteTimeout)
		err := st.s.write(ctx, p)
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

func formats(fs []cliprdr.Format) []cliprdr.Format {
	var out []cliprdr.Format
	for _, f := range fs {
		if cliphost.Supported(f) {
			out = append(out, f)
		}
	}
	return out
}

func (st *state) stopLocal() error {
	if st.local != nil {
		st.local.epoch.cancel()
	}
	st.local, st.desired, st.advertised = nil, nil, nil
	st.reads = nil
	packets := st.client.RevokeLocal()
	st.reconcileSources()
	return st.send(packets...)
}

// Repeated identical byte-format notifications can share one pending native
// installation, but each notification still receives its own ordered response.
func (st *state) acknowledgeRemote(success bool) error {
	r := st.remote
	if r.ack == nil {
		return nil
	}
	if !success {
		binary.LittleEndian.PutUint16(r.ack[2:], 2)
	}
	for range r.ackCount {
		if err := st.send(r.ack); err != nil {
			return err
		}
	}
	r.ack, r.ackCount = nil, 0
	return nil
}

func (st *state) stopRemote() error { return st.endRemote(true) }

func (st *state) endRemote(keepFiles bool) error {
	if st.remote != nil {
		r := st.remote
		f := r.files
		keep := keepFiles && r.accepted && f != nil && f.locked && f.haveSet && f.lease != nil && r.epoch.ctx.Err() == nil
		if f != nil && f.lease != nil {
			st.retainFiles(r)
		}
		if !keep {
			r.epoch.cancel()
			if f != nil && f.lease != nil {
				f.lease.Close()
			}
			if err := st.releaseFiles(r); err != nil {
				return err
			}
		}
		if err := st.acknowledgeRemote(false); err != nil {
			return err
		}
		st.remote = nil
	}
	if st.active != nil {
		st.active.request.finish(nil, cliprdr.ErrChanged)
	}
	st.queued.finish(nil, cliprdr.ErrChanged)
	st.queued = nil
	return nil
}

// Tokens, not format IDs, identify ownership. The format comparison also catches
// malformed/custom Host implementations that mutate a snapshot in place.
func (st *state) observe() error {
	snapshot, err := st.s.host.Current()
	if err != nil {
		if st.haveLast {
			st.haveLast = false
			return st.stopLocal()
		}
		return nil // an application may simply have the clipboard open
	}
	if st.haveLast && snapshot.Token == st.last.Token && snapshot.External == st.last.External && snapshot.Files == st.last.Files && slices.Equal(snapshot.Formats, st.last.Formats) {
		return nil
	}
	st.last, st.haveLast = snapshot, true
	if !snapshot.External {
		// A canceled older installation may have won the native clipboard just
		// before cancellation. The latest remote offer can replace that owned
		// item, but must still condition on its fresh token. Never rebase onto a
		// newer external/user copy, which follows the cancellation path below.
		if st.remote != nil && !st.remote.accepted {
			st.remote.expected = snapshot
		}
		return st.stopLocal()
	} // own delayed offer: never echo it
	if err := st.stopLocal(); err != nil {
		return err
	}
	if err := st.stopRemote(); err != nil {
		return err
	}
	if err := st.rejectDeferredFormats(); err != nil {
		return err
	}
	if st.s.o.Mode&ToRemote != 0 {
		snapshot.Formats = formats(snapshot.Formats)
		item := &localItem{epoch: st.s.epoch(), snapshot: snapshot, files: st.s.o.LocalFiles != nil && snapshot.Files}
		st.local, st.desired = item, item
	}
	return nil
}

func (st *state) receive(chunk []byte) error {
	message, complete, err := st.decoder.Feed(chunk)
	if err != nil || !complete {
		return err
	}
	if len(message) >= 2 && binary.LittleEndian.Uint16(message) == 2 && (len(st.deferredFormats) != 0 || st.remote != nil && st.remote.files != nil && st.remote.ack != nil) {
		return st.deferFormatList(message)
	}
	return st.handleMessage(message)
}

func (st *state) handleMessage(message []byte) error {
	replies, event, err := st.client.Handle(message)
	st.reconcileSources()
	if err != nil {
		return err
	}
	if event.Kind == cliprdr.RemoteFormats {
		// Client's protocol-only default ACK is the final reply. A native adapter
		// must defer that ACK until installing formats; preceding revocation FAILs
		// still go out now in their original order. Keep the codec's exact packet.
		if len(replies) == 0 {
			return cliprdr.ErrProtocol
		}
		ack := replies[len(replies)-1]
		replies = replies[:len(replies)-1]
		if len(ack) != 8 || binary.LittleEndian.Uint16(ack) != 3 {
			return cliprdr.ErrProtocol
		}
		if err = st.send(replies...); err != nil {
			return err
		}
		all := st.client.RemoteFormatList()
		if r := st.remote; r != nil && r.ack != nil && r.supported && r.files == nil && !hasFiles(all) && st.active == nil && st.queued == nil && slices.Equal(r.wireFormats, all) {
			// Windows may notify both OLE publication and its flush before our
			// native installation returns. No content has been requested yet and
			// the complete ID/name mapping is identical. The pending provider
			// therefore represents the latest version without another install.
			// An artificial FAIL for the earlier notification can make the peer
			// reject later reads even after a subsequent successful response.
			if r.ackCount >= 64 {
				return cliprdr.ErrProtocol
			}
			r.ackCount++
			return nil
		}
		if err = st.stopRemote(); err != nil {
			return err
		}
		// Preserve a preexisting local clipboard through initial negotiation. The
		// initial protocol empty offer is only a handshake, not user data.
		initialLocal := !st.everPublished && st.desired != nil && (len(st.desired.snapshot.Formats) > 0 || st.desired.files)
		if st.s.o.Mode&ToLocal == 0 || initialLocal {
			if !initialLocal {
				if err = st.stopLocal(); err != nil {
					return err
				}
			}
			binary.LittleEndian.PutUint16(ack[2:], 2)
			return st.send(ack)
		}
		if err = st.stopLocal(); err != nil {
			return err
		}
		fs := formats(all)
		st.remote = &remoteItem{epoch: st.s.epoch(), formats: fs, wireFormats: all, expected: st.last, ack: ack, ackCount: 1, supported: len(fs) > 0 || len(all) == 0, deadline: time.Now().Add(st.s.o.NativeTimeout)}
		if st.s.o.RemoteFiles != nil && st.client.FileStatus().Streaming && hasFiles(all) {
			st.remote.files = &remoteFiles{deadline: time.Now().Add(st.s.o.DrainTimeout), lazy: st.s.o.RemoteFiles.DeferMetadata}
			st.remote.supported = true
		}
		if !st.haveLast {
			return st.rejectRemote(cliphost.ErrBusy)
		}
		return nil
	}
	if err = st.send(replies...); err != nil {
		return err
	}
	switch event.Kind {
	case cliprdr.DataNeeded:
		if event.DataRequest == nil || st.advertised == nil || len(st.reads) >= cliprdr.MaxDataRequests {
			return cliprdr.ErrProtocol
		}
		st.reads = append(st.reads, localRead{st.advertised, *event.DataRequest})
	case cliprdr.DataResult:
		if st.active == nil || st.active.request == nil {
			return cliprdr.ErrProtocol
		}
		r := st.active.request
		if st.remote == nil || r.epoch != st.remote.epoch || r.epoch.ctx.Err() != nil {
			r.finish(nil, cliprdr.ErrChanged)
		} else {
			r.finish(event.Data, event.Err)
		}
		st.active = nil
	case cliprdr.FileListResult:
		return st.fileList(event)
	case cliprdr.FileContentsResult:
		return st.fileResult(event)
	case cliprdr.FileContentsNeeded:
		if event.FileRequest == nil {
			return cliprdr.ErrProtocol
		}
		return st.queueUpload(*event.FileRequest)
	case cliprdr.OfferResult:
		if event.Err != nil {
			st.s.report(event.Err)
			if st.advertised != nil {
				st.advertised.epoch.cancel()
				st.advertised = nil
				st.reads = nil
			}
		}
	}
	return nil
}

func (st *state) rejectRemote(reason error) error {
	if st.remote == nil {
		return nil
	}
	if st.remote.files != nil {
		st.remote.files.meta.finish(nil, reason)
	}
	st.s.report(reason)
	return st.endRemote(false)
}

func (st *state) request(r *renderRequest) {
	if st.remote == nil || r.epoch != st.remote.epoch || r.epoch.ctx.Err() != nil || st.s.o.Mode&ToLocal == 0 {
		r.finish(nil, cliprdr.ErrChanged)
		return
	}
	if r.ctx.Err() != nil {
		r.finish(nil, r.ctx.Err())
		return
	}
	if st.queued != nil {
		r.finish(nil, cliprdr.ErrBusy)
		return
	}
	st.queued = r
}

func (st *state) complete(r nativeResult) error {
	leaseTransferred := false
	if r.lease != nil {
		defer func() {
			if !leaseTransferred {
				r.lease.Close() // Host still owns and joins late publications.
			}
		}()
	}
	if st.job != r.job {
		return cliprdr.ErrProtocol
	}
	st.job = nil
	j := r.job
	if j.kind == 'o' || j.kind == 'f' {
		if err := st.observe(); err != nil {
			return err
		}
		if st.remote == nil || st.remote.epoch != j.epoch {
			return nil
		}
		if errors.Is(r.err, cliphost.ErrChanged) && st.haveLast && !st.last.External && st.remote.expected.Token != j.snapshot.Token && time.Now().Before(st.remote.deadline) {
			st.remote.retry = time.Now().Add(10 * time.Millisecond)
			return nil
		}
		if errors.Is(r.err, cliphost.ErrBusy) && time.Now().Before(st.remote.deadline) {
			st.remote.retry = time.Now().Add(50 * time.Millisecond)
			return nil
		}
		if r.err != nil {
			return st.rejectRemote(r.err)
		}
		if !st.remote.supported {
			return st.rejectRemote(cliprdr.ErrNoFormat)
		}
		if st.remote.files != nil {
			st.remote.files.lease = r.lease
			leaseTransferred = true
			if fo, ok := r.lease.(FileOperations); ok {
				go st.s.forwardFileOperations(j.epoch, fo.Operations())
			}
		}
		if err := st.acknowledgeRemote(true); err != nil {
			return err
		}
		st.remote.accepted = true
		return nil
	}
	if st.advertised == nil || st.advertised.epoch != j.epoch || j.epoch.ctx.Err() != nil {
		return nil
	}
	if len(st.reads) == 0 || st.reads[0].request.Token != j.request.Token {
		return cliprdr.ErrProtocol
	}
	st.reads = st.reads[1:]
	if errors.Is(r.err, cliphost.ErrChanged) {
		return st.stopLocal()
	}
	packets, err := st.client.CompleteDataRequest(j.request.Token, r.data, r.err)
	if err == cliprdr.ErrFormat {
		packets, err = st.client.CompleteDataRequest(j.request.Token, nil, err)
	}
	if err == cliprdr.ErrChanged {
		return nil
	}
	if err != nil {
		return err
	}
	return st.send(packets...)
}

func (st *state) drive(jobs chan<- *nativeJob) error {
	now := time.Now()
	if st.active != nil {
		if st.active.request != nil && st.active.request.ctx.Err() != nil {
			st.active.request.finish(nil, st.active.request.ctx.Err())
		}
		if !now.Before(st.active.deadline) {
			return ErrDrainTimeout
		}
	}
	if st.queued != nil && st.queued.ctx.Err() != nil {
		st.queued.finish(nil, st.queued.ctx.Err())
		st.queued = nil
	}
	if err := st.driveFiles(now); err != nil {
		return err
	}
	if err := st.driveUploads(now); err != nil {
		return err
	}
	if len(st.deferredFormats) != 0 && (st.remote == nil || st.remote.ack == nil) {
		message := st.deferredFormats[0]
		st.deferredFormats[0] = nil
		st.deferredFormats = st.deferredFormats[1:]
		st.deferredFormatBytes -= len(message)
		return st.handleMessage(message)
	}
	if err := st.publishLocal(); err != nil {
		return err
	}
	if st.active == nil && st.queued != nil && st.remote != nil && st.remote.accepted && !st.client.Status().Busy {
		r := st.queued
		st.queued = nil
		p, err := st.client.Request(r.format)
		if err != nil {
			r.finish(nil, err)
		} else {
			st.active = &wireRead{request: r, deadline: now.Add(st.s.o.DrainTimeout)}
			if err = st.send(p); err != nil {
				return err
			}
		}
	}
	if st.job == nil {
		var j *nativeJob
		if st.remote != nil && !st.remote.accepted && (st.remote.files == nil || st.remote.files.ready || st.remote.files.lazy) && !now.Before(st.remote.retry) {
			if !now.Before(st.remote.deadline) {
				return st.rejectRemote(context.DeadlineExceeded)
			}
			ctx, cancel := context.WithDeadline(st.remote.epoch.ctx, st.remote.deadline)
			j = &nativeJob{ctx: ctx, cancel: cancel, kind: 'o', epoch: st.remote.epoch, snapshot: st.remote.expected, formats: st.remote.formats}
			if st.remote.files != nil {
				j.kind = 'f'
				if st.remote.files.lazy {
					j.lazyMeta = true
					j.retain = st.client.FileStatus().Locking
				} else {
					j.files = st.remote.files.descriptors
					j.retain = st.remote.files.locked
				}
			}
		} else if len(st.reads) > 0 {
			r := st.reads[0]
			ctx, cancel := context.WithTimeout(r.item.epoch.ctx, st.s.o.NativeTimeout)
			j = &nativeJob{ctx: ctx, cancel: cancel, kind: 'r', epoch: r.item.epoch, snapshot: r.item.snapshot, request: r.request}
		}
		if j != nil {
			st.job = j
			jobs <- j
		}
	}
	return nil
}

func (st *state) loop(jobs chan<- *nativeJob, results <-chan nativeResult) error {
	st.decoder.Limit = cliprdr.MaxMessage
	if st.s.o.RemoteFiles != nil || st.s.o.LocalFiles != nil {
		if err := st.client.EnableFileStreaming(); err != nil {
			return err
		}
		st.filePending = make(map[uint32]*fileOperation)
	}
	var uploadResults <-chan uploadResult
	if st.upload != nil {
		var err error
		st.upload.sources, err = cliprdr.NewFileSources(&st.client, cliprdr.FileSourceOptions{MaxTotalSize: st.s.o.LocalFiles.MaxTotalSize})
		if err != nil {
			return err
		}
		uploadResults = st.upload.results
	}
	changes, hostErrors := st.s.host.Changes(), st.s.host.Errors()
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		if st.s.ctx.Err() != nil {
			return nil
		}
		if err := st.observe(); err != nil {
			return err
		}
		if err := st.drive(jobs); err != nil {
			return err
		}
		st.s.mu.Lock()
		st.s.status = st.client.Status()
		st.s.mu.Unlock()
		select {
		case <-st.s.ctx.Done():
			return nil
		case <-st.s.host.Done():
			if st.s.ctx.Err() != nil {
				return nil
			}
			return errors.Join(cliphost.ErrClosed, st.s.host.Err())
		case <-timer.C:
		case _, ok := <-changes:
			if !ok {
				changes = nil
			}
		case err, ok := <-hostErrors:
			if !ok {
				hostErrors = nil
			} else {
				st.s.report(err)
			}
		case p := <-st.s.packets:
			err := p.ctx.Err()
			if err != nil {
				p.result <- err
				continue
			}
			if err == nil {
				err = st.observe()
			}
			if err == nil {
				err = st.receive(p.data)
			}
			p.result <- err
			if err != nil {
				return err
			}
		case r := <-st.s.renders:
			st.request(r)
		case r := <-st.s.fileReads:
			if err := st.requestFile(r); err != nil {
				return err
			}
		case r := <-st.s.fileMeta:
			st.requestMeta(r)
		case ev := <-st.s.fileOps:
			st.s.deliverFileOperation(ev, st.remote == nil || st.remote.epoch != ev.epoch)
		case r := <-results:
			if err := st.complete(r); err != nil {
				return err
			}
		case r := <-uploadResults:
			if err := st.completeUpload(r); err != nil {
				return err
			}
		}
	}
}
