package clipsync

import (
	"context"
	"errors"
	"time"

	"github.com/hq0101/rdp-go/cliphost"
	"github.com/hq0101/rdp-go/cliprdr"
)

// This ID belongs to our wire endpoint, not the OS registered-format table.
const uploadFormatID = 0xc001

type queuedUpload struct {
	request  cliprdr.FileRequest
	deadline time.Time
}

type uploadJob struct {
	kind     byte // acquisition, read, cleanup
	ctx      context.Context
	cancel   context.CancelFunc
	deadline time.Time
	item     *localItem
	options  cliphost.FileSelectionOptions
	request  cliprdr.FileRequest
	lease    *cliprdr.FileSourceRead
	offer    *cliprdr.FileSourceOffer
	answered bool // coordinator only: a timed-out request has already received FAIL
}

type uploadResult struct {
	job   *uploadJob
	offer *cliprdr.FileSourceOffer
	data  []byte
	err   error
}

type uploads struct {
	s         *Sync
	sources   *cliprdr.FileSources
	jobs      chan *uploadJob
	results   chan uploadResult
	done      chan struct{}
	job       *uploadJob
	queue     []queuedUpload
	offer     *cliprdr.FileSourceOffer // acquired, not yet transferred to FileSources
	offerItem *localItem
}

func newUploads(s *Sync) *uploads {
	u := &uploads{s: s, jobs: make(chan *uploadJob, 1), results: make(chan uploadResult, 1), done: make(chan struct{})}
	go u.run()
	return u
}

func releaseSource(o *cliprdr.FileSourceOffer) error {
	if o != nil && o.Release != nil {
		return o.Release()
	}
	return nil
}

// Exactly one job is admitted at a time. Closing jobs drains that admitted job,
// even after cancellation; a single buffered result cannot strand the worker.
// Never abandon an acquired source or pretend a blocked ReaderAt/Release ended.
func (u *uploads) run() {
	defer close(u.done)
	for j := range u.jobs {
		r := uploadResult{job: j}
		switch j.kind {
		case 'a':
			if r.err = j.ctx.Err(); r.err == nil {
				o, err := u.s.host.(LocalFileHost).AcquireFileSource(j.ctx, j.item.snapshot.Token, j.options)
				r.err = err
				if r.err == nil {
					r.err = j.ctx.Err()
				}
				if err == nil || o.Release != nil {
					r.offer = &o
				}
			}
		case 'r':
			r.data, r.err = j.lease.Read(j.ctx)
		case 'c':
			r.err = errors.Join(releaseSource(j.offer), u.sources.Collect())
		}
		j.cancel()
		u.results <- r
	}
}

// Called only after the coordinator stopped. No concurrent Client access; the
// store's Retire/Collect methods and the worker's ReaderAt synchronize themselves.
func (u *uploads) close() error {
	if u.sources != nil {
		u.sources.Retire()
	}
	close(u.jobs)
	<-u.done
	var err error
	select {
	case r := <-u.results:
		if r.job.kind == 'c' {
			err = r.err
		}
		err = errors.Join(err, releaseSource(r.offer))
	default:
	}
	err = errors.Join(err, releaseSource(u.offer))
	u.offer = nil
	if u.sources != nil {
		err = errors.Join(err, u.sources.Collect())
	}
	return err
}

func (st *state) reconcileSources() {
	if st.upload != nil && st.upload.sources != nil {
		st.upload.sources.Reconcile()
	}
}

func (st *state) finishUpload(request cliprdr.FileRequest, data []byte, readErr error) error {
	p, err := st.client.CompleteFileRequest(request.Token, data, readErr)
	if errors.Is(err, cliprdr.ErrFile) || errors.Is(err, cliprdr.ErrFileStreaming) {
		p, err = st.client.CompleteFileRequest(request.Token, nil, err)
	}
	st.reconcileSources()
	if errors.Is(err, cliprdr.ErrChanged) {
		return nil // only an expired opaque token, never answer a reused stream ID
	}
	if err != nil {
		return err
	}
	return st.send(p)
}

func (st *state) queueUpload(request cliprdr.FileRequest) error {
	if st.upload == nil || len(st.upload.queue) >= cliprdr.MaxFileRequests {
		return st.finishUpload(request, nil, cliprdr.ErrFileLimit)
	}
	st.upload.queue = append(st.upload.queue, queuedUpload{request, time.Now().Add(st.s.o.NativeTimeout)})
	return nil
}

func (st *state) completeUpload(r uploadResult) error {
	u := st.upload
	if u == nil || u.job != r.job {
		return cliprdr.ErrProtocol
	}
	u.job = nil
	j := r.job
	switch j.kind {
	case 'a':
		// Even a late or canceled acquisition result must be released. It cannot
		// replace a newer selection and must not be closed on the protocol thread.
		u.offer, u.offerItem = r.offer, j.item
		if r.err == nil && j.item.epoch.ctx.Err() != nil {
			r.err = cliprdr.ErrChanged
		}
		if r.err == nil && (j.answered || !time.Now().Before(j.deadline)) {
			r.err = context.DeadlineExceeded
		}
		if r.err != nil && st.desired == j.item && !j.item.failed {
			j.item.failed = true
			st.s.report(r.err)
		}
	case 'r':
		if !j.answered {
			if r.err != nil {
				st.s.report(r.err)
			}
			return st.finishUpload(j.request, r.data, r.err)
		}
	case 'c':
		return r.err // uncertain cleanup is terminal; never retry Release blindly
	}
	return nil
}

func (st *state) driveUploads(now time.Time) error {
	u := st.upload
	if u == nil {
		return nil
	}
	if j := u.job; j != nil && j.kind != 'c' && !j.answered && !now.Before(j.deadline) {
		j.answered = true
		j.cancel()
		if j.kind == 'r' {
			if err := st.finishUpload(j.request, nil, context.DeadlineExceeded); err != nil {
				return err
			}
		} else if st.desired == j.item && !j.item.failed {
			j.item.failed = true
			st.s.report(context.DeadlineExceeded)
		}
	}
	for len(u.queue) > 0 && !now.Before(u.queue[0].deadline) {
		r := u.queue[0]
		u.queue = u.queue[1:]
		if err := st.finishUpload(r.request, nil, context.DeadlineExceeded); err != nil {
			return err
		}
	}
	if u.job != nil {
		return nil
	}
	var j *uploadJob
	if u.offer != nil && (u.offerItem != st.desired || u.offerItem.failed || u.offerItem.epoch.ctx.Err() != nil) {
		j = &uploadJob{kind: 'c', offer: u.offer}
		u.offer, u.offerItem = nil, nil // transfer ownership into the cleanup job
	} else if u.sources.Status().Retired > 0 {
		j = &uploadJob{kind: 'c'}
	} else if len(u.queue) != 0 {
		r := u.queue[0]
		u.queue = u.queue[1:]
		lease, err := u.sources.Acquire(r.request)
		if err != nil {
			return st.finishUpload(r.request, nil, err)
		}
		j = &uploadJob{kind: 'r', request: r.request, lease: lease, deadline: r.deadline}
	} else if st.desired != nil && st.desired.files && !st.desired.failed && u.offer == nil && st.client.Status().Ready && !st.client.Status().Busy {
		item := st.desired
		if !st.client.FileStatus().Streaming {
			item.failed = true
			st.s.report(cliprdr.ErrFileStreaming)
			return nil
		}
		used := u.sources.Status()
		if used.Sets >= cliprdr.MaxFileSets || used.Files >= cliprdr.MaxFiles {
			item.failed = true
			st.s.report(cliprdr.ErrFileLimit)
			return nil
		}
		j = &uploadJob{kind: 'a', item: item, deadline: now.Add(st.s.o.NativeTimeout), options: cliphost.FileSelectionOptions{MaxTotalSize: st.s.o.LocalFiles.MaxTotalSize - used.Bytes, MaxFiles: cliprdr.MaxFiles - used.Files}}
	}
	if j != nil {
		if j.kind == 'a' {
			j.ctx, j.cancel = context.WithDeadline(j.item.epoch.ctx, j.deadline)
		} else if j.kind == 'r' {
			j.ctx, j.cancel = context.WithDeadline(st.s.ctx, j.deadline)
		} else {
			j.ctx, j.cancel = context.WithCancel(st.s.ctx)
		}
		u.job = j
		u.jobs <- j
	}
	return nil
}

func (st *state) publishLocal() error {
	item := st.desired
	if item == nil || !st.client.Status().Ready || st.client.Status().Busy {
		return nil
	}
	var p []byte
	var err error
	if item.files && !item.failed {
		u := st.upload
		if u.offer == nil || u.offerItem != item {
			return nil
		}
		if len(u.offer.Additional) != 0 {
			err = ErrInvalid // file-only publication; never inject unsolicited bytes
		} else {
			p, _, err = u.sources.Publish(uploadFormatID, *u.offer)
		}
		if err != nil {
			item.failed = true
			st.s.report(err)
			return nil // cleanup owns the rejected acquisition on the next drive
		}
		u.offer, u.offerItem = nil, nil // ownership belongs to FileSources now
	} else {
		fs := item.snapshot.Formats
		if item.files {
			fs = nil // rejected file acquisition explicitly clears the old offer
		}
		p, err = st.client.PublishDelayed(fs)
		st.reconcileSources()
		if err != nil {
			return err
		}
	}
	st.advertised, st.desired = item, nil
	st.everPublished = true
	return st.send(p)
}
