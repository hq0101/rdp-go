package clipsync

import (
	"context"
	"errors"

	"github.com/hq0101/rdp-go/cliphost"
	"github.com/hq0101/rdp-go/clipole"
	"github.com/hq0101/rdp-go/cliprdr"
)

type nativeJob struct {
	ctx      context.Context
	cancel   context.CancelFunc
	kind     byte
	epoch    *epoch
	snapshot cliphost.Snapshot
	request  cliprdr.DataRequest
	formats  []cliprdr.Format
	files    []cliprdr.FileDescriptor
	retain   bool
	lazyMeta bool
}
type nativeResult struct {
	job   *nativeJob
	data  []byte
	err   error
	lease cliphost.FileLease
}

func (s *Sync) native(jobs <-chan *nativeJob, results chan<- nativeResult, done chan<- struct{}) {
	defer close(done)
	for {
		select {
		case <-s.ctx.Done():
			return
		case j := <-jobs:
			var r nativeResult
			r.job = j
			if j.ctx.Err() != nil {
				r.err = j.ctx.Err()
			} else if j.kind == 'r' {
				r.data, r.err = s.host.Read(j.ctx, j.snapshot.Token, j.request.Format)
			} else if j.kind == 'f' {
				read := func(c context.Context, index uint32, offset uint64, length uint32) ([]byte, error) {
					return s.requestFile(c, j.epoch, index, offset, length)
				}
				o := clipole.Options{MaxTotalSize: s.o.RemoteFiles.MaxTotalSize}
				if j.lazyMeta {
					o.DescriptorsFunc = func(c context.Context) ([]cliprdr.FileDescriptor, error) {
						return s.requestMeta(c, j.epoch)
					}
				}
				if h, ok := s.host.(RetainedFileHost); ok && j.retain {
					_, r.lease, r.err = h.OfferRetainedFilesIfCurrent(j.ctx, j.snapshot.Token, j.files, read, o)
					if r.err == nil && r.lease == nil {
						r.err = ErrInvalid
					}
				} else {
					_, r.err = s.host.(FileHost).OfferFilesIfCurrent(j.ctx, j.snapshot.Token, j.files, read, o)
				}
			} else {
				_, r.err = s.host.OfferIfCurrent(j.ctx, j.snapshot.Token, j.formats, func(c context.Context, f cliprdr.Format) ([]byte, error) { return s.request(c, j.epoch, f) })
			}
			j.cancel()
			select {
			case results <- r:
			case <-s.ctx.Done():
				if r.lease != nil {
					r.lease.Close()
				}
				return
			}
		}
	}
}

func (s *Sync) run() {
	st := state{s: s}
	if s.o.LocalFiles != nil {
		st.upload = newUploads(s)
	}
	jobs := make(chan *nativeJob, 1)
	results := make(chan nativeResult, 1)
	nativeDone := make(chan struct{})
	go s.native(jobs, results, nativeDone)
	err := st.loop(jobs, results)
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
	s.cancel() // visible before potentially uninterruptible native cleanup
	s.host.Close()
	leaseErr := st.closeFileLeases()
	var sourceErr error
	if st.upload != nil {
		sourceErr = st.upload.close()
	}
	<-nativeDone
	<-s.host.Done()
	st.client.Reset()
	st.decoder.Reset()
	s.mu.Lock()
	s.err = errors.Join(s.err, s.host.Err(), sourceErr, leaseErr)
	s.mu.Unlock()
	if s.fileOperations != nil {
		close(s.fileOperations)
	}
	close(s.errors)
	close(s.done)
}
