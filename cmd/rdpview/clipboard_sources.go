package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hq0101/rdp-go/cliprdr"
)

// Lazily created for an active connection's first explicit upload. Four disk
// workers and one collector; no candidate connection starts these workers.
type clipboardSources struct {
	client *cliprdr.Client
	store  *cliprdr.FileSources
	ctx    context.Context
	cancel context.CancelFunc
	reads  chan sourceWork
	wake   chan struct{}
	done   chan struct{}
	failed atomic.Bool
}
type sourceWork struct {
	request cliprdr.FileRequest
	lease   *cliprdr.FileSourceRead
}

// connectionMu and clipMu held by caller.
func (v *viewer) ensureSources() (*clipboardSources, error) {
	if v.sources != nil {
		return v.sources, nil
	}
	store, err := cliprdr.NewFileSources(v.clip, cliprdr.FileSourceOptions{MaxTotalSize: viewerFileBytes, MaxFiles: viewerFileCount})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &clipboardSources{client: v.clip, store: store, ctx: ctx, cancel: cancel, reads: make(chan sourceWork, cliprdr.MaxFileRequests), wake: make(chan struct{}, 1), done: make(chan struct{})}
	v.sources = s
	go v.runSources(s)
	return s, nil
}

func (s *clipboardSources) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (v *viewer) reconcileSources() { // clipMu held; no I/O
	if s := v.sources; s != nil {
		s.store.Reconcile()
		s.notify()
	}
}
func (v *viewer) stopSources() *clipboardSources { // clipMu held
	s := v.sources
	if s != nil {
		s.store.Retire()
		s.cancel()
	}
	if v.uploadJob != nil {
		v.uploadJob.cancel()
	}
	return s
}

func (v *viewer) routeSourceEvent(event cliprdr.Event) ([][]byte, error) {
	if event.Kind != cliprdr.FileContentsNeeded || event.FileRequest == nil {
		return nil, nil
	}
	r := *event.FileRequest
	s := v.sources
	if s != nil && s.client == v.clip && s.ctx.Err() == nil {
		lease, err := s.store.Acquire(r)
		if err == nil {
			select {
			case s.reads <- sourceWork{r, lease}:
				return nil, nil
			default:
				_ = lease.Close()
			}
		}
	}
	b, err := v.clip.CompleteFileRequest(r.Token, nil, cliprdr.ErrBusy)
	v.reconcileSources()
	return [][]byte{b}, err
}

func (v *viewer) runSources(s *clipboardSources) {
	defer close(s.done)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-s.ctx.Done():
					return
				case work := <-s.reads:
					data, readErr := work.lease.Read(s.ctx) // disk never holds connection/clipboard locks
					v.connectionMu.RLock()
					v.clipMu.Lock()
					if v.sources == s && v.clip == s.client && s.ctx.Err() == nil {
						b, err := s.client.CompleteFileRequest(work.request.Token, data, readErr)
						s.store.Reconcile()
						if err == nil {
							ctx, cancel := context.WithTimeout(s.ctx, 8*time.Second)
							err = v.remote.(channelRemote).WriteChannel(ctx, v.clipChannel, b)
							cancel()
						}
						if err != nil {
							v.closeFailedClipboardTransport()
						}
					}
					v.clipMu.Unlock()
					v.connectionMu.RUnlock()
					s.notify()
				}
			}
		}()
	}
	for {
		select {
		case <-s.wake:
			if s.store.Collect() != nil {
				s.failed.Store(true)
			}
		case <-s.ctx.Done():
			workers.Wait()
			for {
				select {
				case work := <-s.reads:
					_ = work.lease.Close()
				default:
					goto drained
				}
			}
		drained:
			s.store.Retire()
			if s.store.Collect() != nil {
				s.failed.Store(true)
			}
			return
		}
	}
}
