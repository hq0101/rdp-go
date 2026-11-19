package cliphost

import (
	"context"
	"errors"
	"runtime"
	"time"
	"unsafe"

	"github.com/hq0101/rdp-go/clipole"
	"github.com/hq0101/rdp-go/cliprdr"
)

// OfferFilesIfCurrent uses the same ownership coordinator as byte offers, but
// publishes a native OLE virtual-file object. expected must still name Current.
// read is delayed, bounded and canceled when superseded. ctx bounds installation
// only; after success the Host owns the offer until replacement, Clear or Close.
// The original descriptor indices are preserved. File streams are not exposed
// through Read/Supported byte APIs. This does not enable CLIPRDR file negotiation.
// Starting a valid attempt retires the preceding provider even if installation
// later fails, as with Offer. Call outside GUI callbacks; keep that GUI pumping.
func (h *Host) OfferFilesIfCurrent(ctx context.Context, expected Token, files []cliprdr.FileDescriptor, read clipole.ReadFunc, o clipole.Options) (Token, error) {
	if o.RetainOnChange {
		return Token{}, ErrInvalid // use the lease-returning API for retained sources
	}
	token, _, err := h.offerFiles(ctx, expected, files, read, o)
	return token, err
}

// OfferRetainedFilesIfCurrent installs files whose existing consumers survive
// a new clipboard copy. The caller must keep the source valid until lease.Done,
// or Close the lease when its source is revoked. ctx limits installation only.
// Host owns and joins every lease on Close, and bounds current/retained offers
// to cliprdr.MaxFileSets. This does not imply the source supports remote locks.
func (h *Host) OfferRetainedFilesIfCurrent(ctx context.Context, expected Token, files []cliprdr.FileDescriptor, read clipole.ReadFunc, o clipole.Options) (Token, FileLease, error) {
	o.RetainOnChange = true
	return h.offerFiles(ctx, expected, files, read, o)
}

func (h *Host) offerFiles(ctx context.Context, expected Token, files []cliprdr.FileDescriptor, read clipole.ReadFunc, o clipole.Options) (Token, FileLease, error) {
	if ctx == nil || expected.id == nil {
		return Token{}, nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Token{}, nil, err
	}
	if err := clipole.Validate(files, read, o); err != nil {
		return Token{}, nil, err
	}
	files = append([]cliprdr.FileDescriptor(nil), files...)
	token := Token{new(identity)}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return Token{}, nil, ErrClosed
	}
	if h.cancel != nil {
		h.cancel()
	}
	h.wanted = token
	h.mu.Unlock()
	r := h.call(command{ctx: ctx, kind: 'f', token: token, expected: expected, files: files, fileRead: read, fileOptions: o})
	if r.err != nil {
		h.mu.Lock()
		if h.wanted == token {
			h.wanted = Token{}
			if h.cancel != nil {
				h.cancel()
			}
		}
		h.mu.Unlock()
		return Token{}, nil, r.err
	}
	return token, r.file, nil
}

func (w *worker) pump() {
	for range 64 {
		var m winMessage
		ok, _, _ := peekMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0, 1)
		if ok == 0 {
			return
		}
		dispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func fileError(err error) error {
	switch {
	case errors.Is(err, clipole.ErrChanged):
		return ErrChanged
	case errors.Is(err, clipole.ErrBusy):
		return ErrBusy
	case errors.Is(err, clipole.ErrUnsupported):
		return ErrUnsupported
	default:
		return err
	}
}

func (w *worker) collectFile() {
	w.collectRetained()
	if w.file == nil {
		return
	}
	select {
	case err, ok := <-w.file.Errors():
		if ok {
			w.h.report(err)
		}
	default:
	}
	select {
	case <-w.file.Done():
		err := fileError(w.file.Err())
		if err != nil && !errors.Is(err, ErrChanged) {
			w.h.report(err)
		}
		w.h.mu.Lock()
		delete(w.h.files, w.file)
		if w.h.file == w.file {
			w.h.file = nil
		}
		w.h.mu.Unlock()
		if w.fileCancel != nil {
			w.fileCancel()
			w.fileCancel = nil
		}
		w.file = nil
		w.fileRetain = false
		w.dirty = true
	default:
	}
}

func (w *worker) closeFile() error {
	if w.file == nil {
		return nil
	}
	w.file.Close()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		w.pump()
		select {
		case <-w.file.Done():
			err := fileError(w.file.Err())
			w.collectFile()
			if errors.Is(err, ErrChanged) {
				return nil
			}
			return err
		case <-ticker.C:
		}
	}
}

func (w *worker) offerFiles(c command) error {
	w.collectFile()
	w.h.mu.Lock()
	full := len(w.h.files) >= cliprdr.MaxFileSets
	w.h.mu.Unlock()
	if full {
		return cliprdr.ErrFileLimit
	}
	if !w.valid || c.expected != w.snapshot.Token || !w.wanted(c.token) {
		return ErrChanged
	}
	owner, sequence := nativeStamp()
	if owner != w.owner || sequence != w.sequence {
		return ErrChanged
	}
	expected, err := clipole.Observe()
	if err != nil {
		return fileError(err)
	}
	owner, sequence = nativeStamp()
	if owner != w.owner || sequence != w.sequence {
		return ErrChanged
	}
	// Keep the old native item installed until the guarded OLE replacement. Its
	// provider was already canceled by the public method; retiring the native
	// item first would invalidate our own expected ownership snapshot.
	old := w.file
	oldCancel := w.fileCancel
	oldRetain := w.fileRetain
	life, cancelLife := context.WithCancel(context.Background())
	readLife, cancelRead := context.WithCancel(life)
	cancel := func() { cancelRead(); cancelLife() }
	w.h.mu.Lock()
	if w.h.closed || w.h.wanted != c.token {
		w.h.mu.Unlock()
		cancelRead()
		cancel()
		return ErrChanged
	}
	w.h.cancel = nil
	if !c.fileOptions.RetainOnChange {
		w.h.cancel = cancelRead
	}
	w.h.mu.Unlock()
	type result struct {
		s   *clipole.Offer
		err error
	}
	started := make(chan result, 1)
	go func() {
		runtime.LockOSThread() // exit locked; never pool a caller-selected desktop
		if ok, _, e := setDesktop.Call(w.desktop); ok == 0 {
			started <- result{err: winerr("SetThreadDesktop file startup", e)}
			return
		}
		s, err := clipole.PublishIfCurrent(life, expected, c.files, func(ctx context.Context, index uint32, offset uint64, length uint32) ([]byte, error) {
			if !c.fileOptions.RetainOnChange && !w.wanted(c.token) {
				return nil, ErrChanged
			}
			request, stop := context.WithCancel(ctx)
			defer stop()
			detach := context.AfterFunc(readLife, stop)
			defer detach()
			if err := readLife.Err(); err != nil {
				return nil, err
			}
			data, err := c.fileRead(request, index, offset, length)
			if !c.fileOptions.RetainOnChange && !w.wanted(c.token) {
				return nil, ErrChanged
			}
			if request.Err() != nil {
				return nil, request.Err()
			}
			return data, err
		}, c.fileOptions)
		started <- result{s, err}
	}()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		w.pump() // OLE can synchronously notify our previous byte owner window
		if c.ctx.Err() != nil || !w.wanted(c.token) {
			cancel()
		}
		select {
		case r := <-started:
			if r.err != nil {
				cancel()
				return fileError(r.err)
			}
			if c.ctx.Err() != nil || !w.wanted(c.token) {
				cancel()
				r.s.Close()
				for {
					w.pump()
					select {
					case <-r.s.Done():
						return ErrChanged
					case <-ticker.C:
					}
				}
			}
			// The new offer owns the clipboard before an old OLE object is joined.
			w.file = r.s
			w.fileCancel = cancel
			w.fileRetain = c.fileOptions.RetainOnChange
			w.offer, w.provider, w.formats = c.token, nil, nil
			w.h.mu.Lock()
			w.h.file = r.s
			if w.h.files == nil {
				w.h.files = make(map[*clipole.Offer]bool)
			}
			w.h.files[r.s] = true
			if w.h.closed {
				r.s.Close()
			}
			w.h.mu.Unlock()
			if old != nil {
				if oldRetain {
					w.retainFile(old, oldCancel)
					oldCancel = nil
					goto retired
				}
				old.Close()
				for {
					w.pump()
					select {
					case <-old.Done():
						goto retired
					case <-ticker.C:
					}
				}
			}
		retired:
			if old != nil && !oldRetain {
				w.h.mu.Lock()
				delete(w.h.files, old)
				w.h.mu.Unlock()
			}
			if oldCancel != nil {
				oldCancel()
			}
			w.valid = false
			w.sample()
			return nil
		case <-ticker.C:
		}
	}
}
