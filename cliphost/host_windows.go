package cliphost

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/hq0101/rdp-go/clipole"
	"github.com/hq0101/rdp-go/cliprdr"
)

type command struct {
	ctx         context.Context
	kind        byte
	token       Token
	expected    Token
	conditional bool
	format      cliprdr.Format
	formats     []cliprdr.Format
	provider    Provider
	reply       chan response
	files       []cliprdr.FileDescriptor
	fileRead    clipole.ReadFunc
	fileOptions clipole.Options
}
type response struct {
	data        []byte
	err         error
	file        FileLease
	virtual     bool
	oleSnapshot clipole.Snapshot
	desktop     uintptr
	preferred   uint32
}

// Host uses one private, locked clipboard thread. It never changes the caller's
// process window station. The caller's desktop must remain open for its lifetime.
// Close requests cancellation; Done closes only after all native calls, provider
// callbacks, listener removal and window destruction finish. A foreign app's
// GetClipboardData delayed rendering cannot be interrupted by a Go context.
// Read/Offer/Clear wait for completion; call them outside GUI callbacks so other
// windows in the caller's process can still service synchronous clipboard messages.
type Host struct {
	commands            chan command
	changes             chan struct{}
	errors              chan error
	stop, done          chan struct{}
	once                sync.Once
	mu                  sync.Mutex
	current             Snapshot
	sampleErr, terminal error
	wanted              Token
	cancel              context.CancelFunc
	closed              bool
	file                *clipole.Offer
	files               map[*clipole.Offer]bool // current and retained; protected by mu
}

type worker struct {
	h           *Host
	o           Options
	hwnd        uintptr
	owner       uintptr
	sequence    uint32
	valid       bool
	snapshot    Snapshot
	offer       Token
	formats     map[uint32]cliprdr.Format
	provider    Provider
	dirty       bool
	closing     bool
	listening   bool
	desktop     uintptr
	file        *clipole.Offer
	fileCancel  context.CancelFunc
	fileRetain  bool
	retained    map[*clipole.Offer]context.CancelFunc
	retainedErr error
}

var class struct {
	sync.Once
	name     []uint16
	instance uintptr
	err      error
}
var windows = struct {
	sync.RWMutex
	items map[uintptr]*worker
}{items: make(map[uintptr]*worker)}

// Open begins observing supported format metadata. Data is read only on Read,
// and system clipboard contents change only on Offer/Clear or delayed rendering.
// Use one Host per clipboard endpoint; caller controls direction/focus policy.
// ctx bounds startup only; the returned Host remains open until Close.
func Open(ctx context.Context, o Options) (*Host, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	var err error
	if o, err = options(o); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	tid, _, _ := threadID.Call()
	desktop, _, e := getDesktop.Call(tid)
	runtime.UnlockOSThread()
	if desktop == 0 {
		return nil, winerr("GetThreadDesktop", e)
	}
	h := &Host{commands: make(chan command), changes: make(chan struct{}, 1), errors: make(chan error, 1), stop: make(chan struct{}), done: make(chan struct{}), sampleErr: ErrBusy}
	started := make(chan error, 1)
	go h.run(o, desktop, started)
	select {
	case err = <-started:
		if err != nil {
			<-h.done
			return nil, err
		}
		return h, nil
	case <-ctx.Done():
		h.Close()
		return nil, ctx.Err()
	}
}

// Current returns the most recently observed metadata. Changes coalesces wakeups;
// always read Current after a wakeup. Read checks native ownership again, even
// when the listener has not yet observed a change. ErrBusy retires the old token.
func (h *Host) Current() (Snapshot, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return Snapshot{}, ErrClosed
	}
	s := h.current
	s.Formats = append([]cliprdr.Format(nil), s.Formats...)
	return s, h.sampleErr
}
func (h *Host) Changes() <-chan struct{} { return h.changes }

// Errors coalesces nonterminal rendering/OS errors. Host-generated errors omit
// clipboard contents; Provider is responsible for the text of its own errors.
func (h *Host) Errors() <-chan error  { return h.errors }
func (h *Host) Done() <-chan struct{} { return h.done }

// Err returns the terminal cleanup error after Done closes.
func (h *Host) Err() error { h.mu.Lock(); defer h.mu.Unlock(); return h.terminal }
func (h *Host) Close() {
	h.once.Do(func() {
		h.mu.Lock()
		h.closed = true
		h.wanted = Token{}
		if h.cancel != nil {
			h.cancel()
		}
		if h.file != nil {
			h.file.Close()
		}
		for file := range h.files {
			file.Close()
		}
		h.mu.Unlock()
		close(h.stop)
	})
}
func (h *Host) call(c command) response {
	if c.ctx == nil {
		return response{err: ErrInvalid}
	}
	if err := c.ctx.Err(); err != nil {
		return response{err: err}
	}
	c.reply = make(chan response, 1)
	select {
	case <-h.stop:
		return response{err: ErrClosed}
	default:
	}
	select {
	case h.commands <- c:
	case <-h.stop:
		return response{err: ErrClosed}
	case <-c.ctx.Done():
		return response{err: c.ctx.Err()}
	}
	select {
	case r := <-c.reply:
		return r
	case <-h.stop:
		return response{err: ErrClosed}
	case <-c.ctx.Done():
		return response{err: c.ctx.Err()}
	}
}

// Read copies a single advertised representation after rechecking ownership.
// It returns validated bytes without allocator padding. Context cancellation
// releases the caller but does not claim that a foreign native call has stopped.
func (h *Host) Read(ctx context.Context, token Token, f cliprdr.Format) ([]byte, error) {
	r := h.call(command{ctx: ctx, kind: 'r', token: token, format: f})
	return r.data, r.err
}

// Offer replaces clipboard formats without fetching data. Registered IDs are
// mapped by name to this OS; Provider receives the original remote ID/name.
// Beginning Offer retires the preceding provider, even if installation fails.
// After dispatch, cancellation can race installation: do not replay blindly.
// Already rendered bytes survive Close; unrendered formats disappear with the
// owner window. This is not OLE/file redirection or a clipboard-history manager.
func (h *Host) Offer(ctx context.Context, fs []cliprdr.Format, p Provider) (Token, error) {
	return h.offer(ctx, Token{}, false, fs, p)
}

// OfferIfCurrent installs formats only if expected still identifies the current
// native clipboard when it is opened. It never overwrites a newer local copy
// made while the caller's remote request or the host command was waiting.
func (h *Host) OfferIfCurrent(ctx context.Context, expected Token, fs []cliprdr.Format, p Provider) (Token, error) {
	if expected.id == nil {
		return Token{}, ErrInvalid
	}
	return h.offer(ctx, expected, true, fs, p)
}

func (h *Host) offer(ctx context.Context, expected Token, conditional bool, fs []cliprdr.Format, p Provider) (Token, error) {
	if ctx == nil || (len(fs) != 0 && p == nil) {
		return Token{}, ErrInvalid
	}
	if err := validateFormats(fs); err != nil {
		return Token{}, err
	}
	if err := ctx.Err(); err != nil {
		return Token{}, err
	}
	token := Token{new(identity)}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return Token{}, ErrClosed
	}
	if h.cancel != nil {
		h.cancel()
	}
	h.wanted = token
	h.mu.Unlock()
	r := h.call(command{ctx: ctx, kind: 'o', token: token, expected: expected, conditional: conditional, formats: append([]cliprdr.Format(nil), fs...), provider: p})
	if r.err != nil {
		h.mu.Lock()
		if h.wanted == token {
			h.wanted = Token{}
			if h.cancel != nil {
				h.cancel()
			}
		}
		h.mu.Unlock()
		return Token{}, r.err
	}
	return token, nil
}

// Clear removes only the still-current offer owned by this Host. It never
// empties another application's clipboard or a newer offer with the same IDs.
func (h *Host) Clear(ctx context.Context, token Token) error {
	if ctx == nil || token.id == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	if h.wanted != token {
		h.mu.Unlock()
		return ErrChanged
	}
	if h.cancel != nil {
		h.cancel()
	}
	h.wanted = Token{}
	h.mu.Unlock()
	return h.call(command{ctx: ctx, kind: 'c', token: token}).err
}

func (h *Host) publish(s Snapshot, err error) {
	h.mu.Lock()
	h.current, h.sampleErr = s, err
	h.mu.Unlock()
	select {
	case h.changes <- struct{}{}:
	default:
	}
}
func (h *Host) report(err error) {
	if err == nil {
		return
	}
	select {
	case h.errors <- err:
	default:
		select {
		case <-h.errors:
		default:
		}
		select {
		case h.errors <- err:
		default:
		}
	}
}

func (h *Host) run(o Options, desktop uintptr, started chan<- error) {
	runtime.LockOSThread()
	// Exit while locked so the runtime terminates this private OS thread. It must
	// not reenter the Go thread pool attached to a caller-selected desktop.
	w := &worker{h: h, o: o, desktop: desktop}
	var terminal error
	defer func() {
		h.Close()
		w.closing = true
		terminal = errors.Join(terminal, w.closeFile())
		terminal = errors.Join(terminal, w.closeRetained())
		if w.hwnd != 0 {
			if w.listening {
				if ok, _, e := removeListener.Call(w.hwnd); ok == 0 {
					terminal = errors.Join(terminal, winerr("RemoveClipboardFormatListener", e))
				}
			}
			if ok, _, e := destroyWindow.Call(w.hwnd); ok == 0 {
				terminal = errors.Join(terminal, winerr("DestroyWindow", e))
			}
			windows.Lock()
			delete(windows.items, w.hwnd)
			windows.Unlock()
		}
		h.mu.Lock()
		h.current = Snapshot{}
		h.terminal = terminal
		h.mu.Unlock()
		close(h.changes)
		close(h.errors)
		close(h.done)
	}()
	if ok, _, e := setDesktop.Call(desktop); ok == 0 {
		terminal = winerr("SetThreadDesktop", e)
		started <- terminal
		return
	}
	if err := w.create(); err != nil {
		terminal = err
		started <- err
		return
	}
	w.sample()
	started <- nil
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-h.stop:
			return
		default:
		}
		// Dispatch sent and posted messages on this thread, never the GUI thread.
		for range 64 {
			var msg winMessage
			ok, _, _ := peekMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1)
			if ok == 0 {
				break
			}
			dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
		}
		w.sample()
		w.collectFile()
		select {
		case <-h.stop:
			return
		case <-ticker.C:
		case c := <-h.commands:
			r := response{err: c.ctx.Err()}
			if r.err == nil {
				switch c.kind {
				case 'r':
					r.data, r.err = w.read(c.ctx, c.token, c.format)
				case 'o':
					r.err = w.offerData(c.token, c.expected, c.conditional, c.formats, c.provider)
				case 'c':
					r.err = w.clear(c.token)
				case 'f':
					r.err = w.offerFiles(c)
					if r.err == nil {
						r.file = w.file
					}
				case 'p':
					r.data, r.preferred, r.err = w.readDrop(c.ctx, c.token)
				case 's':
					r = w.sourceInfo(c.token)
				case 'v':
					r.err = w.verifySelection(c.token)
				}
			}
			c.reply <- r
		}
	}
}

func (w *worker) create() error {
	class.Do(func() {
		class.name, _ = syscall.UTF16FromString("rdp-go.Clipboard.v1")
		class.instance, _, _ = module.Call(0)
		wc := winClass{Size: uint32(unsafe.Sizeof(winClass{})), Proc: syscall.NewCallback(windowProc), Instance: class.instance, Name: uintptr(unsafe.Pointer(&class.name[0]))}
		if atom, _, e := registerClass.Call(uintptr(unsafe.Pointer(&wc))); atom == 0 {
			class.err = winerr("RegisterClassEx", e)
		}
	})
	if class.err != nil {
		return class.err
	}
	hwnd, _, e := createWindow.Call(0, uintptr(unsafe.Pointer(&class.name[0])), 0, 0, 0, 0, 0, 0, 0, 0, class.instance, 0)
	if hwnd == 0 {
		return winerr("CreateWindowEx", e)
	}
	w.hwnd = hwnd
	windows.Lock()
	windows.items[hwnd] = w
	windows.Unlock()
	if ok, _, e := addListener.Call(hwnd); ok == 0 {
		return winerr("AddClipboardFormatListener", e)
	}
	w.listening = true
	return nil
}

func windowProc(hwnd uintptr, message uint32, wp, lp uintptr) uintptr {
	windows.RLock()
	w := windows.items[hwnd]
	windows.RUnlock()
	if w != nil {
		switch message {
		case 0x31d:
			w.dirty = true
			return 0 // WM_CLIPBOARDUPDATE
		case 0x305:
			w.render(uint32(wp), time.Now().Add(w.o.RenderTimeout))
			return 0
		case 0x306: // WM_RENDERALLFORMATS: only while we still own the clipboard.
			if !w.closing {
				if ok, _, _ := openClipboard.Call(hwnd); ok != 0 {
					owner, _, _ := getOwner.Call()
					if owner == hwnd {
						deadline := time.Now().Add(w.o.RenderTimeout)
						for id := range w.formats {
							if !time.Now().Before(deadline) {
								break
							}
							w.render(id, deadline)
						}
					}
					closeClipboard.Call()
				}
			}
			return 0 // on shutdown, rendered data stays; unavailable formats go away
		case 0x307: // WM_DESTROYCLIPBOARD
			w.h.mu.Lock()
			if w.h.wanted == w.offer {
				w.h.wanted = Token{}
				if w.h.cancel != nil {
					w.h.cancel()
				}
			}
			w.h.mu.Unlock()
			w.offer, w.provider, w.formats = Token{}, nil, nil
			w.dirty = true
			return 0
		}
	}
	r, _, _ := defWindow.Call(hwnd, uintptr(message), wp, lp)
	return r
}

func nativeStamp() (uintptr, uint32) {
	o, _, _ := getOwner.Call()
	s, _, _ := getSequence.Call()
	return o, uint32(s)
}
func (w *worker) sample() {
	o, seq := nativeStamp()
	if w.valid && o == w.owner && seq == w.sequence && !w.dirty {
		return
	}
	w.dirty = false
	if w.valid && o == w.owner && seq == w.sequence {
		return
	}
	if ok, _, _ := openClipboard.Call(w.hwnd); ok == 0 {
		if w.valid {
			w.valid = false
			w.snapshot = Snapshot{}
			w.h.publish(Snapshot{}, ErrBusy)
		}
		return
	}
	o, seq = nativeStamp()
	formats, files, err := nativeFormats()
	if ok, _, e := closeClipboard.Call(); ok == 0 {
		err = errors.Join(err, winerr("CloseClipboard", e))
	}
	if err != nil {
		w.valid = false
		w.h.publish(Snapshot{}, err)
		return
	}
	w.owner, w.sequence, w.valid = o, seq, true
	own := o == w.hwnd || (w.file != nil && w.file.OwnsCurrent())
	w.snapshot = Snapshot{Token: Token{new(identity)}, Formats: formats, External: !own, Files: files}
	w.h.publish(w.snapshot, nil)
}

func nativeFormats() ([]cliprdr.Format, bool, error) {
	var fs []cliprdr.Format
	var files bool
	id := uintptr(0)
	for count := 0; count < cliprdr.MaxFormats; count++ {
		n, _, err := enumFormats.Call(id)
		if n == 0 {
			if err != syscall.Errno(0) {
				return nil, false, winerr("EnumClipboardFormats", err)
			}
			return fs, files, nil
		}
		id = n
		files = files || id == 15 // CF_HDROP, never included in byte formats
		f := cliprdr.Format{ID: uint32(id)}
		if id >= 0xc000 {
			var name [256]uint16
			n, _, e := formatName.Call(id, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)))
			if n == 0 {
				return nil, false, winerr("GetClipboardFormatName", e)
			}
			f.Name = syscall.UTF16ToString(name[:n])
		}
		files = files || strings.EqualFold(f.Name, cliprdr.FileGroupDescriptorName)
		if supported(f) {
			fs = append(fs, f)
		}
	}
	return nil, false, ErrInvalid
}

func (w *worker) read(ctx context.Context, token Token, f cliprdr.Format) (data []byte, err error) {
	if !w.valid || token.id == nil || token != w.snapshot.Token || !w.snapshot.External {
		return nil, ErrChanged
	}
	found := false
	for _, v := range w.snapshot.Formats {
		if f.ID == v.ID && (f.ID < 0xc000 || strings.EqualFold(f.Name, v.Name)) {
			f = v
			found = true
			break
		}
	}
	if !found {
		return nil, ErrInvalid
	}
	if ok, _, _ := openClipboard.Call(w.hwnd); ok == 0 {
		return nil, ErrBusy
	}
	defer func() {
		if ok, _, e := closeClipboard.Call(); ok == 0 {
			data = nil
			err = errors.Join(err, winerr("CloseClipboard", e))
		}
	}()
	o, seq := nativeStamp()
	if o != w.owner || seq != w.sequence {
		return nil, ErrChanged
	}
	handle, _, e := getData.Call(uintptr(f.ID)) // may synchronously ask another app to render
	if handle == 0 {
		return nil, winerr("GetClipboardData", e)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	after, rendered := nativeStamp()
	if after != o {
		return nil, ErrChanged
	}
	// Clipboard is still held open by this thread. A sequence advance here can
	// be materialization by the existing owner, not a new clipboard item.
	w.sequence = rendered
	n, _, e := size.Call(handle)
	if n == 0 || n > cliprdr.MaxDataBytes {
		return nil, winerr("GlobalSize/bound", e)
	}
	ptr, _, e := lock.Call(handle)
	if ptr == 0 {
		return nil, winerr("GlobalLock", e)
	}
	data = make([]byte, int(n))
	copyMemory.Call(uintptr(unsafe.Pointer(&data[0])), ptr, n)
	if err := unlockBytes(handle); err != nil {
		return nil, err
	}
	return cleanData(f, data)
}

func (w *worker) wanted(token Token) bool {
	w.h.mu.Lock()
	defer w.h.mu.Unlock()
	return !w.h.closed && token.id != nil && w.h.wanted == token
}
func (w *worker) offerData(token, expected Token, conditional bool, fs []cliprdr.Format, provider Provider) (err error) {
	if !w.wanted(token) {
		return ErrChanged
	}
	local := make(map[uint32]cliprdr.Format)
	var ids []uint32
	for _, f := range fs {
		id := f.ID
		if id >= 0xc000 {
			name, _ := syscall.UTF16FromString(f.Name)
			n, _, e := registerFormat.Call(uintptr(unsafe.Pointer(&name[0])))
			if n == 0 {
				return winerr("RegisterClipboardFormat", e)
			}
			id = uint32(n)
		}
		local[id] = f
		ids = append(ids, id)
	}
	if ok, _, _ := openClipboard.Call(w.hwnd); ok == 0 {
		return ErrBusy
	}
	defer func() {
		// Do not leave a partly installed delayed offer with no usable token.
		if err != nil && w.offer == token {
			owner, _ := nativeStamp()
			if owner == w.hwnd {
				if ok, _, e := emptyClipboard.Call(); ok == 0 {
					err = errors.Join(err, winerr("EmptyClipboard rollback", e))
				}
			}
		}
		if ok, _, e := closeClipboard.Call(); ok == 0 {
			err = errors.Join(err, winerr("CloseClipboard", e))
		}
		if w.offer == token && w.file != nil {
			err = errors.Join(err, w.replaceFile())
		}
		w.valid = false
		w.sample()
	}()
	if !w.wanted(token) {
		return ErrChanged
	}
	if conditional {
		owner, sequence := nativeStamp()
		if !w.valid || expected != w.snapshot.Token || owner != w.owner || sequence != w.sequence {
			return ErrChanged
		}
	}
	if ok, _, e := emptyClipboard.Call(); ok == 0 {
		return winerr("EmptyClipboard", e)
	}
	w.offer, w.formats, w.provider = token, local, provider
	for _, id := range ids {
		setData.Call(uintptr(id), 0) // NULL is also the successful delayed handle
		if ok, _, e := formatAvailable.Call(uintptr(id)); ok == 0 {
			return winerr("SetClipboardData delayed", e)
		}
	}
	// The OLE owner was replaced by EmptyClipboard. Join it only after releasing
	// the native clipboard lock; its cleanup must be able to inspect ownership.
	return nil
}
func (w *worker) clear(token Token) (err error) {
	if token != w.offer {
		return ErrChanged
	}
	if w.file != nil {
		if !w.file.OwnsCurrent() {
			return ErrChanged
		}
		err = w.closeFile()
		w.offer = Token{}
		w.valid = false
		w.sample()
		return err
	}
	if ok, _, _ := openClipboard.Call(w.hwnd); ok == 0 {
		return ErrBusy
	}
	defer func() {
		if ok, _, e := closeClipboard.Call(); ok == 0 {
			err = errors.Join(err, winerr("CloseClipboard", e))
		}
		w.valid = false
		w.sample()
	}()
	o, _ := nativeStamp()
	if o != w.hwnd {
		return ErrChanged
	}
	if ok, _, e := emptyClipboard.Call(); ok == 0 {
		return winerr("EmptyClipboard", e)
	}
	return nil
}

func (w *worker) render(id uint32, deadline time.Time) {
	f, ok := w.formats[id]
	if !ok || w.provider == nil || w.closing {
		return
	}
	token := w.offer
	w.h.mu.Lock()
	if w.h.closed || w.h.wanted != token {
		w.h.mu.Unlock()
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	w.h.cancel = cancel
	w.h.mu.Unlock()
	defer cancel()
	b, err := w.provider(ctx, f)
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		b, err = cleanData(f, b)
	}
	if err != nil {
		w.h.report(err)
		return
	}
	handle, err := nativeBytes(b)
	if err != nil {
		w.h.report(err)
		return
	}
	defer func() {
		if handle != 0 {
			free.Call(handle)
		}
	}()
	w.h.mu.Lock()
	defer w.h.mu.Unlock()
	owner, _ := nativeStamp()
	if w.h.closed || w.h.wanted != token || ctx.Err() != nil || owner != w.hwnd {
		return
	}
	// WM_RENDERFORMAT's requesting application already holds the clipboard open.
	// Do not call OpenClipboard here. Ownership transfers only on success.
	if ok, _, e := setData.Call(uintptr(id), handle); ok == 0 {
		w.h.report(winerr("SetClipboardData", e))
		return
	}
	handle = 0
	// Materializing our own delayed format does not create a new clipboard item.
	// Keep its snapshot token valid, including while the requesting app still
	// has the clipboard open and a metadata rescan would report ErrBusy.
	if w.valid && w.owner == w.hwnd {
		_, w.sequence = nativeStamp()
	}
	delete(w.formats, id) // already-rendered formats survive render-all/shutdown
}

func nativeBytes(b []byte) (uintptr, error) {
	if len(b) == 0 || len(b) > cliprdr.MaxDataBytes {
		return 0, ErrInvalid
	}
	handle, _, e := alloc.Call(0x42, uintptr(len(b))) // GMEM_MOVEABLE | GMEM_ZEROINIT
	if handle == 0 {
		return 0, winerr("GlobalAlloc", e)
	}
	p, _, e := lock.Call(handle)
	if p == 0 {
		free.Call(handle)
		return 0, winerr("GlobalLock", e)
	}
	copyMemory.Call(p, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if err := unlockBytes(handle); err != nil {
		free.Call(handle)
		return 0, err
	}
	return handle, nil
}

func unlockBytes(handle uintptr) error {
	if ok, _, e := unlock.Call(handle); ok == 0 && e != syscall.Errno(0) {
		return winerr("GlobalUnlock", e)
	}
	return nil
}
