package ime

import (
	"errors"
	"slices"
	"sort"
	"unsafe"

	"github.com/hq0101/rdp-go/rail"
)

// WindowsDocument supplies a bounded plain-text ITextStoreACP and composition
// owner to a real TSF context. It is a local document, not remote application
// text. It does not forward keys, emit committed input, or render candidates.
// All methods run on the adapter's UI goroutine. Pump must run at safe message
// loop/timer points; no method may be called reentrantly from a native callback.
type WindowsDocument struct {
	adapter          *WindowsAdapter
	store            *acpStore
	manager, context *comObject
	ui               *comObject
	candidateTargets map[*candidateLease]*candidateTarget
	textSub, uiSub   subscription
	cookie           uint32
	pushed, closed   bool
}

// OpenDocument creates and pushes a TSF context without changing native focus.
// Each adapter owns at most one document and closes it before deactivating TSF.
// Closing discards local text; it does not send a commit to the remote session.
func (a *WindowsAdapter) OpenDocument(options WindowsDocumentOptions) (*WindowsDocument, error) {
	if err := a.enter(); err != nil {
		return nil, err
	}
	defer func() { a.busy = false }()
	if a.input != nil {
		return nil, rail.ErrBusy
	}
	return a.openDocument(options)
}

// Caller holds the adapter's busy guard.
func (a *WindowsAdapter) openDocument(options WindowsDocumentOptions) (*WindowsDocument, error) {
	if a.document != nil {
		return nil, rail.ErrBusy
	}
	s, err := newACP(a.thread, a.wnd, a.marker, options)
	if err != nil {
		return nil, err
	}
	d := &WindowsDocument{adapter: a, store: s}
	failed := true
	defer func() {
		if failed {
			d.closeNative()
		}
	}()
	hr := comCall(a.manager, 5, uintptr(unsafe.Pointer(&d.manager)))
	if int32(hr) < 0 {
		return nil, hresult("CreateDocumentMgr", hr)
	}
	if d.manager == nil {
		return nil, ErrUnavailable
	}
	hr = comCall(d.manager, 3, uintptr(a.clientID), 0, s.base, uintptr(unsafe.Pointer(&d.context)), uintptr(unsafe.Pointer(&d.cookie)))
	if int32(hr) < 0 {
		return nil, hresult("CreateContext", hr)
	}
	if d.context == nil {
		return nil, ErrUnavailable
	}
	hr = comCall(d.manager, 4, uintptr(unsafe.Pointer(d.context)))
	if int32(hr) < 0 {
		return nil, hresult("DocumentMgr.Push", hr)
	}
	d.pushed = true
	if err := d.watchText(); err != nil {
		return nil, err
	}
	a.document = d
	failed = false
	return d, nil
}

func (d *WindowsDocument) enter(pending bool) error {
	tid, _, _ := getThread.Call()
	if tid != d.store.thread {
		return ErrThread
	}
	if d.closed {
		return rail.ErrClosed
	}
	if d.store.closed.Load() {
		return ErrUnavailable
	}
	if err := d.adapter.enter(); err != nil {
		return err
	}
	s := d.store
	if s.depth != 0 || s.lock != 0 || s.notifying || s.wiring || (!pending && s.pending != 0) {
		d.adapter.busy = false
		return rail.ErrBusy
	}
	return nil
}
func (d *WindowsDocument) leave() { d.adapter.busy = false }

// Native TSF can enter the store outside an application method. The adapter
// must also reject close/state calls until that native stack has unwound.
func (a *WindowsAdapter) documentBusy() bool {
	if a.document == nil {
		return false
	}
	s := a.document.store
	return s.depth != 0 || s.lock != 0 || s.notifying || s.wiring
}

// Pump services at most one coalesced asynchronous lock request. true means
// more work was requested by the callback; schedule another UI-loop turn.
func (d *WindowsDocument) Pump() (bool, error) {
	if err := d.enter(true); err != nil {
		return false, err
	}
	defer d.leave()
	return d.pump()
}
func (d *WindowsDocument) pump() (bool, error) {
	s := d.store
	if s.pending == 0 {
		return false, nil
	}
	flags := s.pending
	s.pending = 0
	if hr := s.grant(flags); int32(hr) < 0 {
		return s.pending != 0, hresult("OnLockGranted", hr)
	}
	return s.pending != 0, nil
}

// Snapshot must be sampled after Pump reports no pending work. Active
// composition ranges are read from their current native views after callbacks
// have returned. A failed range read never turns preedit into committed text.
func (d *WindowsDocument) Snapshot() (TextSnapshot, error) {
	if err := d.enter(false); err != nil {
		return TextSnapshot{}, err
	}
	defer d.leave()
	return d.snapshot()
}
func (d *WindowsDocument) snapshot() (TextSnapshot, error) {
	s := d.store
	if s.pending != 0 {
		return TextSnapshot{}, rail.ErrBusy
	}
	revision := s.state.revision
	refs := make([]compositionRef, 0, len(s.compositions))
	for _, v := range s.compositions {
		refs = append(refs, v)
	}
	// Retained views belong to this UI thread. Native calls may cause nested
	// notifications, so own temporary references and check the revision again.
	for _, v := range refs {
		comCall(v.view, 1)
	}
	defer func() {
		for _, v := range refs {
			comCall(v.view, 2)
		}
	}()
	var ranges []TextRange
	for _, v := range refs {
		r, err := compositionExtent(v.view)
		if err != nil {
			return TextSnapshot{}, err
		}
		if !s.state.validRange(r.Start, r.End) {
			return TextSnapshot{}, ErrChanged
		}
		ranges = append(ranges, r)
	}
	if s.state.revision != revision {
		return TextSnapshot{}, ErrChanged
	}
	if s.pending != 0 {
		return TextSnapshot{}, rail.ErrBusy
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Start != ranges[j].Start {
			return ranges[i].Start < ranges[j].Start
		}
		return ranges[i].End < ranges[j].End
	})
	return TextSnapshot{Text: append([]uint16(nil), s.state.text...), Selection: s.state.selection, Compositions: ranges, Revision: revision}, nil
}
func compositionExtent(view *comObject) (TextRange, error) {
	var r *comObject
	hr := comCall(view, 4, uintptr(unsafe.Pointer(&r)))
	if int32(hr) < 0 {
		return TextRange{}, hresult("Composition.GetRange", hr)
	}
	if r == nil {
		return TextRange{}, ErrUnavailable
	}
	defer comCall(r, 2)
	acp, err := queryCOM(r, &iidRangeACP)
	if err != nil {
		return TextRange{}, err
	}
	defer comCall(acp, 2)
	var start, n int32
	hr = comCall(acp, 25, uintptr(unsafe.Pointer(&start)), uintptr(unsafe.Pointer(&n)))
	if int32(hr) < 0 {
		return TextRange{}, hresult("RangeACP.GetExtent", hr)
	}
	if start < 0 || n < 0 || int64(start)+int64(n) > 0x7fffffff {
		return TextRange{}, ErrChanged
	}
	return TextRange{start, start + n}, nil
}

// SetText replaces the local document only if revision is still current and no
// composition is active. A notification error may follow a successful local
// change; do not blindly retry. This is not an input commit operation.
func (d *WindowsDocument) SetText(revision uint64, text []uint16, selection TextSelection) error {
	if err := d.enter(false); err != nil {
		return err
	}
	defer d.leave()
	return d.setText(revision, text, selection)
}
func (d *WindowsDocument) setText(revision uint64, text []uint16, selection TextSelection) error {
	s := d.store
	if s.pending != 0 {
		return rail.ErrBusy
	}
	if revision != s.state.revision {
		return ErrChanged
	}
	if len(s.compositions) != 0 {
		return rail.ErrBusy
	}
	if len(text) > s.state.max || !validSelection(selection, len(text)) {
		return rail.ErrInvalid
	}
	old := int32(len(s.state.text))
	if !s.state.replace(0, old, text) {
		return rail.ErrBusy
	}
	s.state.selection = selection
	change := nativeChange{oldEnd: old, newEnd: int32(len(text))}
	return s.notify(&change, true, true)
}

// SetLayout installs actual renderer geometry for exactly the sampled revision.
// It can be updated during composition, but never during a TSF lock callback.
func (d *WindowsDocument) SetLayout(revision uint64, layout TextLayout) error {
	if err := d.enter(false); err != nil {
		return err
	}
	defer d.leave()
	return d.setLayout(revision, layout)
}
func (d *WindowsDocument) setLayout(revision uint64, layout TextLayout) error {
	s := d.store
	if s.pending != 0 {
		return rail.ErrBusy
	}
	if revision != s.state.revision {
		return ErrChanged
	}
	// Render loops may report the same geometry after consuming an invalidation.
	// Avoid changing revisions or generating another layout hint in that case.
	old := s.state.layout
	if s.state.laidOut && old.Screen == layout.Screen && old.Clipped == layout.Clipped && slices.Equal(old.Units, layout.Units) && slices.Equal(old.Carets, layout.Carets) {
		return nil
	}
	if err := s.state.setLayout(layout); err != nil {
		return err
	}
	return s.notify(nil, false, true)
}
func (s *acpStore) notify(change *nativeChange, selection, layout bool) error {
	var hints TextChanges
	if change != nil {
		hints |= TextContentChanged | TextCompositionChanged | TextDisplayChanged
	}
	if selection {
		hints |= TextSelectionChanged
	}
	if layout {
		hints |= TextLayoutChanged
	}
	s.changes.mark(hints)
	p := s.sink
	if p == nil {
		return nil
	}
	subscriber := s.subscriber
	comCall(p, 1)
	defer comCall(p, 2)
	s.notifying = true
	defer func() { s.notifying = false }()
	var err error
	call := func(mask uint32, slot int, args ...uintptr) {
		if s.subscriber != subscriber || s.mask&mask == 0 {
			return
		}
		if hr := comCall(p, slot, args...); int32(hr) < 0 {
			err = errors.Join(err, hresult("TextStore notification", hr))
		}
	}
	if change != nil {
		call(1, 3, 0, uintptr(unsafe.Pointer(change)))
	}
	if selection {
		call(2, 4)
	}
	if layout {
		call(4, 5, 1, 1)
	}
	return err
}

// Focus selects this document in TSF only after the bound native window owns
// foreground keyboard focus. It does not call SetFocus/SetForegroundWindow.
func (d *WindowsDocument) Focus() error {
	if err := d.enter(true); err != nil {
		return err
	}
	defer d.leave()
	return d.focus()
}
func (d *WindowsDocument) focus() error {
	d.dropCandidateTargets()
	if err := d.adapter.focused(); err != nil {
		return err
	}
	if hr := comCall(d.adapter.manager, 8, uintptr(unsafe.Pointer(d.manager))); int32(hr) < 0 {
		return hresult("ThreadMgr.SetFocus", hr)
	}
	if err := d.adapter.focused(); err != nil {
		return errors.Join(err, d.blur())
	}
	return nil
}
func (d *WindowsDocument) ownsFocus() (bool, error) {
	if d.manager == nil || d.adapter.manager == nil {
		return false, nil
	}
	var p *comObject
	hr := comCall(d.adapter.manager, 7, uintptr(unsafe.Pointer(&p)))
	if int32(hr) < 0 {
		return false, hresult("ThreadMgr.GetFocus", hr)
	}
	if p == nil {
		return false, nil
	}
	defer comCall(p, 2)
	x, err := queryCOM(p, &iidUnknown)
	if err != nil {
		return false, err
	}
	defer comCall(x, 2)
	y, err := queryCOM(d.manager, &iidUnknown)
	if err != nil {
		return false, err
	}
	defer comCall(y, 2)
	return x == y, nil
}
func (d *WindowsDocument) blur() error {
	d.dropCandidateTargets()
	ours, err := d.ownsFocus()
	if err != nil {
		return err
	}
	if ours {
		if hr := comCall(d.adapter.manager, 8, 0); int32(hr) < 0 {
			return hresult("ThreadMgr.ClearFocus", hr)
		}
	}
	return nil
}

// Blur clears TSF focus only if it still belongs to this document. It does not
// interpret composition termination as a remote input commit or restore an
// external document selected before Focus. The application owns focus routing.
func (d *WindowsDocument) Blur() error {
	if err := d.enter(true); err != nil {
		return err
	}
	defer d.leave()
	return d.blur()
}

func (d *WindowsDocument) closeNative() error {
	if d.closed {
		return nil
	}
	d.closed = true
	s := d.store
	s.closed.Store(true)
	s.pending = 0
	err := errors.Join(d.unwatchText(), d.blur())
	if d.pushed {
		if hr := comCall(d.manager, 5, 1); int32(hr) < 0 {
			err = errors.Join(err, hresult("DocumentMgr.Pop", hr))
		}
		d.pushed = false
	}
	if d.context != nil {
		comCall(d.context, 2)
		d.context = nil
	}
	if d.manager != nil {
		comCall(d.manager, 2)
		d.manager = nil
	}
	s.releaseSink()
	refs := s.compositions
	s.compositions = make(map[uintptr]compositionRef)
	for _, v := range refs {
		comCall(v.view, 2)
		comCall(v.identity, 2)
	}
	s.state.text = nil
	s.state.layout = TextLayout{}
	s.state.laidOut = false
	acpRelease(s.base)
	return err
}
func (d *WindowsDocument) Close() error {
	tid, _, _ := getThread.Call()
	if tid != d.store.thread {
		return ErrThread
	}
	if d.closed {
		return nil
	}
	a, s := d.adapter, d.store
	if a.busy || s.depth != 0 || s.lock != 0 || s.notifying || s.wiring {
		return rail.ErrBusy
	}
	a.busy = true
	defer func() { a.busy = false }()
	err := d.closeNative()
	if a.document == d {
		a.document = nil
	}
	return err
}
