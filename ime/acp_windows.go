package ime

import (
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/hq0101/rdp-go/rail"
)

var (
	iidTextStore       = rail.GUID{Data1: 0x28888fe3, Data2: 0xc2a0, Data3: 0x483a, Data4: [8]byte{0xa3, 0xea, 0x8c, 0xb1, 0xce, 0x51, 0xff, 0x3d}}
	iidTextSink        = rail.GUID{Data1: 0x22d44c94, Data2: 0xa419, Data3: 0x4542, Data4: [8]byte{0xa2, 0x72, 0xae, 0x26, 0x09, 0x3e, 0xce, 0xcf}}
	iidCompositionSink = rail.GUID{Data1: 0x5f20aa40, Data2: 0xb57a, Data3: 0x4f34, Data4: [8]byte{0x96, 0xab, 0x35, 0x76, 0xf3, 0x77, 0xcc, 0x79}}
	iidRangeACP        = rail.GUID{Data1: 0x057a6296, Data2: 0x029b, Data3: 0x4154, Data4: [8]byte{0xb7, 0x9a, 0x0d, 0x46, 0x1d, 0x4e, 0xa9, 0x4c}}
	acpOnce            sync.Once
	acpVtable          [29]uintptr
	compositionVtable  [6]uintptr
	stores             = struct {
		sync.Mutex
		live map[uintptr]*acpStore
	}{live: make(map[uintptr]*acpStore)}
)

const (
	eInvalid       uintptr = 0x80070057
	eNotImpl       uintptr = 0x80004001
	eFail          uintptr = 0x80004005
	eThread        uintptr = 0x8001010e
	eNoConnection  uintptr = 0x80040200
	eAdviseLimit   uintptr = 0x80040201
	tsInvalidPos   uintptr = 0x80040200
	tsNoLock       uintptr = 0x80040201
	tsNoObject     uintptr = 0x80040202
	tsNoSelection  uintptr = 0x80040205
	tsNoLayout     uintptr = 0x80040206
	tsInvalidPoint uintptr = 0x80040207
	tsSynchronous  uintptr = 0x80040208
	tsAsync        uintptr = 0x00040300
	maxTextStores          = 64
)

type nativeSelection struct {
	start, end int32
	active     uint32
	interim    int32
}
type nativeChange struct{ start, oldEnd, newEnd int32 }
type nativeRun struct{ count, kind uint32 }
type nativeStatus struct{ dynamic, static uint32 }
type nativePoint struct{ x, y int32 }
type compositionRef struct{ identity, view *comObject }
type acpStore struct {
	base, composition, thread, wnd uintptr
	marker                         uintptr
	refs                           uint32 // stores.Mutex; all other mutable fields are UI-thread only
	closed                         atomic.Bool
	state                          textState
	changes                        textChangeState
	sink, identity                 *comObject
	mask, lock, pending            uint32
	subscriber                     uint64
	depth                          int
	notifying, wiring              bool
	compositions                   map[uintptr]compositionRef
}

func initACP() {
	acpOnce.Do(func() {
		q, a, r := syscall.NewCallback(acpQuery), syscall.NewCallback(acpAddRef), syscall.NewCallback(acpRelease)
		acpVtable = [29]uintptr{q, a, r, syscall.NewCallback(acpAdvise), syscall.NewCallback(acpUnadvise), syscall.NewCallback(acpRequestLock), syscall.NewCallback(acpStatus), syscall.NewCallback(acpQueryInsert), syscall.NewCallback(acpGetSelection), syscall.NewCallback(acpSetSelection), syscall.NewCallback(acpGetText), syscall.NewCallback(acpSetText), syscall.NewCallback(acpFormatted), syscall.NewCallback(acpEmbedded), syscall.NewCallback(acpQueryEmbedded), syscall.NewCallback(acpInsertEmbedded), syscall.NewCallback(acpInsert), syscall.NewCallback(acpInsertEmbeddedSelection), syscall.NewCallback(acpSupportedAttrs), syscall.NewCallback(acpAttrsAt), syscall.NewCallback(acpAttrsAt), syscall.NewCallback(acpFindAttrs), syscall.NewCallback(acpRetrieveAttrs), syscall.NewCallback(acpEnd), syscall.NewCallback(acpActiveView), syscall.NewCallback(acpPoint), syscall.NewCallback(acpTextExt), syscall.NewCallback(acpScreen), syscall.NewCallback(acpWnd)}
		compositionVtable = [6]uintptr{q, a, r, syscall.NewCallback(acpCompositionStart), syscall.NewCallback(acpCompositionUpdate), syscall.NewCallback(acpCompositionEnd)}
	})
}
func newACP(thread, wnd, marker uintptr, o WindowsDocumentOptions) (*acpStore, error) {
	state, err := newTextState(o)
	if err != nil {
		return nil, err
	}
	initACP()
	stores.Lock()
	full := len(stores.live)/2 >= maxTextStores
	stores.Unlock()
	if full {
		return nil, rail.ErrBusy
	}
	p, _, _ := taskAlloc.Call(2 * unsafe.Sizeof(uintptr(0)))
	if p == 0 {
		return nil, ErrUnavailable
	}
	vs := [2]uintptr{uintptr(unsafe.Pointer(&acpVtable)), uintptr(unsafe.Pointer(&compositionVtable))}
	copyNative.Call(p, uintptr(unsafe.Pointer(&vs[0])), unsafe.Sizeof(vs))
	s := &acpStore{base: p, composition: p + unsafe.Sizeof(uintptr(0)), thread: thread, wnd: wnd, marker: marker, refs: 1, state: state, compositions: make(map[uintptr]compositionRef)}
	stores.Lock()
	if len(stores.live)/2 >= maxTextStores {
		stores.Unlock()
		taskFree.Call(p)
		return nil, rail.ErrBusy
	}
	stores.live[s.base] = s
	stores.live[s.composition] = s
	stores.Unlock()
	return s, nil
}
func acpQuery(this uintptr, id *rail.GUID, out *uintptr) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	if id == nil {
		return ePointer
	}
	stores.Lock()
	defer stores.Unlock()
	s := stores.live[this]
	if s == nil {
		return eUnexpected
	}
	var p uintptr
	switch *id {
	case iidUnknown, iidTextStore:
		p = s.base
	case iidCompositionSink:
		p = s.composition
	default:
		return eNoInterface
	}
	if s.refs == ^uint32(0) {
		return eUnexpected
	}
	s.refs++
	*out = p
	return 0
}
func acpAddRef(this uintptr) uintptr {
	stores.Lock()
	defer stores.Unlock()
	s := stores.live[this]
	if s == nil {
		return 0
	}
	if s.refs != ^uint32(0) {
		s.refs++
	}
	return uintptr(s.refs)
}
func acpRelease(this uintptr) uintptr {
	stores.Lock()
	s := stores.live[this]
	if s == nil {
		stores.Unlock()
		return 0
	}
	if s.refs == ^uint32(0) {
		stores.Unlock()
		return uintptr(s.refs)
	}
	s.refs--
	n := s.refs
	if n == 0 {
		delete(stores.live, s.base)
		delete(stores.live, s.composition)
	}
	stores.Unlock()
	if n == 0 {
		taskFree.Call(s.base)
	}
	return uintptr(n)
}
func enterACP(this uintptr, allowClosed bool) (*acpStore, uintptr) {
	stores.Lock()
	s := stores.live[this]
	stores.Unlock()
	if s == nil {
		return nil, eUnexpected
	}
	tid, _, _ := getThread.Call()
	if tid != s.thread {
		return nil, eThread
	}
	if s.closed.Load() && !allowClosed {
		return nil, eUnexpected
	}
	if !allowClosed && s.wnd != 0 {
		owner, _, _ := windowThread.Call(s.wnd, 0)
		marker, _, _ := getProp.Call(s.wnd, uintptr(unsafe.Pointer(propertyName)))
		if owner != s.thread || marker == 0 || marker != s.marker {
			return nil, eUnexpected
		}
	}
	s.depth++
	return s, 0
}
func (s *acpStore) leave() { s.depth-- }
func (s *acpStore) locked(write bool) bool {
	if write {
		return s.lock&6 == 6
	}
	return s.lock&2 != 0
}
func (s *acpStore) releaseSink() {
	p, id := s.sink, s.identity
	if (p != nil || id != nil) && s.subscriber != ^uint64(0) {
		s.subscriber++
	}
	s.sink = nil
	s.identity = nil
	s.mask = 0
	s.pending = 0
	if p != nil {
		comCall(p, 2)
	}
	if id != nil {
		comCall(id, 2)
	}
}
func acpAdvise(this uintptr, id *rail.GUID, p *comObject, mask uint32) uintptr {
	if id == nil || p == nil {
		return ePointer
	}
	if *id != iidTextSink {
		return eInvalid
	}
	if mask&^uint32(31) != 0 {
		return eInvalid
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if s.wiring {
		return eUnexpected
	}
	s.wiring = true
	defer func() { s.wiring = false }()
	identity, err := queryCOM(p, &iidUnknown)
	if err != nil {
		return eNoInterface
	}
	if s.identity != nil {
		defer comCall(identity, 2)
		if identity != s.identity {
			return eAdviseLimit
		}
		s.mask = mask
		return 0
	}
	if s.subscriber == ^uint64(0) {
		comCall(identity, 2)
		return eAdviseLimit
	}
	sink, err := queryCOM(p, &iidTextSink)
	if err != nil {
		comCall(identity, 2)
		return eNoInterface
	}
	s.sink, s.identity, s.mask = sink, identity, mask
	s.subscriber++
	return 0
}
func acpUnadvise(this uintptr, p *comObject) uintptr {
	if p == nil {
		return ePointer
	}
	s, hr := enterACP(this, true)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if s.wiring {
		return eUnexpected
	}
	s.wiring = true
	defer func() { s.wiring = false }()
	id, err := queryCOM(p, &iidUnknown)
	if err != nil {
		return eNoInterface
	}
	defer comCall(id, 2)
	if s.identity == nil || s.identity != id {
		return eNoConnection
	}
	s.releaseSink()
	return 0
}
func (s *acpStore) grant(flags uint32) uintptr {
	p := s.sink
	if p == nil {
		return eUnexpected
	}
	comCall(p, 1)
	defer comCall(p, 2)
	s.lock = flags & 6
	defer func() { s.lock = 0 }()
	return comCall(p, 8, uintptr(s.lock))
}
func acpRequestLock(this uintptr, flags uint32, session *uint32) uintptr {
	if session == nil {
		return ePointer
	}
	*session = uint32(eFail)
	if flags&^uint32(7) != 0 || (flags&6 != 2 && flags&6 != 6) {
		return eInvalid
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if s.sink == nil || s.wiring {
		return eUnexpected
	}
	if s.lock != 0 || s.notifying {
		if flags&1 != 0 {
			*session = uint32(tsSynchronous)
			return 0
		}
		if s.lock != 0 && !(s.lock == 2 && flags&6 == 6) {
			return eUnexpected
		}
		s.pending |= flags & 6
		*session = uint32(tsAsync)
		return 0
	}
	// A successful synchronous request supersedes an outstanding async lock.
	// An async request is coalesced with existing pending write access.
	oldPending, subscriber := s.pending, s.subscriber
	if flags&1 != 0 {
		s.pending = 0
	} else if s.pending != 0 {
		s.pending |= flags & 6
		*session = uint32(tsAsync)
		return 0
	}
	granted := s.grant(flags)
	if int32(granted) < 0 && s.subscriber == subscriber && s.sink != nil {
		s.pending |= oldPending
	}
	*session = uint32(granted)
	return 0
}
func acpStatus(this uintptr, out *nativeStatus) uintptr {
	if out == nil {
		return ePointer
	}
	*out = nativeStatus{}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	out.static = 8
	return 0 // no hidden text
}
func acpQueryInsert(this uintptr, start, end int32, n uint32, outStart, outEnd *int32) uintptr {
	if outStart == nil || outEnd == nil {
		return ePointer
	}
	*outStart = 0
	*outEnd = 0
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if !s.state.canReplace(start, end, n) {
		return eInvalid
	}
	*outStart = start
	*outEnd = end
	return 0
}
func acpGetSelection(this uintptr, index, count uint32, out *nativeSelection, fetched *uint32) uintptr {
	if fetched == nil {
		return ePointer
	}
	*fetched = 0
	if count != 0 && out == nil {
		return ePointer
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if !s.locked(false) {
		return tsNoLock
	}
	if index != 0 && index != ^uint32(0) {
		return tsNoSelection
	}
	if count == 0 {
		return 0
	}
	v := s.state.selection
	*out = nativeSelection{start: v.Start, end: v.End, active: v.ActiveEnd}
	if v.Interim {
		out.interim = 1
	}
	*fetched = 1
	return 0
}
func acpSetSelection(this uintptr, count uint32, in *nativeSelection) uintptr {
	if count != 1 {
		return eInvalid
	}
	if in == nil {
		return ePointer
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if !s.locked(true) {
		return tsNoLock
	}
	v := TextSelection{Start: in.start, End: in.end, ActiveEnd: in.active, Interim: in.interim != 0}
	if !validSelection(v, len(s.state.text)) {
		return tsInvalidPos
	}
	if s.state.selection == v {
		return 0
	}
	if !s.state.bump() {
		return eUnexpected
	}
	s.state.selection = v
	s.changes.mark(TextSelectionChanged)
	return 0
}
func acpGetText(this uintptr, start, end int32, out *uint16, want uint32, got *uint32, runs *nativeRun, wantRuns uint32, gotRuns *uint32, next *int32) uintptr {
	if got == nil || gotRuns == nil || next == nil {
		return ePointer
	}
	*got = 0
	*gotRuns = 0
	*next = start
	if want != 0 && out == nil || wantRuns != 0 && runs == nil {
		return ePointer
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if !s.locked(false) {
		return tsNoLock
	}
	if end == -1 {
		end = int32(len(s.state.text))
	}
	if !s.state.validRange(start, end) {
		return tsInvalidPos
	}
	n := uint32(end - start)
	if want != 0 {
		n = min(n, want)
	} else if wantRuns == 0 {
		n = 0
	}
	if want != 0 && n != 0 {
		copy(unsafe.Slice(out, int(n)), s.state.text[start:start+int32(n)])
		*got = n
	}
	if wantRuns != 0 && n != 0 {
		*runs = nativeRun{count: n}
		*gotRuns = 1
	}
	*next = start + int32(n)
	return 0
}
func (s *acpStore) set(start, end int32, text *uint16, n uint32, change *nativeChange) uintptr {
	if !s.state.canReplace(start, end, n) {
		return tsInvalidPos
	}
	if n != 0 && text == nil {
		return ePointer
	}
	if !s.state.replace(start, end, unsafe.Slice(text, int(n))) {
		return eUnexpected
	}
	// TSF inserts select the replacement range; a later SetSelection moves the
	// caret. Keep GetSelection consistent with InsertTextAtSelection's outputs.
	s.state.selection = TextSelection{Start: start, End: start + int32(n), ActiveEnd: 2}
	s.changes.mark(TextAllChanged &^ TextCandidatesChanged)
	*change = nativeChange{start: start, oldEnd: end, newEnd: start + int32(n)}
	return 0
}
func acpSetText(this uintptr, flags uint32, start, end int32, text *uint16, n uint32, change *nativeChange) uintptr {
	if change == nil {
		return ePointer
	}
	*change = nativeChange{}
	if flags&^uint32(1) != 0 {
		return eInvalid
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if !s.locked(true) {
		return tsNoLock
	}
	return s.set(start, end, text, n, change)
}
func acpInsert(this uintptr, flags uint32, text *uint16, n uint32, start, end *int32, change *nativeChange) uintptr {
	if flags > 2 {
		return eInvalid
	}
	if flags != 1 && (start == nil || end == nil) {
		return ePointer
	}
	if flags != 2 && change == nil {
		return ePointer
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if !s.locked(flags != 2) {
		return tsNoLock
	}
	a, b := s.state.selection.Start, s.state.selection.End
	if !s.state.canReplace(a, b, n) {
		return tsInvalidPos
	}
	if flags == 2 {
		*start = a
		*end = b
		return 0
	}
	if hr = s.set(a, b, text, n, change); hr != 0 {
		return hr
	}
	if flags != 1 {
		*start = a
		*end = a + int32(n)
	}
	return 0
}

// Plain text only: no data objects, embedded objects or application attributes.
// TSF itself owns its composition/display properties in the context.
func acpFormatted(this uintptr, start, end int32, out *uintptr) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	return eNotImpl
}
func acpEmbedded(this uintptr, pos int32, service, iid *rail.GUID, out *uintptr) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	return tsNoObject
}
func acpQueryEmbedded(this uintptr, service *rail.GUID, format uintptr, out *int32) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	return 0
}
func acpInsertEmbedded(this uintptr, flags uint32, start, end int32, obj uintptr, change *nativeChange) uintptr {
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	return eNotImpl
}
func acpInsertEmbeddedSelection(this uintptr, flags uint32, obj uintptr, start, end *int32, change *nativeChange) uintptr {
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	return eNotImpl
}
func acpSupportedAttrs(this uintptr, flags, count uint32, attrs *rail.GUID) uintptr {
	if count != 0 && attrs == nil {
		return ePointer
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	return 0
}
func acpAttrsAt(this uintptr, pos int32, count uint32, attrs *rail.GUID, flags uint32) uintptr {
	if count != 0 && attrs == nil {
		return ePointer
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if !s.state.validRange(pos, pos) {
		return tsInvalidPos
	}
	return 0
}
func acpFindAttrs(this uintptr, start, halt int32, count uint32, attrs *rail.GUID, flags uint32, next *int32, found *int32, offset *int32) uintptr {
	if next == nil || found == nil || offset == nil {
		return ePointer
	}
	*next = 0
	*found = 0
	*offset = 0
	if count != 0 && attrs == nil {
		return ePointer
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if !s.locked(false) {
		return tsNoLock
	}
	if !s.state.validRange(start, start) || !s.state.validRange(halt, halt) {
		return tsInvalidPos
	}
	*next = halt
	return 0
}
func acpRetrieveAttrs(this uintptr, count uint32, attrs uintptr, fetched *uint32) uintptr {
	if fetched == nil {
		return ePointer
	}
	*fetched = 0
	if count != 0 && attrs == 0 {
		return ePointer
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	return 0
}
func acpEnd(this uintptr, out *int32) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if !s.locked(false) {
		return tsNoLock
	}
	*out = int32(len(s.state.text))
	return 0
}
func acpActiveView(this uintptr, out *uint32) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	*out = 1
	return 0
}
func acpPoint(this uintptr, view uint32, p *nativePoint, flags uint32, out *int32) uintptr {
	if p == nil || out == nil {
		return ePointer
	}
	*out = 0
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if !s.locked(false) {
		return tsNoLock
	}
	if view != 1 || flags&^uint32(3) != 0 {
		return eInvalid
	}
	if !s.state.laidOut {
		return tsNoLayout
	}
	v, ok := s.state.point(p.x, p.y, flags)
	if !ok {
		return tsInvalidPoint
	}
	*out = v
	return 0
}
func acpTextExt(this uintptr, view uint32, start, end int32, out *TextRect, clipped *int32) uintptr {
	if out == nil || clipped == nil {
		return ePointer
	}
	*out = TextRect{}
	*clipped = 0
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if !s.locked(false) {
		return tsNoLock
	}
	if view != 1 {
		return eInvalid
	}
	if !s.state.validRange(start, end) {
		return tsInvalidPos
	}
	v, ok := s.state.bounds(start, end)
	if !ok {
		return tsNoLayout
	}
	*out = v
	if s.state.layout.Clipped {
		*clipped = 1
	}
	return 0
}
func acpScreen(this uintptr, view uint32, out *TextRect) uintptr {
	if out == nil {
		return ePointer
	}
	*out = TextRect{}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if view != 1 {
		return eInvalid
	}
	if s.state.laidOut {
		*out = s.state.layout.Screen
	}
	return 0
}
func acpWnd(this uintptr, view uint32, out *uintptr) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	if view != 1 {
		return eInvalid
	}
	*out = s.wnd
	return 0
}

func acpCompositionStart(this uintptr, view *comObject, ok *int32) uintptr {
	if ok == nil || view == nil {
		return ePointer
	}
	*ok = 0
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	id, err := queryCOM(view, &iidUnknown)
	if err != nil {
		return eNoInterface
	}
	key := uintptr(unsafe.Pointer(id))
	if _, exists := s.compositions[key]; exists {
		comCall(id, 2)
		*ok = 1
		return 0
	}
	if len(s.compositions) >= 8 || !s.state.bump() {
		comCall(id, 2)
		return 0
	}
	comCall(view, 1)
	s.compositions[key] = compositionRef{identity: id, view: view}
	s.changes.mark(TextCompositionChanged)
	*ok = 1
	return 0
}
func acpCompositionUpdate(this uintptr, view, rangeNew *comObject) uintptr {
	if view == nil {
		return ePointer
	}
	s, hr := enterACP(this, false)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	id, err := queryCOM(view, &iidUnknown)
	if err != nil {
		return eNoInterface
	}
	defer comCall(id, 2)
	if _, ok := s.compositions[uintptr(unsafe.Pointer(id))]; !ok {
		return eInvalid
	}
	s.changes.mark(TextCompositionChanged)
	// The new range is applied after this callback returns. Snapshot later asks
	// the retained view for its current range instead of caching the old one.
	if !s.state.bump() {
		return eUnexpected
	}
	return 0
}
func acpCompositionEnd(this uintptr, view *comObject) uintptr {
	if view == nil {
		return ePointer
	}
	s, hr := enterACP(this, true)
	if hr != 0 {
		return hr
	}
	defer s.leave()
	id, err := queryCOM(view, &iidUnknown)
	if err != nil {
		return eNoInterface
	}
	defer comCall(id, 2)
	key := uintptr(unsafe.Pointer(id))
	v, ok := s.compositions[key]
	if !ok {
		return 0
	}
	delete(s.compositions, key)
	changed := s.state.bump()
	s.changes.mark(TextCompositionChanged)
	comCall(v.view, 2)
	comCall(v.identity, 2)
	if !changed {
		// The composition has ended natively, but its revision cannot advance.
		// Reject further snapshots until Close rather than publish an ambiguous
		// unchanged revision that could be mistaken for committed input.
		s.closed.Store(true)
		return eUnexpected
	}
	return 0
}
