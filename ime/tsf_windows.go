package ime

import (
	"errors"
	"github.com/hq0101/rdp-go/rail"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var (
	iidUnknown         = rail.GUID{Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidSource          = rail.GUID{Data1: 0x4ea48a35, Data2: 0x60ae, Data3: 0x446f, Data4: [8]byte{0x8f, 0xd6, 0xe6, 0xa8, 0xd8, 0x24, 0x59, 0xf7}}
	iidCompartments    = rail.GUID{Data1: 0x7dcf57ac, Data2: 0x18ad, Data3: 0x438b, Data4: [8]byte{0x82, 0x4d, 0x97, 0x9b, 0xff, 0xb7, 0x4b, 0x7c}}
	iidCompartmentSink = rail.GUID{Data1: 0x743abd5f, Data2: 0xf26d, Data3: 0x48df, Data4: [8]byte{0x8c, 0xc5, 0x23, 0x84, 0x92, 0x41, 0x9b, 0x64}}
	iidProfileSink     = rail.GUID{Data1: 0x71c6e74e, Data2: 0x0f28, Data3: 0x11d8, Data4: [8]byte{0xa8, 0x2a, 0, 6, 0x5b, 0x84, 0x43, 0x5c}}
	compartmentIDs     = [3]rail.GUID{
		{Data1: 0x58273aad, Data2: 0x01bb, Data3: 0x4164, Data4: [8]byte{0x95, 0xc6, 0x75, 0x5b, 0xa0, 0xb5, 0x16, 0x2d}},
		{Data1: 0xccf05dd8, Data2: 0x4a87, Data3: 0x11d7, Data4: [8]byte{0xa6, 0xe2, 0, 6, 0x5b, 0x84, 0x43, 0x5c}},
		{Data1: 0xccf05dd9, Data2: 0x4a87, Data3: 0x11d7, Data4: [8]byte{0xa6, 0xe2, 0, 6, 0x5b, 0x84, 0x43, 0x5c}},
	}
	taskAlloc                        = ole32.NewProc("CoTaskMemAlloc")
	taskFree                         = ole32.NewProc("CoTaskMemFree")
	copyNative                       = kernel32.NewProc("RtlMoveMemory")
	variantClear                     = syscall.NewLazyDLL("oleaut32.dll").NewProc("VariantClear")
	sinkOnce                         sync.Once
	profileVtable, compartmentVtable [4]uintptr
	sinks                            = struct {
		sync.Mutex
		live map[uintptr]*tsfSink
	}{live: make(map[uintptr]*tsfSink)}
)

const maxNativeSinks = 256 // Includes sinks retained by a source after failed detach.
const (
	eNoInterface uintptr = 0x80004002
	ePointer     uintptr = 0x80004003
	eUnexpected  uintptr = 0x8000ffff
)

type changeState struct {
	bits   atomic.Uint32
	closed atomic.Bool
}

func (s *changeState) add(v WindowsChanges) {
	if !s.closed.Load() {
		s.bits.Or(uint32(v))
	}
}
func (s *changeState) take() WindowsChanges {
	v := s.bits.Swap(0)
	if s.closed.Load() {
		return 0
	}
	return WindowsChanges(v)
}
func (s *changeState) close() { s.closed.Store(true); s.bits.Store(0) }

// The COM instance itself is native memory containing only a vtable address.
// The registry roots Go state while ANY COM reference remains, even after the
// adapter closes. Callbacks never call Host code, change focus, or write state.
type tsfSink struct {
	refs             uint32 // under sinks.Mutex
	iid, compartment rail.GUID
	change           WindowsChanges
	state            *changeState
	text             *textChangeState
}

func sinkCallbacks() {
	sinkOnce.Do(func() {
		query, add, release := syscall.NewCallback(sinkQuery), syscall.NewCallback(sinkAddRef), syscall.NewCallback(sinkRelease)
		profileVtable = [4]uintptr{query, add, release, syscall.NewCallback(sinkProfile)}
		compartmentVtable = [4]uintptr{query, add, release, syscall.NewCallback(sinkCompartment)}
		textEditVtable = [4]uintptr{query, add, release, syscall.NewCallback(sinkTextEdit)}
		uiElementVtable = [6]uintptr{query, add, release, syscall.NewCallback(sinkUIBegin), syscall.NewCallback(sinkUIUpdate), syscall.NewCallback(sinkUIUpdate)}
	})
}
func newSink(state *changeState, iid, compartment rail.GUID, change WindowsChanges) (uintptr, error) {
	sinkCallbacks()
	vt := &compartmentVtable
	if iid == iidProfileSink {
		vt = &profileVtable
	}
	return allocateSink(&tsfSink{refs: 1, iid: iid, compartment: compartment, change: change, state: state}, uintptr(unsafe.Pointer(vt)))
}
func allocateSink(s *tsfSink, vtAddress uintptr) (uintptr, error) {
	sinks.Lock()
	if len(sinks.live) >= maxNativeSinks {
		sinks.Unlock()
		return 0, rail.ErrBusy
	}
	sinks.Unlock()
	// Native allocation/free can invoke process-installed allocator hooks.
	// Never hold the callback registry lock across either native operation.
	p, _, _ := taskAlloc.Call(unsafe.Sizeof(uintptr(0)))
	if p == 0 {
		return 0, ErrUnavailable
	}
	// CoTaskMemAlloc returns a native address, not a Go pointer. Copy the
	// permanent vtable address through Win32 without a uintptr-to-Go conversion.
	copyNative.Call(p, uintptr(unsafe.Pointer(&vtAddress)), unsafe.Sizeof(vtAddress))
	sinks.Lock()
	// Allocation may have reentered, or another UI thread may have subscribed.
	if len(sinks.live) >= maxNativeSinks {
		sinks.Unlock()
		taskFree.Call(p)
		return 0, rail.ErrBusy
	}
	sinks.live[p] = s
	sinks.Unlock()
	return p, nil
}
func sinkQuery(this uintptr, iid *rail.GUID, out *uintptr) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	if iid == nil {
		return ePointer
	}
	requested := *iid
	sinks.Lock()
	defer sinks.Unlock()
	s := sinks.live[this]
	if s == nil {
		return eUnexpected
	}
	if requested != iidUnknown && requested != s.iid {
		return eNoInterface
	}
	if s.refs == ^uint32(0) {
		return eUnexpected
	}
	s.refs++
	*out = this
	return 0
}
func sinkAddRef(this uintptr) uintptr {
	sinks.Lock()
	defer sinks.Unlock()
	s := sinks.live[this]
	if s == nil {
		return 0
	}
	if s.refs != ^uint32(0) {
		s.refs++
	}
	return uintptr(s.refs)
}
func sinkRelease(this uintptr) uintptr {
	sinks.Lock()
	s := sinks.live[this]
	if s == nil {
		sinks.Unlock()
		return 0
	}
	// A saturated invalid refcount is never allowed to wrap and free a live sink.
	if s.refs == ^uint32(0) {
		sinks.Unlock()
		return uintptr(s.refs)
	}
	s.refs--
	n := s.refs
	if n == 0 {
		delete(sinks.live, this)
	}
	sinks.Unlock()
	if n == 0 {
		taskFree.Call(this)
	}
	return uintptr(n)
}
func sinkProfile(this uintptr, profileType uint32, language uint16, clsid, category, profile *rail.GUID, layout uintptr, flags uint32) uintptr {
	if profileType != 1 && profileType != 2 {
		return 0
	}
	if profileType == 1 && (category == nil || *category != keyboardCategory) {
		return 0
	}
	sinks.Lock()
	s := sinks.live[this]
	if s != nil && s.iid == iidProfileSink {
		s.state.add(WindowsAllChanged)
	}
	sinks.Unlock()
	return 0
}
func sinkCompartment(this uintptr, guid *rail.GUID) uintptr {
	if guid == nil {
		return ePointer
	}
	id := *guid
	sinks.Lock()
	s := sinks.live[this]
	if s != nil && s.iid == iidCompartmentSink && id == s.compartment {
		s.state.add(s.change)
	}
	sinks.Unlock()
	return 0
}

func queryCOM(p *comObject, iid *rail.GUID) (*comObject, error) {
	var out *comObject
	hr := comCall(p, 0, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))
	if hr != 0 {
		// Even a faulty provider's failure output is an owned COM reference.
		if out != nil {
			comCall(out, 2)
		}
		return nil, hresult("QueryInterface", hr)
	}
	if out == nil {
		return nil, ErrUnavailable
	}
	return out, nil
}

type subscription struct {
	source  *comObject
	sink    uintptr
	cookie  uint32
	advised bool
}

func subscribe(p *comObject, state *changeState, iid, id rail.GUID, change WindowsChanges) (subscription, error) {
	var sub subscription
	var err error
	sub.source, err = queryCOM(p, &iidSource)
	if err != nil {
		return sub, err
	}
	sub.sink, err = newSink(state, iid, id, change)
	if err != nil {
		comCall(sub.source, 2)
		return subscription{}, err
	}
	hr := comCall(sub.source, 3, uintptr(unsafe.Pointer(&iid)), sub.sink, uintptr(unsafe.Pointer(&sub.cookie)))
	if int32(hr) < 0 {
		sinkRelease(sub.sink)
		comCall(sub.source, 2)
		return subscription{}, hresult("AdviseSink", hr)
	}
	sub.advised = true
	return sub, nil
}
func (s *subscription) close() error {
	var err error
	if s.advised {
		hr := comCall(s.source, 4, uintptr(s.cookie))
		if int32(hr) < 0 {
			err = hresult("UnadviseSink", hr)
		}
		s.advised = false
	}
	if s.sink != 0 {
		sinkRelease(s.sink)
		s.sink = 0
	}
	if s.source != nil {
		comCall(s.source, 2)
		s.source = nil
	}
	return err
}

type tsfWatch struct {
	state        changeState
	subs         [4]subscription
	compartments [3]*comObject
}

func getCompartment(m *comObject, id *rail.GUID) (*comObject, error) {
	var out *comObject
	hr := comCall(m, 3, uintptr(unsafe.Pointer(id)), uintptr(unsafe.Pointer(&out)))
	if int32(hr) < 0 {
		return nil, hresult("GetCompartment", hr)
	}
	if out == nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
func newWatch(manager *comObject) (*tsfWatch, error) {
	w := new(tsfWatch)
	var err error
	w.subs[0], err = subscribe(manager, &w.state, iidProfileSink, rail.GUID{}, WindowsAllChanged)
	if err != nil {
		w.close()
		return nil, err
	}
	m, err := queryCOM(manager, &iidCompartments)
	if err != nil {
		w.close()
		return nil, err
	}
	defer comCall(m, 2)
	for i := range w.compartments {
		w.compartments[i], err = getCompartment(m, &compartmentIDs[i])
		if err != nil {
			w.close()
			return nil, err
		}
		w.subs[i+1], err = subscribe(w.compartments[i], &w.state, iidCompartmentSink, compartmentIDs[i], WindowsOpenChanged<<i)
		if err != nil {
			w.close()
			return nil, err
		}
	}
	w.state.add(WindowsAllChanged)
	return w, nil
}
func (w *tsfWatch) close() error {
	if w == nil {
		return nil
	}
	w.state.close()
	var err error
	for i := len(w.subs) - 1; i >= 0; i-- {
		err = errors.Join(err, w.subs[i].close())
	}
	for i, p := range w.compartments {
		if p != nil {
			comCall(p, 2)
			w.compartments[i] = nil
		}
	}
	return err
}

// VARIANT's union includes a pair of pointers; it is 24 bytes on Windows 64-bit
// and 16 on 32-bit. Integer data starts at offset 8. Always clear received values.
type nativeVariant struct {
	kind     uint16
	reserved [3]uint16
	data     [2]uintptr
}

// An unset compartment is distinct from a known zero value. Keep that absence
// separate from COM/type/cleanup errors so Snapshot can still report a profile.
func readCompartmentValue(p *comObject) (value uint32, present bool, err error) {
	var v nativeVariant
	hr := comCall(p, 4, uintptr(unsafe.Pointer(&v)))
	defer func() {
		hr, _, _ := variantClear.Call(uintptr(unsafe.Pointer(&v)))
		if int32(hr) < 0 {
			err = errors.Join(err, hresult("VariantClear", hr))
		}
	}()
	if int32(hr) < 0 {
		return 0, false, hresult("GetValue", hr)
	}
	if hr == 1 || v.kind == 0 {
		return 0, false, nil
	}
	if v.kind != 3 {
		return 0, false, rail.ErrUnsupported
	}
	return uint32(v.data[0]), true, nil
}
func readCompartment(p *comObject) (uint32, error) {
	value, present, err := readCompartmentValue(p)
	if err != nil {
		return 0, err
	}
	if !present {
		return 0, ErrUnavailable
	}
	return value, nil
}
func writeCompartment(p *comObject, clientID, value uint32) error {
	v := nativeVariant{kind: 3}
	v.data[0] = uintptr(value)
	hr := comCall(p, 3, uintptr(clientID), uintptr(unsafe.Pointer(&v)))
	if int32(hr) < 0 {
		return hresult("SetValue", hr)
	}
	return nil
}
func (w *tsfWatch) read() (rail.IMECompartment, error) {
	value, known, err := w.readOptional()
	if err != nil {
		return rail.IMECompartment{}, err
	}
	if !known {
		return rail.IMECompartment{}, ErrUnavailable
	}
	return value, nil
}
func (w *tsfWatch) readOptional() (rail.IMECompartment, bool, error) {
	var values [3]uint32
	known := true
	for i, p := range w.compartments {
		v, present, err := readCompartmentValue(p)
		if err != nil {
			return rail.IMECompartment{}, false, err
		}
		// Continue after an absent field: a later native failure must not be
		// hidden by a profile-only snapshot.
		known = known && present
		values[i] = v
	}
	if !known {
		return rail.IMECompartment{}, false, nil
	}
	return rail.IMECompartment{Open: values[0] != 0, ConversionMode: rail.IMEConversionMode(values[1]), SentenceMode: rail.IMESentenceMode(values[2])}, true, nil
}

// TakeChanges drains coalesced native hints. Call after the native callback has
// returned, on the owning UI thread, then use Coordinator.Observe with its current
// focus token. It does not pump messages or imply that the remote surface owns focus.
func (a *WindowsAdapter) TakeChanges() (WindowsChanges, error) {
	if err := a.enter(); err != nil {
		return 0, err
	}
	defer func() { a.busy = false }()
	if a.watch == nil {
		return 0, ErrUnavailable
	}
	return a.watch.state.take(), nil
}

// NotifyMessage records relevant messages from the bound HWND's window procedure.
// It may be called reentrantly during native setters; it does not sample or write
// input state. Do not pass messages belonging to another HWND or input thread.
// TSF supplies profile/compartment notifications independently; these messages
// additionally cover legacy IMM and the thread-local Japanese KANA toggle.
func (a *WindowsAdapter) NotifyMessage(message uint32, wparam uintptr) error {
	if a.closed || a.profiles == nil {
		return rail.ErrClosed
	}
	tid, _, _ := getThread.Call()
	if tid != a.thread {
		return ErrThread
	}
	if err := a.window(); err != nil {
		return err
	}
	if a.watch == nil {
		return ErrUnavailable
	}
	var flags WindowsChanges
	switch message {
	case 0x51:
		flags = WindowsAllChanged // WM_INPUTLANGCHANGE
	case 0x282: // WM_IME_NOTIFY
		switch wparam {
		case 6:
			flags = WindowsConversionChanged | WindowsKanaChanged
		case 7:
			flags = WindowsSentenceChanged
		case 8:
			flags = WindowsOpenChanged
		}
	case 0x101, 0x105:
		if wparam == 0x15 {
			flags = WindowsKanaChanged
		} // VK_KANA release
	}
	a.watch.state.add(flags)
	return nil
}

func (w *tsfWatch) apply(clientID uint32, value rail.IMECompartment, check func() error) error {
	values := [3]uint32{0, uint32(value.ConversionMode), uint32(value.SentenceMode)}
	if value.Open {
		values[0] = 1
	}
	for i, p := range w.compartments {
		if err := check(); err != nil {
			return err
		}
		// Opening may change conversion/sentence state: re-read instead of using
		// stale pre-write values. Never fall back to IMM after a partial TSF write.
		current, err := readCompartment(p)
		if err != nil {
			return err
		}
		if i == 0 {
			if current != 0 {
				current = 1
			}
		}
		if current != values[i] {
			if err = check(); err != nil {
				return err
			}
			if err = writeCompartment(p, clientID, values[i]); err != nil {
				return err
			}
		}
	}
	return check()
}

func (a *WindowsAdapter) applyTSF(expected rail.LanguageProfile, value rail.IMECompartment) error {
	if err := a.watch.apply(a.clientID, value, func() error { return a.sameProfile(expected) }); err != nil {
		return err
	}
	if err := a.sameProfile(expected); err != nil {
		return err
	}
	if expected.LanguageID&0x3ff == 0x11 {
		var keys [256]byte
		if ok, _, _ := getKeys.Call(uintptr(unsafe.Pointer(&keys[0]))); ok == 0 {
			return ErrUnavailable
		}
		want := byte(0)
		if value.Kana {
			want = 1
		}
		if keys[0x15]&1 != want {
			keys[0x15] = keys[0x15]&^1 | want
			if ok, _, _ := setKeys.Call(uintptr(unsafe.Pointer(&keys[0]))); ok == 0 {
				return ErrNotApplied
			}
		}
	}
	after, err := a.snapshot()
	if err != nil {
		return err
	}
	if after.Profile != expected {
		return ErrChanged
	}
	if !after.CompartmentKnown || after.Compartment != value {
		return ErrNotApplied
	}
	return nil
}
