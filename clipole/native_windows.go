//go:build windows && (amd64 || arm64)

package clipole

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var ole = syscall.NewLazyDLL("ole32.dll")
var user = syscall.NewLazyDLL("user32.dll")
var kernel = syscall.NewLazyDLL("kernel32.dll")
var (
	initialize      = ole.NewProc("OleInitialize")
	uninitialize    = ole.NewProc("OleUninitialize")
	setClipboard    = ole.NewProc("OleSetClipboard")
	isCurrent       = ole.NewProc("OleIsCurrentClipboard")
	taskAlloc       = ole.NewProc("CoTaskMemAlloc")
	taskFree        = ole.NewProc("CoTaskMemFree")
	copyMemory      = kernel.NewProc("RtlMoveMemory")
	globalAlloc     = kernel.NewProc("GlobalAlloc")
	globalFree      = kernel.NewProc("GlobalFree")
	globalLock      = kernel.NewProc("GlobalLock")
	globalUnlock    = kernel.NewProc("GlobalUnlock")
	globalSize      = kernel.NewProc("GlobalSize")
	peekMessage     = user.NewProc("PeekMessageW")
	dispatchMessage = user.NewProc("DispatchMessageW")
	getDesktop      = user.NewProc("GetThreadDesktop")
	setDesktop      = user.NewProc("SetThreadDesktop")
	threadID        = kernel.NewProc("GetCurrentThreadId")
)

const (
	eNoInterface uintptr = 0x80004002
	ePointer     uintptr = 0x80004003
	eNotImpl     uintptr = 0x80004001
	eInvalid     uintptr = 0x80070057
	eMemory      uintptr = 0x8007000e
	eFormat      uintptr = 0x80040064
	eTarget      uintptr = 0x80040065
	eIndex       uintptr = 0x80040068
	eMedium      uintptr = 0x80040069
	eAspect      uintptr = 0x8004006b
	eAdvise      uintptr = 0x80040003
	eReverted    uintptr = 0x80030102
	eInUse       uintptr = 0x80030100
	eUnexpected  uintptr = 0x8000ffff
	eRead        uintptr = 0x8003001e
	eWrite       uintptr = 0x8003001d
	eDenied      uintptr = 0x80030005
	eFunction    uintptr = 0x80030001
)

type guid struct {
	A    uint32
	B, C uint16
	D    [8]byte
}

var (
	iidUnknown    = guid{D: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidData       = guid{A: 0x10e, D: iidUnknown.D}
	iidEnum       = guid{A: 0x103, D: iidUnknown.D}
	iidStream     = guid{A: 0xc, D: iidUnknown.D}
	iidSequential = guid{A: 0x0c733a30, B: 0x2a1c, C: 0x11ce, D: [8]byte{0xad, 0xe5, 0, 0xaa, 0, 0x44, 0x77, 0x3d}}
	iidAsync      = guid{A: 0x3d8b0590, B: 0xf691, C: 0x11d2, D: [8]byte{0x8e, 0xa9, 0, 0x60, 0x97, 0xdf, 0x5b, 0xd4}}
	iidDropSource = guid{A: 0x121, D: iidUnknown.D}
)

// IDropSource outcomes (success-coded HRESULTs) and mouse/key state flags.
const (
	dragDropSDrop              uintptr = 0x00040100
	dragDropSCancel            uintptr = 0x00040101
	dragDropSUseDefaultCursors uintptr = 0x00040102
	mkLButton                          = 0x0001
	mkRButton                          = 0x0002
	mkShift                            = 0x0004
	mkControl                          = 0x0008
	mkMButton                          = 0x0010
	mkAlt                              = 0x0020
)

type formatEtc struct {
	Format uint16
	Target uintptr
	Aspect uint32
	Index  int32
	Medium uint32
}
type storageMedium struct {
	Medium         uint32
	Value, Release uintptr
}
type statStorage struct {
	Name                        uintptr
	Type                        uint32
	Size                        uint64
	Modified, Created, Accessed [2]uint32
	Mode, Locks                 uint32
	Class                       guid
	State, Reserved             uint32
}
type message struct {
	HWND    uintptr
	ID      uint32
	WP, LP  uintptr
	Time    uint32
	X, Y    int32
	Private uint32
}

type nativeOffer struct {
	s         *Offer
	data      uintptr
	installed bool // accessed only on its STA
	detached  bool // replacement observed; retained consumers may still call us
	formats   [3]formatEtc
	feedback  [2]uint16 // write-back only: Performed DropEffect, Paste Succeeded
	available []formatEtc
}

// OLE's clipboard wrapper answers QueryGetData from the enumerated FORMATETC
// values. Enumerate each regular-file index so querying index N works through
// that wrapper too, rather than only calling our IDataObject directly.
func (n *nativeOffer) enumeration() []formatEtc {
	if n.available == nil {
		n.available = append(n.available, n.formats[0])
		for i, file := range n.s.files {
			if file.IsDirectory() {
				continue
			}
			f := n.formats[1]
			f.Index = int32(i)
			n.available = append(n.available, f)
		}
		n.available = append(n.available, n.formats[2])
	}
	return n.available
}

func hresult(name string, hr uintptr) error {
	return fmt.Errorf("clipole: %s failed (HRESULT 0x%08x)", name, uint32(hr))
}
func failed(hr uintptr) bool { return int32(uint32(hr)) < 0 }

func (s *Offer) start() error {
	runtime.LockOSThread()
	tid, _, _ := threadID.Call()
	desktop, _, err := getDesktop.Call(tid)
	runtime.UnlockOSThread()
	if desktop == 0 {
		return fmt.Errorf("clipole: GetThreadDesktop: %w", err)
	}
	started := make(chan error, 1)
	go s.run(desktop, started)
	select {
	case err := <-started:
		if err != nil {
			<-s.done
		}
		return err
	case <-s.ctx.Done():
		<-s.done
		return s.ctx.Err()
	}
}

func (s *Offer) run(desktop uintptr, started chan<- error) {
	runtime.LockOSThread() // terminate this dedicated OS thread on return
	n := &nativeOffer{s: s}
	var terminal error
	initialized := false
	defer func() {
		s.cancel()
		if n.data != 0 {
			if n.installed {
				terminal = errors.Join(terminal, n.clear())
			}
			n.stopAsync()
			if initialized {
				uninitialize.Call()
				initialized = false
			}
			release(n.data)
		}
		if initialized {
			uninitialize.Call()
		}
		s.finish(terminal)
	}()
	if ok, _, err := setDesktop.Call(desktop); ok == 0 {
		terminal = fmt.Errorf("clipole: SetThreadDesktop: %w", err)
		started <- terminal
		return
	}
	hr, _, _ := initialize.Call(0)
	if failed(hr) {
		terminal = hresult("OleInitialize", hr)
		started <- terminal
		return
	}
	initialized = true
	for i, name := range []string{"FileGroupDescriptorW", "FileContents", "Preferred DropEffect"} {
		str, _ := syscall.UTF16FromString(name)
		id, _, err := user.NewProc("RegisterClipboardFormatW").Call(uintptr(unsafe.Pointer(&str[0])))
		if id == 0 {
			terminal = fmt.Errorf("clipole: RegisterClipboardFormat: %w", err)
			started <- terminal
			return
		}
		n.formats[i] = formatEtc{Format: uint16(id), Aspect: 1, Index: -1, Medium: 1}
	}
	n.formats[1].Medium = 4 // TYMED_ISTREAM
	for i, name := range []string{"Performed DropEffect", "Paste Succeeded"} {
		str, _ := syscall.UTF16FromString(name)
		id, _, err := user.NewProc("RegisterClipboardFormatW").Call(uintptr(unsafe.Pointer(&str[0])))
		if id == 0 {
			terminal = fmt.Errorf("clipole: RegisterClipboardFormat: %w", err)
			started <- terminal
			return
		}
		n.feedback[i] = uint16(id)
	}
	n.data = allocate(&object{owner: n, kind: 'd'})
	if n.data == 0 {
		terminal = hresult("data object allocation", eMemory)
		started <- terminal
		return
	}
	if s.o.RetainOnChange {
		// The source explicitly opts into background extraction. The data object
		// remains usable across replacement until the operation/consumers end.
		if hr := asyncSetMode(n.data, 1); hr != 0 {
			terminal = hresult("SetAsyncMode", hr)
			started <- terminal
			return
		}
	}
	if err := s.ctx.Err(); err != nil {
		started <- err
		return
	}
	if err := n.publish(); err != nil {
		terminal = err
		started <- terminal
		return
	}
	started <- nil
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.ctx.Err() != nil {
			return
		}
		for range 64 {
			var m message
			ok, _, _ := peekMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0, 1)
			if ok == 0 {
				break
			}
			dispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
		}
		if s.ctx.Err() != nil {
			return
		}
		if !n.detached {
			hr, _, _ := isCurrent.Call(n.data)
			if hr != 0 {
				if hr != 1 {
					terminal = hresult("OleIsCurrentClipboard", hr)
					return
				}
				if !s.o.RetainOnChange {
					terminal = ErrChanged
					return
				}
				n.detached = true
			}
		}
		if n.detached && !n.hasConsumers() {
			return
		}
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Check ownership while the clipboard is open. Checking and then calling
// OleSetClipboard(NULL) would race a new copy in another process.
func (n *nativeOffer) clear() error {
	hr, _, _ := isCurrent.Call(n.data)
	if hr == 1 {
		return nil
	}
	if failed(hr) {
		return hresult("OleIsCurrentClipboard", hr)
	}
	wnd, err := clipboardWindow()
	if err != nil {
		return err
	}
	defer user.NewProc("DestroyWindow").Call(wnd)
	ok, _, err := user.NewProc("OpenClipboard").Call(wnd)
	if ok == 0 {
		return fmt.Errorf("clipole: OpenClipboard during cleanup: %w", err)
	}
	var result error
	hr, _, _ = isCurrent.Call(n.data)
	if hr == 0 {
		if ok, _, err = user.NewProc("EmptyClipboard").Call(); ok == 0 {
			result = fmt.Errorf("clipole: EmptyClipboard: %w", err)
		}
	} else if failed(hr) {
		result = hresult("OleIsCurrentClipboard", hr)
	}
	if ok, _, err = user.NewProc("CloseClipboard").Call(); ok == 0 {
		result = errors.Join(result, fmt.Errorf("clipole: CloseClipboard: %w", err))
	}
	return result
}

func (n *nativeOffer) valid() bool {
	if n.s.ctx.Err() != nil {
		return false
	}
	if n.installed && !n.s.o.RetainOnChange {
		hr, _, _ := isCurrent.Call(n.data)
		if hr != 0 {
			return false
		}
	}
	return true
}

// The publication keeps one root data-object reference until STA teardown.
// OLE releases its clipboard references on replacement; external data objects,
// streams and enumerators keep this apartment pumping until their final Release.
func (n *nativeOffer) hasConsumers() bool {
	objects.Lock()
	defer objects.Unlock()
	for p, o := range objects.live {
		internal := uint32(1)
		if o.asyncHeld {
			internal++
		}
		if o.owner == n && (p != n.data || o.refs > internal || o.inOperation) {
			return true
		}
	}
	return false
}

// Native instances contain only a permanent vtable address, never Go pointers.
// The bounded registry roots Go state until the last COM reference is released.
type object struct {
	owner    *nativeOffer
	kind     byte
	refs     uint32
	mu       sync.Mutex
	index    uint32
	position uint64
	// The data object's two interface addresses share identity/refcount. Async
	// state and references are protected by objects, not the stream position lock.
	asyncMode, asyncHeld, inOperation bool
	// opCtx bounds reads belonging to the active async operation; a failed or
	// canceled EndOperation cancels it. Feedback write-backs are also guarded
	// by objects and cleared when the next operation starts.
	opCtx               context.Context
	opCancel            context.CancelFunc
	performed           uint32
	performedValid      bool
	pasteOK, pasteValid bool
}

var objects = struct {
	sync.Mutex
	live    map[uintptr]*object
	aliases map[uintptr]uintptr
}{live: map[uintptr]*object{}, aliases: map[uintptr]uintptr{}}
var callbacks sync.Once
var dataVtable [12]uintptr
var enumVtable [7]uintptr
var streamVtable [14]uintptr
var asyncVtable [8]uintptr
var dropSourceVtable [5]uintptr

func allocate(o *object) uintptr {
	initCallbacks()
	vt := uintptr(unsafe.Pointer(&dataVtable[0]))
	if o.kind == 'e' {
		vt = uintptr(unsafe.Pointer(&enumVtable[0]))
	}
	if o.kind == 's' {
		vt = uintptr(unsafe.Pointer(&streamVtable[0]))
	}
	size := unsafe.Sizeof(uintptr(0))
	if o.kind == 'd' {
		size *= 3
	}
	p, _, _ := taskAlloc.Call(size)
	if p == 0 {
		return 0
	}
	copyMemory.Call(p, uintptr(unsafe.Pointer(&vt)), unsafe.Sizeof(vt))
	if o.kind == 'd' {
		avt := uintptr(unsafe.Pointer(&asyncVtable[0]))
		copyMemory.Call(p+unsafe.Sizeof(vt), uintptr(unsafe.Pointer(&avt)), unsafe.Sizeof(avt))
		dvt := uintptr(unsafe.Pointer(&dropSourceVtable[0]))
		copyMemory.Call(p+2*unsafe.Sizeof(vt), uintptr(unsafe.Pointer(&dvt)), unsafe.Sizeof(dvt))
	}
	objects.Lock()
	count := 0
	for _, v := range objects.live {
		if v.owner == o.owner {
			count++
		}
	}
	if len(objects.live) >= 512 || count >= o.owner.s.o.MaxObjects {
		objects.Unlock()
		taskFree.Call(p)
		return 0
	}
	o.refs = 1
	objects.live[p] = o
	if o.kind == 'd' {
		objects.aliases[p+unsafe.Sizeof(vt)] = p
		objects.aliases[p+2*unsafe.Sizeof(vt)] = p
	}
	objects.Unlock()
	return p
}
func identityLocked(p uintptr) uintptr {
	if root := objects.aliases[p]; root != 0 {
		return root
	}
	return p
}
func lookup(p uintptr) *object {
	objects.Lock()
	defer objects.Unlock()
	return objects.live[identityLocked(p)]
}
func query(this uintptr, iid *guid, out *uintptr) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	if iid == nil {
		return ePointer
	}
	objects.Lock()
	defer objects.Unlock()
	this = identityLocked(this)
	o := objects.live[this]
	if o == nil {
		return eReverted
	}
	want := iidData
	if o.kind == 'e' {
		want = iidEnum
	}
	if o.kind == 's' {
		want = iidStream
	}
	async := o.kind == 'd' && o.owner.s.o.RetainOnChange && *iid == iidAsync
	drop := o.kind == 'd' && o.owner.s.o.DragSource && *iid == iidDropSource
	if *iid != iidUnknown && *iid != want && !(o.kind == 's' && *iid == iidSequential) && !async && !drop {
		return eNoInterface
	}
	if o.refs == ^uint32(0) {
		return eMemory
	}
	o.refs++
	*out = this
	if async {
		*out += unsafe.Sizeof(uintptr(0))
	}
	if drop {
		*out = this + 2*unsafe.Sizeof(uintptr(0))
	}
	return 0
}
func addRef(this uintptr) uintptr {
	objects.Lock()
	defer objects.Unlock()
	this = identityLocked(this)
	o := objects.live[this]
	if o == nil {
		return 0
	}
	if o.refs != ^uint32(0) {
		o.refs++
	}
	return uintptr(o.refs)
}
func release(this uintptr) uintptr {
	objects.Lock()
	this = identityLocked(this)
	o := objects.live[this]
	if o == nil {
		objects.Unlock()
		return 0
	}
	if o.refs == ^uint32(0) {
		objects.Unlock()
		return uintptr(o.refs)
	}
	o.refs--
	remaining := o.refs
	if remaining == 0 {
		delete(objects.live, this)
		if o.kind == 'd' {
			delete(objects.aliases, this+unsafe.Sizeof(uintptr(0)))
			delete(objects.aliases, this+2*unsafe.Sizeof(uintptr(0)))
		}
	}
	objects.Unlock()
	if remaining == 0 {
		taskFree.Call(this)
	}
	return uintptr(remaining)
}

// Pointer arguments cross a Go wrapper before SyscallN. Keep their storage
// stable even if a callback grows the Go stack during this call.
//
//go:uintptrescapes
func invoke(p uintptr, slot int, args ...uintptr) uintptr {
	var vt, fn uintptr
	copyMemory.Call(uintptr(unsafe.Pointer(&vt)), p, unsafe.Sizeof(vt))
	copyMemory.Call(uintptr(unsafe.Pointer(&fn)), vt+uintptr(slot)*unsafe.Sizeof(fn), unsafe.Sizeof(fn))
	args = append([]uintptr{p}, args...)
	hr, _, _ := syscall.SyscallN(fn, args...)
	return uintptr(uint32(hr))
}

func globalBytes(b []byte) uintptr {
	h, _, _ := globalAlloc.Call(0x42, uintptr(len(b)))
	if h == 0 {
		return 0
	}
	p, _, _ := globalLock.Call(h)
	if p == 0 {
		globalFree.Call(h)
		return 0
	}
	copyMemory.Call(p, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	globalUnlock.Call(h)
	return h
}
