package ime

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/hq0101/rdp-go/rail"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	imm32            = syscall.NewLazyDLL("imm32.dll")
	ole32            = syscall.NewLazyDLL("ole32.dll")
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	getThread        = kernel32.NewProc("GetCurrentThreadId")
	getProcess       = kernel32.NewProc("GetCurrentProcessId")
	windowThread     = user32.NewProc("GetWindowThreadProcessId")
	getFocus         = user32.NewProc("GetFocus")
	getForeground    = user32.NewProc("GetForegroundWindow")
	getAncestor      = user32.NewProc("GetAncestor")
	getLayout        = user32.NewProc("GetKeyboardLayout")
	getKeys          = user32.NewProc("GetKeyboardState")
	setKeys          = user32.NewProc("SetKeyboardState")
	getProp          = user32.NewProc("GetPropW")
	setProp          = user32.NewProc("SetPropW")
	removeProp       = user32.NewProc("RemovePropW")
	getContext       = imm32.NewProc("ImmGetContext")
	releaseContext   = imm32.NewProc("ImmReleaseContext")
	getOpen          = imm32.NewProc("ImmGetOpenStatus")
	setOpen          = imm32.NewProc("ImmSetOpenStatus")
	getConversion    = imm32.NewProc("ImmGetConversionStatus")
	setConversion    = imm32.NewProc("ImmSetConversionStatus")
	coInit           = ole32.NewProc("CoInitializeEx")
	coUninit         = ole32.NewProc("CoUninitialize")
	coCreate         = ole32.NewProc("CoCreateInstance")
	propertyName     = syscall.StringToUTF16Ptr("RdpGo.IME.Owner.v1")
	windowIDs        atomic.Uint64
	clsProfiles      = rail.GUID{Data1: 0x33c53a50, Data2: 0xf456, Data3: 0x4884, Data4: [8]byte{0xb0, 0x49, 0x85, 0xfd, 0x64, 0x3e, 0xcf, 0xed}}
	iidProfiles      = rail.GUID{Data1: 0x71c6e74c, Data2: 0x0f28, Data3: 0x11d8, Data4: [8]byte{0xa8, 0x2a, 0, 6, 0x5b, 0x84, 0x43, 0x5c}}
	keyboardCategory = rail.GUID{Data1: 0x34745c63, Data2: 0xb2f0, Data3: 0x4784, Data4: [8]byte{0x8b, 0x67, 0x5e, 0x12, 0xc8, 0x70, 0x1a, 0x31}}
	clsThreadMgr     = rail.GUID{Data1: 0x529a9e6b, Data2: 0x6587, Data3: 0x4f23, Data4: [8]byte{0xab, 0x9e, 0x9c, 0x7d, 0x68, 0x3e, 0x3c, 0x50}}
	iidThreadMgr     = rail.GUID{Data1: 0xaa80e801, Data2: 0x2021, Data3: 0x11d2, Data4: [8]byte{0x93, 0xe0, 0, 0x60, 0xb0, 0x67, 0xb8, 0x6e}}
)

type comObject struct{ vtable *[11]uintptr }

//go:uintptrescapes
func comCall(p *comObject, index int, args ...uintptr) uintptr {
	all := append([]uintptr{uintptr(unsafe.Pointer(p))}, args...)
	// Interfaces such as ITfRangeACP extend beyond IUnknown's small prefix.
	// Only the requested slot is viewed, so short synthetic/native vtables are
	// never reinterpreted as an unnecessarily larger Go allocation.
	if index < 0 || index >= 64 {
		panic("ime: invalid COM method slot")
	}
	r, _, _ := syscall.SyscallN(unsafe.Slice(&p.vtable[0], index+1)[index], all...)
	runtime.KeepAlive(p)
	// Every interface method used here returns HRESULT or ULONG (32 bits),
	// including IUnknown. Unused high return-register bits are not the result.
	return uintptr(uint32(r))
}
func hresult(op string, hr uintptr) error {
	return fmt.Errorf("ime: %s HRESULT 0x%08x", op, uint32(hr))
}
func createCOM(cls, iid *rail.GUID) (*comObject, error) {
	var p *comObject
	hr, _, _ := coCreate.Call(uintptr(unsafe.Pointer(cls)), 0, 1, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&p)))
	if int32(hr) < 0 {
		return nil, hresult("CoCreateInstance", hr)
	}
	if p == nil {
		return nil, ErrUnavailable
	}
	return p, nil
}

// nativeProfile follows TF_INPUTPROCESSORPROFILE, including native HKL width
// and ABI padding. It is deliberately distinct from the packed RAIL structure.
type nativeProfile struct {
	Type                       uint32
	LanguageID                 uint16
	CLSID, ProfileID, Category rail.GUID
	Substitute                 uintptr
	Caps                       uint32
	Layout                     uintptr
	Flags                      uint32
}

// WindowsAdapter uses TSF for profile identity and change notifications. Its
// explicit state backend defaults to the bound HWND's IMM context; WindowsTSF
// instead reads/writes the thread manager's keyboard compartments. Both require
// the bound foreground focus. Unset TSF values leave CompartmentKnown false;
// other unavailable state returns ErrUnavailable. It requires
// a native UI thread and message loop. OpenDocument supplies an optional text
// store; rendering and the language bar belong to the caller. Japanese Kana
// uses the thread's VK_KANA toggle.
type WindowsAdapter struct {
	input                             *WindowsInput
	document                          *WindowsDocument
	backend                           WindowsStateBackend
	watch                             *tsfWatch
	wnd, marker, thread               uintptr
	profiles, manager                 *comObject
	clientID                          uint32
	active, initialized, closed, busy bool
}

// OpenWindows must run on the goroutine already locked to the UI thread that
// owns hwnd. It adds one OS-thread lock, initializes STA COM and activates TSF;
// Close balances only these references on that same goroutine. Never attach
// this thread's input queue to another thread. Close before WM_NCDESTROY; a
// window property additionally rejects destroyed/reused HWNDs. No focus, input
// locale, IME mode or language bar is changed by opening the adapter.
func OpenWindows(hwnd uintptr) (*WindowsAdapter, error) {
	return OpenWindowsWithOptions(hwnd, WindowsOptions{})
}

// OpenWindowsWithOptions selects one state backend for the adapter lifetime.
// It never silently falls back to the other backend. All OpenWindows UI-thread
// and ownership requirements apply. Native event subscriptions are automatic.
// UIElementOnly is an explicit thread-wide service restriction for clients that
// integrate candidate UI. Its activation flags are verified; no silent fallback.
func OpenWindowsWithOptions(hwnd uintptr, options WindowsOptions) (*WindowsAdapter, error) {
	if options.StateBackend != WindowsIMM && options.StateBackend != WindowsTSF {
		return nil, rail.ErrUnsupported
	}
	runtime.LockOSThread()
	tid, _, _ := getThread.Call()
	a := &WindowsAdapter{wnd: hwnd, thread: tid, backend: options.StateBackend}
	failed := true
	defer func() {
		if failed {
			a.cleanup()
			runtime.UnlockOSThread()
		}
	}()
	var pid uint32
	owner, _, _ := windowThread.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	process, _, _ := getProcess.Call()
	if hwnd == 0 || owner != tid || uintptr(pid) != process {
		return nil, ErrThread
	}
	name := uintptr(unsafe.Pointer(propertyName))
	if v, _, _ := getProp.Call(hwnd, name); v != 0 {
		return nil, rail.ErrBusy
	}
	id := nextWindowID()
	if id == 0 {
		return nil, rail.ErrBusy
	}
	a.marker = uintptr(id)
	if ok, _, e := setProp.Call(hwnd, name, a.marker); ok == 0 {
		return nil, fmt.Errorf("ime: SetProp: %w", e)
	}
	hr, _, _ := coInit.Call(0, 2)
	if int32(hr) < 0 {
		return nil, hresult("CoInitializeEx(STA)", hr)
	}
	a.initialized = true
	var err error
	a.manager, err = createCOM(&clsThreadMgr, &iidThreadMgr)
	if err != nil {
		return nil, err
	}
	if err = a.activateThread(options.UIElementOnly); err != nil {
		return nil, err
	}
	a.profiles, err = createCOM(&clsProfiles, &iidProfiles)
	if err != nil {
		return nil, err
	}
	a.watch, err = newWatch(a.manager)
	if err != nil {
		return nil, err
	}
	failed = false
	return a, nil
}

func nextWindowID() uint64 {
	for {
		old := windowIDs.Load()
		if old >= uint64(^uintptr(0)) {
			return 0
		}
		if windowIDs.CompareAndSwap(old, old+1) {
			return old + 1
		}
	}
}

func (a *WindowsAdapter) cleanup() error {
	var err error
	if a.input != nil {
		err = a.input.closeNative()
		a.input = nil
	}
	if a.document != nil {
		err = errors.Join(err, a.document.closeNative())
		a.document = nil
	}
	err = errors.Join(err, a.watch.close())
	a.watch = nil
	if a.profiles != nil {
		comCall(a.profiles, 2)
		a.profiles = nil
	}
	if a.manager != nil {
		if a.active {
			if hr := comCall(a.manager, 4); int32(hr) < 0 {
				err = errors.Join(err, hresult("ITfThreadMgr.Deactivate", hr))
			}
			a.active = false
		}
		comCall(a.manager, 2)
		a.manager = nil
	}
	if a.initialized {
		coUninit.Call()
		a.initialized = false
	}
	if a.marker != 0 {
		name := uintptr(unsafe.Pointer(propertyName))
		if v, _, _ := getProp.Call(a.wnd, name); v == a.marker {
			removeProp.Call(a.wnd, name)
		}
	}
	a.marker = 0
	return err
}

func (a *WindowsAdapter) Close() error {
	if a.closed {
		return nil
	}
	tid, _, _ := getThread.Call()
	if tid != a.thread {
		return ErrThread
	}
	if a.busy || a.documentBusy() {
		return rail.ErrBusy
	}
	// COM Deactivate/Release may synchronously reenter the application's window
	// procedure. Retire the adapter before releasing any native interface.
	a.closed = true
	err := a.cleanup()
	runtime.UnlockOSThread()
	return err
}

func (a *WindowsAdapter) enter() error {
	if a.closed || a.profiles == nil {
		return rail.ErrClosed
	}
	tid, _, _ := getThread.Call()
	if tid != a.thread {
		return ErrThread
	}
	if a.busy || a.documentBusy() {
		return rail.ErrBusy
	}
	if err := a.window(); err != nil {
		return err
	}
	a.busy = true
	return nil
}
func (a *WindowsAdapter) window() error {
	owner, _, _ := windowThread.Call(a.wnd, 0)
	marker, _, _ := getProp.Call(a.wnd, uintptr(unsafe.Pointer(propertyName)))
	if owner != a.thread || marker != a.marker || marker == 0 {
		return ErrStale
	}
	return nil
}
func (a *WindowsAdapter) focused() error {
	if err := a.window(); err != nil {
		return err
	}
	focus, _, _ := getFocus.Call()
	root, _, _ := getAncestor.Call(a.wnd, 2)
	foreground, _, _ := getForeground.Call()
	if focus != a.wnd || root == 0 || root != foreground {
		return ErrNotFocused
	}
	return nil
}

func (a *WindowsAdapter) profile() (rail.LanguageProfile, error) {
	var p nativeProfile
	hr := comCall(a.profiles, 10, uintptr(unsafe.Pointer(&keyboardCategory)), uintptr(unsafe.Pointer(&p)))
	runtime.KeepAlive(&p)
	if hr == 1 {
		return rail.LanguageProfile{}, ErrUnavailable
	}
	if int32(hr) < 0 {
		return rail.LanguageProfile{}, hresult("GetActiveProfile", hr)
	}
	layout := p.Layout
	if layout == 0 {
		layout, _, _ = getLayout.Call(0)
	}
	if layout == 0 {
		return rail.LanguageProfile{}, ErrUnavailable
	}
	s := rail.LanguageProfile{Type: rail.ProfileType(p.Type), LanguageID: p.LanguageID, CLSID: p.CLSID, ProfileID: p.ProfileID, KeyboardLayout: uint32(layout)}
	if _, err := rail.EncodeLanguageProfile(s); err != nil {
		return rail.LanguageProfile{}, err
	}
	return s, nil
}

// Profile reads this UI thread's TSF profile without requiring foreground focus.
// It is useful for capability probing; Snapshot still requires the bound focus.
func (a *WindowsAdapter) Profile() (rail.LanguageProfile, error) {
	if err := a.enter(); err != nil {
		return rail.LanguageProfile{}, err
	}
	defer func() { a.busy = false }()
	return a.profile()
}

func (a *WindowsAdapter) snapshot() (Snapshot, error) {
	if err := a.focused(); err != nil {
		return Snapshot{}, err
	}
	p, err := a.profile()
	if err != nil {
		return Snapshot{}, err
	}
	s := Snapshot{Profile: p}
	if p.Type == rail.ProfileInputProcessor {
		if a.backend == WindowsTSF {
			s.Compartment, s.CompartmentKnown, err = a.watch.readOptional()
			if err != nil {
				return Snapshot{}, err
			}
		} else {
			h, _, _ := getContext.Call(a.wnd)
			if h == 0 {
				return Snapshot{}, ErrUnavailable
			}
			defer releaseContext.Call(a.wnd, h)
			open, _, _ := getOpen.Call(h)
			var conv, sentence uint32
			if ok, _, _ := getConversion.Call(h, uintptr(unsafe.Pointer(&conv)), uintptr(unsafe.Pointer(&sentence))); ok == 0 {
				return Snapshot{}, ErrUnavailable
			}
			s.Compartment = rail.IMECompartment{Open: open != 0, ConversionMode: rail.IMEConversionMode(conv), SentenceMode: rail.IMESentenceMode(sentence)}
			s.CompartmentKnown = true
		}
		if s.CompartmentKnown && p.LanguageID&0x3ff == 0x11 {
			var keys [256]byte
			if ok, _, _ := getKeys.Call(uintptr(unsafe.Pointer(&keys[0]))); ok == 0 {
				return Snapshot{}, ErrUnavailable
			}
			s.Compartment.Kana = keys[0x15]&1 != 0
		}
	}
	if err = a.focused(); err != nil {
		return Snapshot{}, err
	}
	p2, err := a.profile()
	if err != nil {
		return Snapshot{}, err
	}
	if p2 != p {
		return Snapshot{}, ErrChanged
	}
	return s, nil
}
func (a *WindowsAdapter) Snapshot() (Snapshot, error) {
	if err := a.enter(); err != nil {
		return Snapshot{}, err
	}
	defer func() { a.busy = false }()
	return a.snapshot()
}

func (a *WindowsAdapter) sameProfile(expected rail.LanguageProfile) error {
	if err := a.focused(); err != nil {
		return err
	}
	p, err := a.profile()
	if err != nil {
		return err
	}
	if p != expected {
		return ErrChanged
	}
	return nil
}

func (a *WindowsAdapter) sameContext(h uintptr) error {
	current, _, _ := getContext.Call(a.wnd)
	if current != 0 {
		releaseContext.Call(a.wnd, current)
	}
	if current != h || current == 0 {
		return ErrChanged
	}
	return nil
}

func (a *WindowsAdapter) ApplyIME(expected rail.LanguageProfile, value rail.IMECompartment) error {
	if err := a.enter(); err != nil {
		return err
	}
	defer func() { a.busy = false }()
	if err := validate(Snapshot{Profile: expected, CompartmentKnown: true, Compartment: value}, rail.LanguageCapabilities{LanguageIME: true}); err != nil {
		return err
	}
	if err := a.sameProfile(expected); err != nil {
		return err
	}
	before, err := a.snapshot()
	if err != nil {
		return err
	}
	if before.Profile != expected {
		return ErrChanged
	}
	if !before.CompartmentKnown {
		return ErrUnavailable
	}
	if a.backend == WindowsTSF {
		return a.applyTSF(expected, value)
	}
	h, _, _ := getContext.Call(a.wnd)
	if h == 0 {
		return ErrUnavailable
	}
	defer releaseContext.Call(a.wnd, h)
	if before.Compartment.Open != value.Open {
		open := uintptr(0)
		if value.Open {
			open = 1
		}
		if ok, _, _ := setOpen.Call(h, open); ok == 0 {
			return ErrNotApplied
		}
	}
	if err = a.sameProfile(expected); err != nil {
		return err
	}
	if err = a.sameContext(h); err != nil {
		return err
	}
	// Opening an IME can itself change its conversion mode. Set the requested
	// modes even if they matched before opening, then verify the resulting state.
	if before.Compartment != value {
		if ok, _, _ := setConversion.Call(h, uintptr(value.ConversionMode), uintptr(value.SentenceMode)); ok == 0 {
			return ErrNotApplied
		}
	}
	if err = a.sameProfile(expected); err != nil {
		return err
	}
	if err = a.sameContext(h); err != nil {
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

// The native language bar and TSF composition UI are not provided by this
// adapter; keep LanguageBar negotiation disabled when using it as the Host.
func (a *WindowsAdapter) ApplyLanguageBar(rail.LanguageBarStatus) error { return rail.ErrUnsupported }
