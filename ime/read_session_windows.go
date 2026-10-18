package ime

import (
	"errors"
	"github.com/hq0101/rdp-go/rail"
	"sync"
	"syscall"
	"unsafe"
)

var iidReadSession = rail.GUID{Data1: 0xaa80e803, Data2: 0x2021, Data3: 0x11d2, Data4: [8]byte{0x93, 0xe0, 0, 0x60, 0xb0, 0x67, 0xb8, 0x6e}}
var readOnce sync.Once
var readVtable [4]uintptr
var readSessions = struct {
	sync.Mutex
	live map[uintptr]*nativeReadSession
}{live: make(map[uintptr]*nativeReadSession)}

const maxReadSessions = 64

type nativeReadSession struct {
	refs           uint32  // registry lock
	thread         uintptr // immutable
	active, called bool    // owning UI thread only
	run            func(uint32) error
	err            error
}

func newReadSession(thread uintptr, run func(uint32) error) (uintptr, *nativeReadSession, error) {
	readOnce.Do(func() {
		readVtable = [4]uintptr{syscall.NewCallback(readQuery), syscall.NewCallback(readAddRef), syscall.NewCallback(readRelease), syscall.NewCallback(readDo)}
	})
	readSessions.Lock()
	full := len(readSessions.live) >= maxReadSessions
	readSessions.Unlock()
	if full {
		return 0, nil, rail.ErrBusy
	}
	p, _, _ := taskAlloc.Call(unsafe.Sizeof(uintptr(0)))
	if p == 0 {
		return 0, nil, ErrUnavailable
	}
	vt := uintptr(unsafe.Pointer(&readVtable))
	copyNative.Call(p, uintptr(unsafe.Pointer(&vt)), unsafe.Sizeof(vt))
	s := &nativeReadSession{refs: 1, thread: thread, active: true, run: run}
	readSessions.Lock()
	if len(readSessions.live) >= maxReadSessions {
		readSessions.Unlock()
		taskFree.Call(p)
		return 0, nil, rail.ErrBusy
	}
	readSessions.live[p] = s
	readSessions.Unlock()
	return p, s, nil
}
func readQuery(this uintptr, id *rail.GUID, out *uintptr) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	if id == nil {
		return ePointer
	}
	readSessions.Lock()
	defer readSessions.Unlock()
	s := readSessions.live[this]
	if s == nil {
		return eUnexpected
	}
	if *id != iidUnknown && *id != iidReadSession {
		return eNoInterface
	}
	if s.refs == ^uint32(0) {
		return eUnexpected
	}
	s.refs++
	*out = this
	return 0
}
func readAddRef(this uintptr) uintptr {
	readSessions.Lock()
	defer readSessions.Unlock()
	s := readSessions.live[this]
	if s == nil {
		return 0
	}
	if s.refs != ^uint32(0) {
		s.refs++
	}
	return uintptr(s.refs)
}
func readRelease(this uintptr) uintptr {
	readSessions.Lock()
	s := readSessions.live[this]
	if s == nil {
		readSessions.Unlock()
		return 0
	}
	if s.refs == ^uint32(0) {
		readSessions.Unlock()
		return uintptr(s.refs)
	}
	s.refs--
	n := s.refs
	if n == 0 {
		delete(readSessions.live, this)
	}
	readSessions.Unlock()
	if n == 0 {
		taskFree.Call(this)
	}
	return uintptr(n)
}
func readDo(this uintptr, ec uint32) uintptr {
	readSessions.Lock()
	s := readSessions.live[this]
	readSessions.Unlock()
	if s == nil {
		return eUnexpected
	}
	tid, _, _ := getThread.Call()
	if tid != s.thread {
		return eThread
	}
	if !s.active || s.called {
		return eUnexpected
	}
	s.called = true
	s.err = s.run(ec)
	if s.err != nil {
		return eFail
	}
	return 0
}

// The native context receives a real ITfEditSession with bounded ownership.
// It may retain a reference, but no late callback can access the document.
// No callback address is generated per request: four process-wide slots only.
func (d *WindowsDocument) readSession(run func(uint32) error) error {
	p, s, err := newReadSession(d.adapter.thread, run)
	if err != nil {
		return err
	}
	defer func() { s.active = false; s.run = nil; readRelease(p) }()
	var result uint32 = uint32(eUnexpected)
	hr := comCall(d.context, 3, uintptr(d.adapter.clientID), p, 3, uintptr(unsafe.Pointer(&result)))
	if hr != 0 {
		return errors.Join(s.err, hresult("RequestEditSession(read)", hr))
	}
	if result != 0 {
		return errors.Join(s.err, hresult("DoEditSession(read)", uintptr(result)))
	}
	if !s.called {
		return ErrUnavailable
	}
	return s.err
}
