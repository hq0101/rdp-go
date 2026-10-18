package rdpdr

import (
	"errors"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

const directoryNotifyBuffer = 32 << 10

var (
	directoryCreateEvent   = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateEventW")
	directoryGetOverlapped = syscall.NewLazyDLL("kernel32.dll").NewProc("GetOverlappedResult")
	// OS writes outlive the submitting call. This root also prevents a Pinner
	// finalizer from unpinning memory after an exceptional cancellation failure.
	// Such failures remain charged and require process-level resource recovery.
	directoryActiveNotifications sync.Map
)

type directoryWindowsWatch struct {
	s       *directoryWindowsWatchState
	cleanup runtime.Cleanup
}
type directoryWindowsWatchState struct {
	handle, event   syscall.Handle
	config          NotifyRequest
	ov              syscall.Overlapped
	buffer          [directoryNotifyBuffer]byte
	pin             runtime.Pinner
	active, stopped bool
	failure         error
}

func newDirectoryNativeWatch(f *directoryFile, q NotifyRequest) (directoryNativeWatch, uint32) {
	// Reopen the same object with an empty name, not its possibly replaced path.
	// Omit SYNCHRONOUS_IO so notification submission can never wait for change.
	source := f.ioFile()
	name := directoryNTString{}
	obj := directoryNTObject{Root: source.Fd(), Name: &name, Attributes: 0x40}
	obj.Length = uint32(unsafe.Sizeof(obj))
	var h uintptr
	var ios directoryNTIO
	options := uint32(0x200000) | (f.openOptions & 0x400000)
	if f.openOptions&0x400000 == 0 {
		options |= 1
	}
	status, _, _ := directoryNtOpen.Call(uintptr(unsafe.Pointer(&h)), 0x100001, uintptr(unsafe.Pointer(&obj)), uintptr(unsafe.Pointer(&ios)), 7, uintptr(options))
	runtime.KeepAlive(source)
	if uint32(status) != 0 {
		return nil, uint32(status)
	}
	s := &directoryWindowsWatchState{handle: syscall.Handle(h), config: q}
	w := &directoryWindowsWatch{s: s}
	w.cleanup = runtime.AddCleanup(w, func(s *directoryWindowsWatchState) { _ = s.close() }, s)
	event, _, e := directoryCreateEvent.Call(0, 1, 0, 0)
	if event == 0 {
		return w, directoryStatus(e)
	}
	s.event = syscall.Handle(event)
	return w, 0
}

func (w *directoryWindowsWatch) start() uint32 { defer runtime.KeepAlive(w); return w.s.start() }
func (w *directoryWindowsWatch) poll() (bool, []byte, uint32, error) {
	defer runtime.KeepAlive(w)
	return w.s.poll()
}
func (w *directoryWindowsWatch) cancel() error { defer runtime.KeepAlive(w); return w.s.cancel() }
func (w *directoryWindowsWatch) close() error {
	defer runtime.KeepAlive(w)
	err := w.s.close()
	w.cleanup.Stop()
	return err
}

func (s *directoryWindowsWatchState) start() uint32 {
	if s.stopped || s.active || s.failure != nil {
		return StatusInvalidParameter
	}
	s.ov = syscall.Overlapped{HEvent: s.event}
	s.pin.Pin(&s.ov)
	s.pin.Pin(&s.buffer[0])
	s.active = true
	directoryActiveNotifications.Store(s, struct{}{})
	err := syscall.ReadDirectoryChanges(s.handle, &s.buffer[0], uint32(len(s.buffer)), s.config.WatchTree, s.config.Filter, nil, &s.ov, 0)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		s.finish()
		return directoryNotifyStatus(err)
	}
	return 0
}
func (s *directoryWindowsWatchState) finish() {
	s.active = false
	s.pin.Unpin()
	directoryActiveNotifications.Delete(s)
}
func directoryNotifyStatus(err error) uint32 {
	if err == syscall.Errno(1022) {
		return StatusNotifyEnumDir
	}
	if err == syscall.ERROR_OPERATION_ABORTED {
		return StatusCancelled
	}
	if err == syscall.Errno(1) {
		return StatusNotSupported
	}
	return directoryStatus(err)
}
func (s *directoryWindowsWatchState) result(wait bool) (bool, uint32, error) {
	var n uint32
	var flag uintptr
	if wait {
		flag = 1
	}
	ok, _, err := directoryGetOverlapped.Call(uintptr(s.handle), uintptr(unsafe.Pointer(&s.ov)), uintptr(unsafe.Pointer(&n)), flag)
	if ok == 0 && err == syscall.Errno(996) {
		return false, 0, nil
	}
	if ok == 0 {
		return true, 0, err
	}
	return true, n, nil
}
func (s *directoryWindowsWatchState) poll() (bool, []byte, uint32, error) {
	if s.failure != nil {
		return false, nil, 0, s.failure
	}
	if !s.active {
		return false, nil, 0, ErrFileHandle
	}
	done, n, err := s.result(false)
	if !done {
		return false, nil, 0, nil
	}
	s.finish()
	if err != nil {
		return true, nil, directoryNotifyStatus(err), nil
	}
	if n == 0 || uint64(n) > uint64(len(s.buffer)) {
		return true, nil, StatusNotifyEnumDir, nil
	}
	data, e := directoryNotifyData(s.buffer[:n])
	if e != nil {
		return true, nil, StatusNotifyEnumDir, nil
	}
	return true, data, 0, nil
}
func (s *directoryWindowsWatchState) cancel() error {
	if s.failure != nil {
		return s.failure
	}
	if !s.active {
		return nil
	}
	err := syscall.CancelIoEx(s.handle, &s.ov)
	if err != nil && err != syscall.ERROR_NOT_FOUND {
		s.failure = err
		return err // keep pinned and rooted; completion is unknown
	}
	// Cancellation is not completion. Wait before reusing/freeing OVERLAPPED
	// or its buffer. Host driver completion may delay Close/context cancellation.
	done, _, _ := s.result(true)
	if !done {
		s.failure = errors.New("rdpdr: notification cancellation did not complete")
		return s.failure
	}
	s.finish()
	return nil
}
func (s *directoryWindowsWatchState) close() error {
	if s.stopped {
		return s.failure
	}
	s.stopped = true
	if err := s.cancel(); err != nil {
		return err
	}
	if s.event != 0 {
		s.failure = errors.Join(s.failure, syscall.CloseHandle(s.event))
	}
	s.failure = errors.Join(s.failure, syscall.CloseHandle(s.handle))
	return s.failure
}
