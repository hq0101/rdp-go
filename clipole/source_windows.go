//go:build windows && (amd64 || arm64)

package clipole

import (
	"context"
	"encoding/binary"
	"io"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/hq0101/rdp-go/cliprdr"
)

type sourceRead struct {
	index  int
	offset uint64
	bytes  []byte
	result chan error
}
type nativeSource struct {
	mu         sync.Mutex // serializes public ReaderAt and Release, never held by the STA
	closed     bool
	requests   chan sourceRead
	stop, done chan struct{}
	files      []cliprdr.FileDescriptor // immutable after acquisition
	preferred  uint32                   // observed drop intent; remaining fields belong exclusively to the dedicated STA
	data       uintptr
	media      []storageMedium
	buffers    [][]byte // forward-only streams buffered once at acquisition; nil entries use media
	o          SourceOptions
	expected   Snapshot // clipboard acquisition only
	adopt      uintptr  // marshaled IDataObject stream for a dropped source; 0 for clipboard
}
type sourceReader struct {
	source *nativeSource
	index  int
}

func acquireSource(ctx context.Context, expected Snapshot, o SourceOptions) (cliprdr.FileSourceOffer, error) {
	s := &nativeSource{requests: make(chan sourceRead), stop: make(chan struct{}), done: make(chan struct{}), preferred: DropEffectCopy, o: o, expected: expected}
	return startSource(ctx, s)
}

// acquireDrop adopts a dropped IDataObject (already valid in the caller's
// apartment, e.g. the proxy OLE passes to IDropTarget.Drop). It marshals the
// object into a dedicated source apartment so subsequent reads never depend on
// the caller's message pump. The dropped object's reference is transferred to
// the source and released at cleanup. No clipboard ownership is consulted.
func acquireDrop(ctx context.Context, data uintptr, o SourceOptions) (cliprdr.FileSourceOffer, error) {
	if data == 0 {
		return cliprdr.FileSourceOffer{}, ErrInvalid
	}
	var stream uintptr
	hr, _, _ := ole.NewProc("CoMarshalInterThreadInterfaceInStream").Call(uintptr(unsafe.Pointer(&iidData)), data, uintptr(unsafe.Pointer(&stream)))
	if failed(hr) {
		return cliprdr.FileSourceOffer{}, hresult("CoMarshalInterThreadInterfaceInStream", hr)
	}
	s := &nativeSource{requests: make(chan sourceRead), stop: make(chan struct{}), done: make(chan struct{}), preferred: DropEffectCopy, o: o, adopt: stream}
	offer, err := startSource(ctx, s)
	if err != nil {
		invoke(stream, 2) // release the marshaled stream on startup failure
	}
	return offer, err
}

func startSource(ctx context.Context, s *nativeSource) (cliprdr.FileSourceOffer, error) {
	runtime.LockOSThread()
	tid, _, _ := threadID.Call()
	desktop, _, err := getDesktop.Call(tid)
	runtime.UnlockOSThread()
	if desktop == 0 {
		return cliprdr.FileSourceOffer{}, err
	}
	started := make(chan error, 1)
	go s.run(ctx, desktop, started)
	if err := <-started; err != nil {
		<-s.done
		return cliprdr.FileSourceOffer{}, err
	}
	if err := ctx.Err(); err != nil {
		s.close()
		return cliprdr.FileSourceOffer{}, err
	}
	offer := cliprdr.FileSourceOffer{Files: append([]cliprdr.FileDescriptor(nil), s.files...), Readers: make([]io.ReaderAt, len(s.files)), Release: s.close, PreferredDropEffect: s.preferred}
	for i, f := range s.files {
		if !f.IsDirectory() {
			offer.Readers[i] = sourceReader{s, i}
		}
	}
	return offer, nil
}

func (s *nativeSource) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.stop)
	}
	<-s.done
	return nil
}

func (r sourceReader) ReadAt(p []byte, off int64) (int, error) {
	s := r.source
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrChanged
	}
	if off < 0 {
		return 0, ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	size := s.files[r.index].Size
	if uint64(off) >= size {
		return 0, io.EOF
	}
	length := min(uint64(len(p)), size-uint64(off))
	n := 0
	for uint64(n) < length {
		chunk := int(min(uint64(256<<10), length-uint64(n)))
		q := sourceRead{r.index, uint64(off) + uint64(n), p[n : n+chunk], make(chan error, 1)}
		s.requests <- q
		if err := <-q.result; err != nil {
			clear(p[n : n+chunk])
			return n, err
		}
		n += chunk
	}
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (s *nativeSource) run(ctx context.Context, desktop uintptr, started chan<- error) {
	runtime.LockOSThread() // terminate the dedicated thread; never pool a COM STA
	initialized := false
	defer func() {
		for i := len(s.media) - 1; i >= 0; i-- {
			releaseSourceMedium(&s.media[i])
		}
		if s.data != 0 {
			invoke(s.data, 2)
		}
		if initialized {
			uninitialize.Call()
		}
		close(s.done)
	}()
	if ok, _, err := setDesktop.Call(desktop); ok == 0 {
		started <- err
		return
	}
	hr, _, _ := initialize.Call(0)
	if failed(hr) {
		started <- hresult("source OleInitialize", hr)
		return
	}
	initialized = true
	var err error
	if s.adopt != 0 {
		hr, _, _ := ole.NewProc("CoGetInterfaceAndReleaseStream").Call(s.adopt, uintptr(unsafe.Pointer(&iidData)), uintptr(unsafe.Pointer(&s.data)))
		s.adopt = 0
		if failed(hr) {
			started <- hresult("CoGetInterfaceAndReleaseStream", hr)
			return
		}
		err = s.acquireAdopted(ctx)
	} else {
		err = s.acquire(ctx, s.expected, s.o)
	}
	if err != nil {
		started <- err
		return
	}
	started <- nil
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		for range 64 {
			var m message
			if ok, _, _ := peekMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0, 1); ok == 0 {
				break
			}
			dispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
		}
		select {
		case <-s.stop:
			return
		case q := <-s.requests:
			q.result <- s.read(q)
		case <-ticker.C:
		}
	}
}

func releaseSourceMedium(m *storageMedium) {
	if m.Medium != 0 {
		ole.NewProc("ReleaseStgMedium").Call(uintptr(unsafe.Pointer(m)))
		*m = storageMedium{}
	}
}

func sourceFormat(name string, index int32, medium uint32) (formatEtc, error) {
	u, _ := syscall.UTF16FromString(name)
	id, _, err := user.NewProc("RegisterClipboardFormatW").Call(uintptr(unsafe.Pointer(&u[0])))
	if id == 0 {
		return formatEtc{}, err
	}
	return formatEtc{Format: uint16(id), Aspect: 1, Index: index, Medium: medium}, nil
}

// A missing Preferred DropEffect means copy intent. A present one must be a
// valid four-byte effect; malformed feedback fails the acquisition instead of
// silently guessing. Observing intent never authorizes moving or deleting.
func (s *nativeSource) observeDropEffect() error {
	f, err := sourceFormat("Preferred DropEffect", -1, 1)
	if err != nil {
		return err
	}
	if hr := invoke(s.data, 5, uintptr(unsafe.Pointer(&f))); hr != 0 {
		return nil
	}
	m, err := s.get(f)
	if err != nil {
		return err
	}
	defer releaseSourceMedium(&m)
	effect, err := sourceDropEffect(m)
	if err != nil {
		return err
	}
	s.preferred = effect
	return nil
}

func sourceDropEffect(m storageMedium) (uint32, error) {
	if m.Medium != 1 || m.Value == 0 {
		return 0, ErrInvalid
	}
	n, _, _ := kernel.NewProc("GlobalSize").Call(m.Value)
	if n < 4 {
		return 0, ErrInvalid
	}
	p, _, err := globalLock.Call(m.Value)
	if p == 0 {
		return 0, err
	}
	var value uint32
	copyMemory.Call(uintptr(unsafe.Pointer(&value)), p, 4)
	globalUnlock.Call(m.Value)
	if value < DropEffectCopy || value > DropEffectCopy|DropEffectMove {
		return 0, ErrInvalid
	}
	return value, nil
}

func (s *nativeSource) get(f formatEtc) (storageMedium, error) {
	var m storageMedium
	hr := invoke(s.data, 3, uintptr(unsafe.Pointer(&f)), uintptr(unsafe.Pointer(&m)))
	if hr != 0 {
		return storageMedium{}, hresult("source IDataObject.GetData", hr)
	}
	return m, nil
}

func sourceGlobal(m storageMedium, length uint64) ([]byte, error) {
	if m.Medium != 1 || m.Value == 0 {
		return nil, ErrInvalid
	}
	n, _, _ := kernel.NewProc("GlobalSize").Call(m.Value)
	if length > uint64(n) || length > 4+cliprdr.MaxFiles*cliprdr.FileDescriptorBytes {
		return nil, ErrInvalid
	}
	if length == 0 {
		return []byte{}, nil
	}
	p, _, err := globalLock.Call(m.Value)
	if p == 0 {
		return nil, err
	}
	b := make([]byte, int(length))
	copyMemory.Call(uintptr(unsafe.Pointer(&b[0])), p, uintptr(length))
	globalUnlock.Call(m.Value)
	return b, nil
}

func (s *nativeSource) acquire(ctx context.Context, expected Snapshot, o SourceOptions) error {
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if stamp() != expected {
			return ErrChanged
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	hr, _, _ := ole.NewProc("OleGetClipboard").Call(uintptr(unsafe.Pointer(&s.data)))
	if hr != 0 {
		return hresult("OleGetClipboard", hr)
	}
	if s.data == 0 {
		return ErrInvalid
	}
	if err := check(); err != nil {
		return err
	}
	return s.acquireMedia(ctx, o, check)
}

// acquireAdopted acquires from a dropped data object already owned by this
// apartment. A drop has no clipboard ownership to verify, so only ctx bounds it.
func (s *nativeSource) acquireAdopted(ctx context.Context) error {
	check := ctx.Err
	return s.acquireMedia(ctx, s.o, check)
}

// acquireMedia reads descriptors and acquires each regular file's medium from
// s.data, shared by clipboard acquisition and dropped-source adoption. check is
// invoked between native calls so cancellation/ownership loss stops acquisition.
func (s *nativeSource) acquireMedia(ctx context.Context, o SourceOptions, check func() error) error {
	f, err := sourceFormat(cliprdr.FileGroupDescriptorName, -1, 1)
	if err != nil {
		return err
	}
	m, err := s.get(f)
	if err != nil {
		return err
	}
	defer releaseSourceMedium(&m)
	header, err := sourceGlobal(m, 4)
	if err != nil {
		return err
	}
	count := binary.LittleEndian.Uint32(header)
	if count == 0 || count > uint32(o.MaxFiles) {
		return cliprdr.ErrFileLimit
	}
	b, err := sourceGlobal(m, 4+uint64(count)*cliprdr.FileDescriptorBytes)
	if err != nil {
		return err
	}
	if s.files, err = cliprdr.DecodeFileList(b); err != nil {
		return err
	}
	preflight := append([]cliprdr.FileDescriptor(nil), s.files...)
	for i := range preflight {
		if preflight[i].Flags&cliprdr.FileSizeValid == 0 {
			preflight[i].Flags |= cliprdr.FileSizeValid
			preflight[i].Size = 0
		}
	}
	if _, err = cliprdr.PlanFileOffer(preflight, cliprdr.FilePlanOptions{MaxTotalSize: o.MaxTotalSize, MaxFileSize: o.MaxTotalSize}); err != nil {
		return err
	}
	if err = s.observeDropEffect(); err != nil {
		return err
	}
	s.media = make([]storageMedium, len(s.files))
	s.buffers = make([][]byte, len(s.files))
	var total uint64
	for i := range s.files {
		if err = check(); err != nil {
			return err
		}
		d := &s.files[i]
		if d.IsDirectory() {
			continue
		}
		f, err = sourceFormat("FileContents", int32(i), 4) // prefer a stream over eager global memory
		if err != nil {
			return err
		}
		media, getErr := s.get(f)
		if getErr != nil {
			f.Medium = 8 // TYMED_ISTORAGE: shell virtual files may present an IStorage holding a CONTENTS stream
			media, getErr = s.get(f)
		}
		if getErr != nil {
			f.Medium = 1
			media, getErr = s.get(f)
		}
		if getErr != nil {
			return getErr
		}
		if media.Medium == 8 {
			inner, err := openStorageStream(media)
			if err != nil {
				releaseSourceMedium(&media)
				return err
			}
			releaseSourceMedium(&media) // the opened stream keeps the storage alive
			media = storageMedium{Medium: 4, Value: inner}
		}
		s.media[i] = media // retained/released as a complete STGMEDIUM, including punkForRelease
		actual, err := sourceSize(media)
		if err != nil {
			return err
		}
		if d.Flags&cliprdr.FileSizeValid != 0 {
			if (media.Medium == 4 && actual != d.Size) || actual < d.Size {
				return ErrChanged
			}
			actual = d.Size // HGLOBAL may include allocation padding
		}
		if actual > o.MaxTotalSize-total {
			return cliprdr.ErrFileLimit
		}
		total += actual
		d.Size, d.Flags = actual, d.Flags|cliprdr.FileSizeValid
		if media.Medium == 4 {
			seekable, err := streamSeekable(media)
			if err != nil {
				return err
			}
			if !seekable {
				buf, err := s.bufferStream(media, actual, check)
				if err != nil {
					return err
				}
				s.buffers[i] = buf
				releaseSourceMedium(&s.media[i]) // content captured; free the exhausted stream
			}
		}
	}
	if _, err = cliprdr.PlanFileOffer(s.files, cliprdr.FilePlanOptions{MaxTotalSize: o.MaxTotalSize, MaxFileSize: o.MaxTotalSize}); err != nil {
		return err
	}
	return check()
}

// openStorageStream opens the shell virtual-file convention: a TYMED_ISTORAGE
// medium whose "CONTENTS" stream holds the file bytes. The returned IStream keeps
// the storage alive, so the caller may release the original storage medium.
func openStorageStream(m storageMedium) (uintptr, error) {
	if m.Value == 0 {
		return 0, ErrInvalid
	}
	name, _ := syscall.UTF16FromString("CONTENTS")
	var inner uintptr
	hr := invoke(m.Value, 4, uintptr(unsafe.Pointer(&name[0])), 0, 0x10, 0, uintptr(unsafe.Pointer(&inner))) // IStorage.OpenStream(name, reserved1=NULL, STGM_READ|STGM_SHARE_EXCLUSIVE, reserved2=0)
	if hr != 0 {
		return 0, hresult("source IStorage.OpenStream", hr)
	}
	if inner == 0 {
		return 0, ErrInvalid
	}
	return inner, nil
}

func sourceSize(m storageMedium) (uint64, error) {
	if m.Value == 0 {
		return 0, ErrInvalid
	}
	switch m.Medium {
	case 1:
		n, _, err := kernel.NewProc("GlobalSize").Call(m.Value)
		if n == 0 && err != syscall.Errno(0) {
			return 0, err
		}
		return uint64(n), nil
	case 4:
		var stat statStorage
		hr := invoke(m.Value, 12, uintptr(unsafe.Pointer(&stat)), 1) // STATFLAG_NONAME
		if stat.Name != 0 {
			taskFree.Call(stat.Name)
		}
		if hr != 0 {
			return 0, hresult("source IStream.Stat", hr)
		}
		if stat.Type != 2 {
			return 0, ErrInvalid
		}
		return stat.Size, nil
	default:
		return 0, ErrUnsupported
	}
}

// streamSeekable probes whether an IStream supports random access. A no-op
// Seek to the current position leaves a seekable stream unchanged; a forward-only
// stream answers E_NOTIMPL. Any other failure is a real error, not a fallback.
func streamSeekable(m storageMedium) (bool, error) {
	var position uint64
	hr := invoke(m.Value, 5, 0, 1, uintptr(unsafe.Pointer(&position))) // STREAM_SEEK_CUR
	if hr == 0 {
		return true, nil
	}
	if hr == eNotImpl {
		return false, nil
	}
	return false, hresult("source IStream.Seek", hr)
}

// bufferStream reads a forward-only stream once into bounded memory so later
// ranged reads can be served without Seek. size is already quota-checked by the
// caller. Cancellation is checked between native reads; a blocking Read cannot
// be interrupted. A short read before size fails rather than guessing content.
func (s *nativeSource) bufferStream(m storageMedium, size uint64, check func() error) ([]byte, error) {
	buf := make([]byte, size)
	var off uint64
	for off < size {
		if err := check(); err != nil {
			return nil, err
		}
		chunk := uint32(min(uint64(256<<10), size-off))
		var got uint32
		hr := invoke(m.Value, 3, uintptr(unsafe.Pointer(&buf[off])), uintptr(chunk), uintptr(unsafe.Pointer(&got)))
		if hr != 0 && hr != 1 {
			return nil, hresult("source IStream.Read", hr)
		}
		if got == 0 || uint64(got) > size-off {
			return nil, io.ErrUnexpectedEOF
		}
		off += uint64(got)
	}
	return buf, nil
}

func (s *nativeSource) read(q sourceRead) error {
	if buf := s.buffers[q.index]; buf != nil {
		end := q.offset + uint64(len(q.bytes))
		if q.offset > uint64(len(buf)) || end > uint64(len(buf)) {
			return io.ErrUnexpectedEOF
		}
		copy(q.bytes, buf[q.offset:end])
		return nil
	}
	m := s.media[q.index]
	size, err := sourceSize(m)
	if err != nil {
		return err
	}
	known := s.files[q.index].Size
	if size < known || (m.Medium == 4 && size != known) {
		return ErrChanged
	}
	if m.Medium == 1 {
		p, _, err := globalLock.Call(m.Value)
		if p == 0 {
			return err
		}
		copyMemory.Call(uintptr(unsafe.Pointer(&q.bytes[0])), p+uintptr(q.offset), uintptr(len(q.bytes)))
		globalUnlock.Call(m.Value)
		return nil
	}
	var position uint64
	if hr := invoke(m.Value, 5, uintptr(q.offset), 0, uintptr(unsafe.Pointer(&position))); hr != 0 {
		return hresult("source IStream.Seek", hr)
	}
	if position != q.offset {
		return ErrInvalid
	}
	var got uint32
	hr := invoke(m.Value, 3, uintptr(unsafe.Pointer(&q.bytes[0])), uintptr(len(q.bytes)), uintptr(unsafe.Pointer(&got)))
	if hr != 0 && hr != 1 {
		return hresult("source IStream.Read", hr)
	}
	if got != uint32(len(q.bytes)) {
		return io.ErrUnexpectedEOF
	}
	after, err := sourceSize(m)
	if err != nil {
		return err
	}
	if after != known {
		return ErrChanged
	}
	return nil
}
