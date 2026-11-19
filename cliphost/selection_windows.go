package cliphost

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/hq0101/rdp-go/clipole"
	"github.com/hq0101/rdp-go/cliprdr"
)

// AcquireFiles explicitly opens an external Unicode CF_HDROP selection. Context
// bounds acquisition only; after success the caller owns the returned selection.
// No local paths are sent to the peer. Observe/Current never open selected files.
//
// Currently supports drive-absolute local files and directories on Windows.
// UNC/mapped network drives, reparse points (including cloud placeholders),
// devices, and virtual OLE-only selections are unsupported. ANSI DROPFILES
// names are converted with the process ANSI code page; malformed ANSI fails.
// Every path component is opened relative to a validated directory handle.
// Selected handles deny ordinary write/delete sharing until Close. Enumeration
// is a bounded observed tree, not an atomic filesystem snapshot; preexisting
// writable mappings and privileged filesystem modifications are outside that
// guarantee. Size/write-time changes detected during reads fail with ErrChanged.
//
// Clipboard ownership is checked before reading paths and again after opening
// the tree. A failure closes all acquired handles. Cancellation is checked
// between native calls; it cannot interrupt a blocking filesystem operation.
// This method runs filesystem I/O on the calling goroutine, outside the Host
// clipboard worker. Join that caller separately; Host.Done does not join it.
func (h *Host) AcquireFiles(ctx context.Context, token Token, o FileSelectionOptions) (*FileSelection, error) {
	if ctx == nil || token.id == nil {
		return nil, ErrInvalid
	}
	var err error
	if o, err = selectionOptions(o); err != nil {
		return nil, err
	}
	r := h.call(command{ctx: ctx, kind: 'p', token: token})
	if r.err != nil {
		return nil, r.err
	}
	paths, err := decodeDrop(r.data)
	if err != nil {
		return nil, err
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.closed {
			return ErrClosed
		}
		if h.sampleErr != nil || h.current.Token != token || !h.current.External {
			return ErrChanged
		}
		return nil
	}
	s, err := acquireSelection(paths, o, check)
	if err != nil {
		return nil, err
	}
	s.preferred = r.preferred
	if err = h.call(command{ctx: ctx, kind: 'v', token: token}).err; err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

func (w *worker) selectionCurrent(token Token) bool {
	return w.valid && token.id != nil && token == w.snapshot.Token && w.snapshot.External && w.snapshot.Files
}

func (w *worker) verifySelection(token Token) (err error) {
	if !w.selectionCurrent(token) {
		return ErrChanged
	}
	if ok, _, _ := openClipboard.Call(w.hwnd); ok == 0 {
		return ErrBusy
	}
	o, seq := nativeStamp()
	if o != w.owner || seq != w.sequence {
		err = ErrChanged
	}
	if ok, _, e := closeClipboard.Call(); ok == 0 {
		err = errors.Join(err, winerr("CloseClipboard", e))
	}
	return err
}

func (w *worker) readDrop(ctx context.Context, token Token) (b []byte, preferred uint32, err error) {
	preferred = clipole.DropEffectCopy
	if !w.selectionCurrent(token) {
		return nil, 0, ErrChanged
	}
	if ok, _, _ := openClipboard.Call(w.hwnd); ok == 0 {
		return nil, 0, ErrBusy
	}
	defer func() {
		if ok, _, e := closeClipboard.Call(); ok == 0 {
			b = nil
			err = errors.Join(err, winerr("CloseClipboard", e))
		}
	}()
	o, seq := nativeStamp()
	if o != w.owner || seq != w.sequence {
		return nil, 0, ErrChanged
	}
	handle, _, e := getData.Call(15)
	if handle == 0 {
		return nil, 0, winerr("GetClipboardData/CF_HDROP", e)
	}
	if err = ctx.Err(); err != nil {
		return nil, 0, err
	}
	after, rendered := nativeStamp()
	if after != o {
		return nil, 0, ErrChanged
	}
	w.sequence = rendered
	n, _, _ := size.Call(handle)
	if n < 24 || n > maxDropBytes {
		return nil, 0, ErrInvalid
	}
	p, _, e := lock.Call(handle)
	if p == 0 {
		return nil, 0, winerr("GlobalLock/CF_HDROP", e)
	}
	b = make([]byte, int(n))
	copyMemory.Call(uintptr(unsafe.Pointer(&b[0])), p, n)
	if err = unlockBytes(handle); err != nil {
		return nil, 0, err
	}
	if b, err = normalizeDropANSI(b); err != nil {
		return nil, 0, err
	}
	// Observe move/copy intent while the clipboard is still open. An absent
	// Preferred DropEffect means copy; a present but malformed value fails.
	name, _ := syscall.UTF16FromString("Preferred DropEffect")
	prefID, _, e := registerFormat.Call(uintptr(unsafe.Pointer(&name[0])))
	if prefID == 0 {
		return nil, 0, winerr("RegisterClipboardFormat/Preferred DropEffect", e)
	}
	if avail, _, _ := formatAvailable.Call(prefID); avail != 0 {
		eh, _, e := getData.Call(prefID)
		if eh == 0 {
			return nil, 0, winerr("GetClipboardData/Preferred DropEffect", e)
		}
		if en, _, _ := size.Call(eh); en != 4 {
			return nil, 0, ErrInvalid
		}
		ep, _, e := lock.Call(eh)
		if ep == 0 {
			return nil, 0, winerr("GlobalLock/Preferred DropEffect", e)
		}
		var eb [4]byte
		copyMemory.Call(uintptr(unsafe.Pointer(&eb[0])), ep, 4)
		if err = unlockBytes(eh); err != nil {
			return nil, 0, err
		}
		if preferred, err = decodeDropEffect(eb[:]); err != nil {
			return nil, 0, err
		}
	}
	final, rendered := nativeStamp()
	if final != o {
		return nil, 0, ErrChanged
	}
	w.sequence = rendered
	return b, preferred, nil
}

// normalizeDropANSI rewrites an ANSI DROPFILES name list as Unicode using the
// process ANSI code page, so decodeDrop's Unicode bounds and limits apply
// unchanged. MB_ERR_INVALID_CHARS makes malformed ANSI fail instead of being
// replaced or guessed. Unicode payloads pass through untouched.
func normalizeDropANSI(b []byte) ([]byte, error) {
	if len(b) < 20 || binary.LittleEndian.Uint32(b[16:]) != 0 {
		return b, nil
	}
	start := int(binary.LittleEndian.Uint32(b))
	if start < 20 || start > len(b)-2 {
		return nil, ErrInvalid
	}
	src := b[start:]
	dst := make([]uint16, len(src))
	n, _, _ := multiByteToWide.Call(0, 8, uintptr(unsafe.Pointer(&src[0])), uintptr(len(src)), uintptr(unsafe.Pointer(&dst[0])), uintptr(len(dst)))
	if n == 0 || 20+n*2 > maxDropBytes {
		return nil, ErrInvalid
	}
	out := make([]byte, 20, 20+n*2)
	out[0], out[16] = 20, 1
	for i := 0; i < int(n); i++ {
		out = binary.LittleEndian.AppendUint16(out, dst[i])
	}
	return out, nil
}

type selectionNTString struct {
	Length, Maximum uint16
	Buffer          *uint16
}
type selectionNTObject struct {
	Length            uint32
	Root              uintptr
	Name              *selectionNTString
	Attributes        uint32
	Security, Quality uintptr
}
type selectionNTIO struct{ Status, Information uintptr }

var selectionNtdll = syscall.NewLazyDLL("ntdll.dll")
var selectionNtCreate = selectionNtdll.NewProc("NtCreateFile")
var selectionNtError = selectionNtdll.NewProc("RtlNtStatusToDosError")

func selectionLeaf(parent *os.File, name string, selected bool) (*os.File, error) {
	if err := selectionName(name); err != nil {
		return nil, err
	}
	u := utf16.Encode([]rune(name))
	n := selectionNTString{uint16(len(u) * 2), uint16(len(u) * 2), &u[0]}
	a := selectionNTObject{Root: parent.Fd(), Name: &n, Attributes: 0x1040} // DONT_REPARSE | CASE_INSENSITIVE
	a.Length = uint32(unsafe.Sizeof(a))
	access, share := uintptr(0x1000a0), uintptr(3) // ancestor attributes/traverse, read/write sharing, no delete
	if selected {
		access, share = 0x120089, 1 // FILE_GENERIC_READ, FILE_SHARE_READ only
	}
	var handle uintptr
	var ios selectionNTIO
	status, _, _ := selectionNtCreate.Call(uintptr(unsafe.Pointer(&handle)), access, uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(&ios)), 0, 0, share, 1, 0x600020, 0, 0) // OPEN, synchronous, no reparse/no recall
	runtime.KeepAlive(parent)
	runtime.KeepAlive(u)
	if uint32(status) != 0 {
		e, _, _ := selectionNtError.Call(status)
		return nil, winerr("open selected file", syscall.Errno(e))
	}
	return os.NewFile(handle, name), nil
}

func selectionName(name string) error {
	if strings.ContainsAny(name, `/\`) {
		return cliprdr.ErrFilePath
	}
	_, err := cliprdr.PlanFileOffer([]cliprdr.FileDescriptor{{Name: name, Flags: cliprdr.FileSizeValid}}, cliprdr.FilePlanOptions{})
	return err
}

func selectionPath(path string) (string, []string, error) {
	path = strings.ReplaceAll(path, "/", `\`)
	path = strings.TrimPrefix(path, `\\?\`)
	if len(path) < 4 || path[1:3] != `:\` || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) {
		return "", nil, ErrUnsupported
	}
	parts := strings.Split(path[3:], `\`)
	if len(parts) > 128 || len(utf16.Encode([]rune(path))) > 32767 {
		return "", nil, cliprdr.ErrFileLimit
	}
	for _, part := range parts {
		if err := selectionName(part); err != nil {
			return "", nil, err
		}
	}
	return path[:3], parts, nil
}

func selectionInfo(f *os.File) (syscall.ByHandleFileInformation, error) {
	var info syscall.ByHandleFileInformation
	kind, err := syscall.GetFileType(syscall.Handle(f.Fd()))
	if err != nil || kind != syscall.FILE_TYPE_DISK {
		return info, errors.Join(ErrUnsupported, err)
	}
	if err = syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &info); err != nil {
		return info, winerr("selected file information", err)
	}
	// Reject all reparse/cloud placeholders and offline files before any data read.
	if info.FileAttributes&(0x400|0x1000|0x40000|0x400000) != 0 {
		return info, ErrUnsupported
	}
	return info, nil
}

func openSelectionPath(volume string, parts []string, check func() error) (f *os.File, err error) {
	u, _ := syscall.UTF16FromString(volume)
	kind, _, _ := kernel.NewProc("GetDriveTypeW").Call(uintptr(unsafe.Pointer(&u[0])))
	if kind != 2 && kind != 3 && kind != 5 && kind != 6 { // local removable/fixed/CD/RAM only
		return nil, ErrUnsupported
	}
	handle, err := syscall.CreateFile(&u[0], 0x1000a0, 3, nil, syscall.OPEN_EXISTING, 0x02200000, 0)
	if err != nil {
		return nil, winerr("open selected volume", err)
	}
	parent := os.NewFile(uintptr(handle), volume)
	defer func() { err = errors.Join(err, parent.Close()) }()
	for i, part := range parts {
		if err = check(); err != nil {
			return nil, err
		}
		info, e := selectionInfo(parent)
		if e != nil || info.FileAttributes&0x10 == 0 {
			return nil, errors.Join(ErrUnsupported, e)
		}
		next, e := selectionLeaf(parent, part, i == len(parts)-1)
		if e != nil {
			return nil, e
		}
		if i == len(parts)-1 {
			return next, nil
		}
		if e = parent.Close(); e != nil {
			return nil, errors.Join(e, next.Close())
		}
		parent = next
	}
	return nil, ErrInvalid
}

type selectedNativeFile struct {
	file *os.File
	info syscall.ByHandleFileInformation
}

func (f *selectedNativeFile) Close() error { return f.file.Close() }
func (f *selectedNativeFile) unchanged() error {
	info, err := selectionInfo(f.file)
	if err != nil {
		return err
	}
	if info.FileSizeHigh != f.info.FileSizeHigh || info.FileSizeLow != f.info.FileSizeLow || info.LastWriteTime != f.info.LastWriteTime {
		return ErrChanged
	}
	return nil
}
func (f *selectedNativeFile) ReadAt(p []byte, off int64) (int, error) {
	if err := f.unchanged(); err != nil {
		return 0, err
	}
	n, err := f.file.ReadAt(p, off)
	if changed := f.unchanged(); changed != nil {
		clear(p)
		return 0, changed
	}
	return n, err
}

func acquireSelection(paths []string, o FileSelectionOptions, check func() error) (selection *FileSelection, err error) {
	if len(paths) == 0 || len(paths) > o.MaxFiles {
		return nil, cliprdr.ErrFileLimit
	}
	type root struct {
		volume string
		parts  []string
	}
	roots := make([]root, len(paths))
	preview := make([]cliprdr.FileDescriptor, len(paths))
	for i, path := range paths {
		volume, parts, e := selectionPath(path)
		if e != nil {
			return nil, e
		}
		roots[i] = root{volume, parts}
		preview[i] = cliprdr.FileDescriptor{Name: parts[len(parts)-1], Flags: cliprdr.FileSizeValid}
	}
	// Reject colliding root names before opening anything.
	if _, err := cliprdr.PlanFileOffer(preview, cliprdr.FilePlanOptions{}); err != nil {
		return nil, err
	}
	s := &FileSelection{}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
		}
	}()
	var descriptors []cliprdr.FileDescriptor
	var walk func(*os.File, string, int) error
	walk = func(f *os.File, name string, depth int) (err error) {
		// Ownership is transferred into s immediately, including on validation failure.
		source := &selectedNativeFile{file: f}
		s.files = append(s.files, selectedFile{source: source})
		if err = check(); err != nil {
			return err
		}
		if len(s.files) > o.MaxFiles || depth > cliprdr.MaxFileTreeDepth {
			return cliprdr.ErrFileLimit
		}
		info, err := selectionInfo(f)
		if err != nil {
			return err
		}
		source.info = info
		d := cliprdr.FileDescriptor{Name: name, Flags: cliprdr.FileAttributesValid | cliprdr.FileWriteTimeValid, Attributes: info.FileAttributes & 0xb7, WriteTime: uint64(info.LastWriteTime.HighDateTime)<<32 | uint64(info.LastWriteTime.LowDateTime)}
		if !d.IsDirectory() {
			d.Flags |= cliprdr.FileSizeValid
			d.Size = uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
		}
		s.files[len(s.files)-1].descriptor = d
		descriptors = append(descriptors, d)
		if _, err = cliprdr.PlanFileOffer(descriptors, cliprdr.FilePlanOptions{MaxFileSize: o.MaxTotalSize, MaxTotalSize: o.MaxTotalSize}); err != nil {
			return err
		}
		if !d.IsDirectory() {
			return nil
		}
		for {
			if err = check(); err != nil {
				return err
			}
			names, e := f.Readdirnames(32)
			if e != nil && e != io.EOF {
				return e
			}
			for _, child := range names {
				if err = check(); err != nil {
					return err
				}
				if len(s.files) >= o.MaxFiles || depth >= cliprdr.MaxFileTreeDepth {
					return cliprdr.ErrFileLimit
				}
				next, err := selectionLeaf(f, child, true)
				if err != nil {
					return err
				}
				if err = walk(next, name+"/"+child, depth+1); err != nil {
					return err
				}
			}
			if e == io.EOF {
				return nil
			}
		}
	}
	for _, root := range roots {
		f, e := openSelectionPath(root.volume, root.parts, check)
		if e != nil {
			if f != nil {
				e = errors.Join(e, f.Close())
			}
			return nil, e
		}
		if err = walk(f, root.parts[len(root.parts)-1], 1); err != nil {
			return nil, err
		}
	}
	if err = check(); err != nil {
		return nil, err
	}
	return s, nil
}
