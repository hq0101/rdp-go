package rdpdr

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	directoryNtOpen   = syscall.NewLazyDLL("ntdll.dll").NewProc("NtOpenFile")
	directoryGetInfo  = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFileInformationByHandleEx")
	directoryNtCreate = syscall.NewLazyDLL("ntdll.dll").NewProc("NtCreateFile")
	directoryNtSet    = syscall.NewLazyDLL("ntdll.dll").NewProc("NtSetInformationFile")
)

type directoryNTString struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}
type directoryNTObject struct {
	Length            uint32
	Root              uintptr
	Name              *directoryNTString
	Attributes        uint32
	Security, Quality uintptr
}
type directoryNTIO struct{ Status, Information uintptr }

func directoryNamespaceAvailable() bool          { return true }
func directoryRequestedFlags(options uint32) int { return int(options & 0x200000) }

// An empty name relative to the validated object reopens that same object,
// including directories, even after its original name has been replaced.
// The original and identity handles have one FileHandles owner and close job.
// Native sharing remains permissive; protocol sharing is checked separately.
func directoryPrepareIdentity(f *directoryFile) uint32 {
	handle, status := directoryReopenIdentity(f, 0)
	if status == 0 {
		f.identity = handle
	}
	return status
}

func directoryReopenIdentity(f *directoryFile, extra uint32) (*os.File, uint32) {
	source := directoryIdentity(f)
	name := directoryNTString{}
	obj := directoryNTObject{Root: source.Fd(), Name: &name, Attributes: 0x40}
	obj.Length = uint32(unsafe.Sizeof(obj))
	options := uint32(0x20|0x200000) | extra | (f.openOptions & 0x400000)
	if f.info.IsDir() && f.openOptions&0x400000 == 0 {
		options |= 1
	} else if !f.info.IsDir() {
		options |= 0x40
	}
	var h uintptr
	var ios directoryNTIO
	s, _, _ := directoryNtOpen.Call(uintptr(unsafe.Pointer(&h)), uintptr(f.access|0x120088), uintptr(unsafe.Pointer(&obj)), uintptr(unsafe.Pointer(&ios)), 7, uintptr(options))
	runtime.KeepAlive(source)
	if uint32(s) != 0 {
		return nil, uint32(s)
	}
	return os.NewFile(h, f.file.Name()), 0
}

func directoryIdentity(f *directoryFile) *os.File {
	if f.identity != nil {
		return f.identity
	}
	return f.file
}

// Keep native delete-on-close distinct from an explicit disposition. The native
// flag, not a pathname removal, controls exactly when deletion becomes pending.
func directoryPrepareDeleteOnClose(f *directoryFile) uint32 {
	handle, status := directoryReopenIdentity(f, 0x1000)
	if status == 0 {
		f.closeDelete = handle
	}
	return status
}

func directoryMarkDelete(f *directoryFile) uint32 {
	flag := []byte{1}
	return directorySet(directoryIdentity(f), 13, flag)
}

func directorySet(f *os.File, class uint32, data []byte) uint32 {
	var ios directoryNTIO
	s, _, _ := directoryNtSet.Call(f.Fd(), uintptr(unsafe.Pointer(&ios)), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(class))
	runtime.KeepAlive(f)
	runtime.KeepAlive(data)
	return uint32(s)
}

// Only one validated leaf component is supplied to each native call. DONT_REPARSE
// prevents traversal through a substituted junction or symbolic link. Ancestor
// handles exclude SHARE_DELETE until the namespace operation has completed.
func directoryNativeOpen(parent *os.File, name string, access, share, disposition, options, attributes uint32) (*os.File, bool, uint32) {
	return directoryNativeCreate(parent, name, access, share, disposition, options, attributes, 0)
}

func directoryNativeCreate(parent *os.File, name string, access, share, disposition, options, attributes uint32, allocation uint64) (*os.File, bool, uint32) {
	u := utf16.Encode([]rune(name))
	if len(u) == 0 || len(u) > 255 {
		return nil, false, StatusInvalidParameter
	}
	ntName := directoryNTString{uint16(len(u) * 2), uint16(len(u) * 2), &u[0]}
	obj := directoryNTObject{Root: parent.Fd(), Name: &ntName, Attributes: 0x1040}
	obj.Length = uint32(unsafe.Sizeof(obj))
	var handle uintptr
	var ios directoryNTIO
	if attributes&^uint32(0x80) != 0 {
		attributes &^= 0x80
	}
	s, _, _ := directoryNtCreate.Call(uintptr(unsafe.Pointer(&handle)), uintptr(access|0x120088), uintptr(unsafe.Pointer(&obj)), uintptr(unsafe.Pointer(&ios)), uintptr(unsafe.Pointer(&allocation)), uintptr(attributes), uintptr(share), uintptr(disposition), uintptr(options|0x20), 0, 0)
	runtime.KeepAlive(parent)
	runtime.KeepAlive(u)
	if uint32(s) != 0 {
		if uint32(s) == 0xc0000034 { // normalize missing leaf as in os.Root backend
			return nil, false, StatusNoSuchFile
		}
		return nil, false, uint32(s)
	}
	return os.NewFile(handle, name), ios.Information == 2, 0
}

func closeDirectoryParents(pins []*os.File) error {
	var failures []error
	for i := len(pins) - 1; i >= 0; i-- {
		failures = append(failures, pins[i].Close())
	}
	return errors.Join(failures...)
}

func (d *DirectoryDrive) namespaceParent(name string) (*os.File, string, []*os.File, uint32) {
	return d.namespaceParentOptions(name, 0)
}

func (d *DirectoryDrive) namespaceParentOptions(name string, options uint32) (parent *os.File, leaf string, pins []*os.File, status uint32) {
	parts := strings.Split(name, "/")
	parent = d.rootFile
	for _, part := range parts[:len(parts)-1] {
		openOptions := options
		if options&0x400000 == 0 {
			openOptions |= 1
		}
		f, _, s := directoryNativeOpen(parent, part, 0xa0, 3, 1, openOptions, 0x10)
		if s != 0 {
			return parent, "", pins, s
		}
		pins = append(pins, f)
		info, err := f.Stat()
		if err != nil {
			return parent, "", pins, directoryStatus(err)
		}
		if !info.IsDir() || info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return parent, "", pins, statusNotDirectory
		}
		parent = f
	}
	return parent, parts[len(parts)-1], pins, 0
}

func (d *DirectoryDrive) renameNamespace(f *directoryFile, name string, replace bool) (status uint32, err error) {
	parent, leaf, pins, status := d.namespaceParent(name)
	defer func() { err = errors.Join(err, closeDirectoryParents(pins)) }()
	if status != 0 {
		return status, nil
	}
	u := utf16.Encode([]rune(leaf))
	type renameLayout struct {
		Replace uint32
		Root    uintptr
		Length  uint32
		Name    [1]uint16
	}
	var layout renameLayout
	start := int(unsafe.Offsetof(layout.Name))
	data := make([]byte, int(unsafe.Sizeof(layout))+len(u)*2)
	header := (*renameLayout)(unsafe.Pointer(&data[0]))
	if replace {
		header.Replace = 1
	}
	header.Root = parent.Fd()
	header.Length = uint32(len(u) * 2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(data[start+i*2:], c)
	}
	status = directorySet(directoryIdentity(f), 10, data)
	runtime.KeepAlive(parent)
	return status, nil
}

func directoryStandard(f *directoryFile, _ fs.FileInfo) (StandardInformation, uint32) {
	var raw struct {
		AllocationSize, EndOfFile int64
		Links                     uint32
		DeletePending, Directory  uint8
		Pad                       uint16
	}
	ok, _, err := directoryGetInfo.Call(f.ioFile().Fd(), 1, uintptr(unsafe.Pointer(&raw)), uintptr(unsafe.Sizeof(raw)))
	runtime.KeepAlive(f.ioFile())
	if ok == 0 {
		return StandardInformation{}, directoryStatus(err)
	}
	return StandardInformation{AllocationSize: raw.AllocationSize, EndOfFile: raw.EndOfFile, Links: raw.Links, DeletePending: raw.DeletePending != 0, Directory: raw.Directory != 0}, 0
}

var directoryFinalPath = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFinalPathNameByHandleW")

// This is metadata only, never a path used for an OS mutation. Native handles
// remain the authority. A normalized name query can fail on unusual filesystems;
// keep the prior hint rather than report a completed rename as failed.
func directoryHandlePath(f *os.File) (string, bool) {
	buf := make([]uint16, 32768)
	n, _, _ := directoryFinalPath.Call(f.Fd(), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	runtime.KeepAlive(f)
	if n == 0 || n >= uintptr(len(buf)) {
		return "", false
	}
	return string(utf16.Decode(buf[:n])), true
}
func (d *DirectoryDrive) refreshNamespacePaths() {
	root, ok := directoryHandlePath(d.rootFile)
	if !ok {
		return
	}
	prefix := strings.TrimRight(root, `\`) + `\`
	for _, f := range d.files {
		name, ok := directoryHandlePath(f.ioFile())
		if !ok {
			continue
		}
		if directorySamePath(name, root) {
			f.path = "."
			continue
		}
		if len(name) > len(prefix) && directorySamePath(name[:len(prefix)], prefix) {
			if relative, err := directoryPath(name[len(prefix):]); err == nil {
				f.path = relative
			}
		}
	}
}
