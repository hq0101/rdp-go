package rdpdr

import (
	"os"
	"runtime"
	"unsafe"
)

// The empty relative name addresses the validated file object, even if a local
// process has since replaced its old name. NtCreateFile performs FILE_OVERWRITE
// on that object, applying allocation and OR-ing attributes with existing ones.
// This is called only after all protocol access/type/sharing checks. Its new
// handle is owned by the same FileID and close job; no path is resolved again.
func directoryOverwrite(f *directoryFile, q *CreateRequest) uint32 {
	if f.identity != nil || f.info.IsDir() || f.access&2 == 0 {
		return StatusInvalidParameter
	}
	if status := directoryCreationPolicy(q); status != 0 {
		return status
	}
	name := directoryNTString{}
	obj := directoryNTObject{Root: f.file.Fd(), Name: &name, Attributes: 0x40}
	obj.Length = uint32(unsafe.Sizeof(obj))
	options := uint32(0x200060) | (q.Options & (2 | 4 | 0x800 | 0x400000))
	attributes := q.Attributes
	if attributes&^uint32(0x80) != 0 {
		attributes &^= 0x80
	}
	allocation := q.AllocationSize
	var handle uintptr
	var ios directoryNTIO
	s, _, _ := directoryNtCreate.Call(uintptr(unsafe.Pointer(&handle)), uintptr(f.access|0x120088), uintptr(unsafe.Pointer(&obj)), uintptr(unsafe.Pointer(&ios)), uintptr(unsafe.Pointer(&allocation)), uintptr(attributes), 7, 4, uintptr(options), 0, 0)
	runtime.KeepAlive(f.file)
	if uint32(s) == 0 {
		f.identity = os.NewFile(handle, f.file.Name())
	}
	return uint32(s)
}
