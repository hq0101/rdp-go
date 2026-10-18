package rdpdr

import (
	"encoding/binary"
	"io/fs"
	"runtime"
	"syscall"
	"unsafe"
)

func directoryMetadataAvailable() bool           { return true }
func directoryAllocation(info fs.FileInfo) int64 { return directoryFallbackAllocation(info) }

func directoryBasicInfo(info fs.FileInfo) BasicInformation {
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		value := func(t syscall.Filetime) int64 { return int64(uint64(t.HighDateTime)<<32 | uint64(t.LowDateTime)) }
		return BasicInformation{CreationTime: value(data.CreationTime), LastAccessTime: value(data.LastAccessTime), LastWriteTime: value(data.LastWriteTime), Attributes: data.FileAttributes}
	}
	return directoryFallbackBasic(info)
}

func directoryBasicHandle(f *directoryFile, _ fs.FileInfo) (BasicInformation, uint32) {
	// Native layout includes four bytes of trailing alignment; the RDPEFS
	// encoder deliberately sends only the 36 protocol bytes.
	var raw struct {
		CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
		Attributes, Padding                                     uint32
	}
	h := f.ioFile()
	ok, _, err := directoryGetInfo.Call(h.Fd(), 0, uintptr(unsafe.Pointer(&raw)), 40)
	runtime.KeepAlive(h)
	if ok == 0 {
		return BasicInformation{}, directoryStatus(err)
	}
	return BasicInformation{raw.CreationTime, raw.LastAccessTime, raw.LastWriteTime, raw.ChangeTime, raw.Attributes}, 0
}

func directorySetMetadata(f *directoryFile, set SetInformation) uint32 {
	if set.Class == FileAllocationInformation {
		b := binary.LittleEndian.AppendUint64(nil, uint64(set.Size))
		return directorySet(f.ioFile(), FileAllocationInformation, b)
	}
	b := make([]byte, 40)
	v := set.Basic
	for i, n := range []int64{v.CreationTime, v.LastAccessTime, v.LastWriteTime, v.ChangeTime} {
		binary.LittleEndian.PutUint64(b[i*8:], uint64(n))
	}
	attributes := v.Attributes
	if attributes&^uint32(0x80) != 0 {
		attributes &^= 0x80
	}
	binary.LittleEndian.PutUint32(b[32:], attributes)
	return directorySet(f.ioFile(), FileBasicInformation, b)
}
