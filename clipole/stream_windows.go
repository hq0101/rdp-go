//go:build windows && (amd64 || arm64)

package clipole

import (
	"context"
	"syscall"
	"unsafe"
)

func streamRead(this, buffer uintptr, count uint32, read *uint32) uintptr {
	if read != nil {
		*read = 0
	}
	if count != 0 && buffer == 0 {
		return ePointer
	}
	o := lookup(this)
	if o == nil || !o.owner.valid() {
		return eReverted
	}
	if !o.mu.TryLock() {
		return eInUse
	}
	defer o.mu.Unlock()
	s := o.owner.s
	ctx, cancel := context.WithTimeout(o.owner.readBase(), s.o.ReadTimeout)
	defer cancel()
	total := uint32(0)
	for total < count && o.position < s.files[o.index].Size {
		length := uint32(min(uint64(count-total), uint64(s.o.ChunkSize), s.files[o.index].Size-o.position))
		b, err := s.chunk(ctx, o.index, o.position, length)
		if !o.owner.valid() {
			return eReverted
		}
		if err != nil {
			return eRead
		}
		copyMemory.Call(buffer+uintptr(total), uintptr(unsafe.Pointer(&b[0])), uintptr(length))
		o.position += uint64(length)
		total += length
		if read != nil {
			*read = total
		}
	}
	if total < count {
		return 1
	}
	return 0
}
func streamWrite(this, buffer uintptr, count uint32, written *uint32) uintptr {
	if written != nil {
		*written = 0
	}
	return eDenied
}
func streamSize(this, size uintptr) uintptr { return eDenied }
func streamCommit(this uintptr, flags uint32) uintptr {
	o := lookup(this)
	if o == nil || !o.owner.valid() {
		return eReverted
	}
	return 0
}
func streamRevert(this uintptr) uintptr                                  { return eNotImpl }
func streamRegion(this, offset, length uintptr, lockType uint32) uintptr { return eFunction }

func streamSeek(this, move uintptr, origin uint32, out *uint64) uintptr {
	if out != nil {
		*out = 0
	}
	o := lookup(this)
	if o == nil || !o.owner.valid() {
		return eReverted
	}
	if !o.mu.TryLock() {
		return eInUse
	}
	defer o.mu.Unlock()
	p, ok := seekPosition(o.position, o.owner.s.files[o.index].Size, uint64(move), origin)
	if !ok {
		return eFunction
	}
	o.position = p
	if out != nil {
		*out = p
	}
	return 0
}

func streamStat(this uintptr, out *statStorage, flags uint32) uintptr {
	if out == nil {
		return ePointer
	}
	*out = statStorage{}
	if flags > 1 {
		return eInvalid
	}
	o := lookup(this)
	if o == nil || !o.owner.valid() {
		return eReverted
	}
	f := o.owner.s.files[o.index]
	if flags == 0 {
		name, _ := syscall.UTF16FromString(f.Name)
		bytes := uintptr(len(name) * 2)
		p, _, _ := taskAlloc.Call(bytes)
		if p == 0 {
			return eMemory
		}
		copyMemory.Call(p, uintptr(unsafe.Pointer(&name[0])), bytes)
		out.Name = p
	}
	out.Type = 2 // STGTY_STREAM; STGM_READ is zero
	out.Size = f.Size
	if f.Flags&0x20 != 0 {
		out.Modified = [2]uint32{uint32(f.WriteTime), uint32(f.WriteTime >> 32)}
	}
	return 0
}
func streamClone(this uintptr, out *uintptr) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	o := lookup(this)
	if o == nil || !o.owner.valid() {
		return eReverted
	}
	if !o.mu.TryLock() {
		return eInUse
	}
	defer o.mu.Unlock()
	p := allocate(&object{owner: o.owner, kind: 's', index: o.index, position: o.position})
	if p == 0 {
		return eMemory
	}
	*out = p
	return 0
}

func streamCopy(this, target, count uintptr, read, written *uint64) uintptr {
	if read != nil {
		*read = 0
	}
	if written != nil {
		*written = 0
	}
	if target == 0 {
		return ePointer
	}
	o := lookup(this)
	if o == nil || !o.owner.valid() {
		return eReverted
	}
	if !o.mu.TryLock() {
		return eInUse
	}
	defer o.mu.Unlock()
	s := o.owner.s
	ctx, cancel := context.WithTimeout(o.owner.readBase(), s.o.ReadTimeout)
	defer cancel()
	var total, output uint64
	for total < uint64(count) && o.position < s.files[o.index].Size {
		length := uint32(min(uint64(count)-total, uint64(s.o.ChunkSize), s.files[o.index].Size-o.position))
		b, err := s.chunk(ctx, o.index, o.position, length)
		if !o.owner.valid() {
			return eReverted
		}
		if err != nil {
			return eRead
		}
		o.position += uint64(length)
		total += uint64(length)
		if read != nil {
			*read = total
		}
		var n uint32
		hr := invoke(target, 4, uintptr(unsafe.Pointer(&b[0])), uintptr(length), uintptr(unsafe.Pointer(&n)))
		if n > length {
			return eWrite
		}
		output += uint64(n)
		if written != nil {
			*written = output
		}
		if failed(hr) {
			return hr
		}
		if n != length {
			return eWrite
		}
	}
	// CopyTo(max uint64) is the conventional copy-to-EOF operation.
	return 0
}
