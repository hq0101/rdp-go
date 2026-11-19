//go:build windows && (amd64 || arm64)

package clipole

import (
	"syscall"
	"unsafe"
)

func initCallbacks() {
	callbacks.Do(func() {
		q, a, r := syscall.NewCallback(query), syscall.NewCallback(addRef), syscall.NewCallback(release)
		dataVtable = [12]uintptr{q, a, r, syscall.NewCallback(getData), syscall.NewCallback(getDataHere), syscall.NewCallback(queryData), syscall.NewCallback(canonical), syscall.NewCallback(setData), syscall.NewCallback(enumData), syscall.NewCallback(advise), syscall.NewCallback(unadvise), syscall.NewCallback(enumAdvise)}
		enumVtable = [7]uintptr{q, a, r, syscall.NewCallback(enumNext), syscall.NewCallback(enumSkip), syscall.NewCallback(enumReset), syscall.NewCallback(enumClone)}
		streamVtable = [14]uintptr{q, a, r, syscall.NewCallback(streamRead), syscall.NewCallback(streamWrite), syscall.NewCallback(streamSeek), syscall.NewCallback(streamSize), syscall.NewCallback(streamCopy), syscall.NewCallback(streamCommit), syscall.NewCallback(streamRevert), syscall.NewCallback(streamRegion), syscall.NewCallback(streamRegion), syscall.NewCallback(streamStat), syscall.NewCallback(streamClone)}
		asyncVtable = [8]uintptr{q, a, r, syscall.NewCallback(asyncSetMode), syscall.NewCallback(asyncGetMode), syscall.NewCallback(asyncStart), syscall.NewCallback(asyncInOperation), syscall.NewCallback(asyncEnd)}
		dropSourceVtable = [5]uintptr{q, a, r, syscall.NewCallback(queryContinueDrag), syscall.NewCallback(giveFeedback)}
	})
}

func (n *nativeOffer) check(f *formatEtc) uintptr {
	if f == nil {
		return ePointer
	}
	if !n.valid() {
		return eReverted
	}
	if f.Target != 0 {
		return eTarget
	}
	if f.Aspect != 1 {
		return eAspect
	}
	for i, want := range n.formats {
		if f.Format != want.Format {
			continue
		}
		if f.Medium&want.Medium == 0 {
			return eMedium
		}
		if i == 1 {
			if f.Index < 0 || int(f.Index) >= len(n.s.files) || n.s.files[f.Index].IsDirectory() {
				return eIndex
			}
		} else if f.Index != -1 {
			return eIndex
		}
		return 0
	}
	return eFormat
}

// resolve gates every file-format access on lazy metadata resolution. It must
// run before check/enumeration take any object lock, since the callback may
// block on a bounded upstream fetch. Eager offers resolve to a no-op.
func (n *nativeOffer) resolve() uintptr {
	if !n.valid() {
		return eReverted
	}
	if err := n.s.ensureDescriptors(); err != nil {
		return eReverted
	}
	return 0
}
func queryData(this uintptr, f *formatEtc) uintptr {
	o := lookup(this)
	if o == nil {
		return eReverted
	}
	if hr := o.owner.resolve(); hr != 0 {
		return hr
	}
	return o.owner.check(f)
}
func getData(this uintptr, f *formatEtc, out *storageMedium) uintptr {
	if out == nil {
		return ePointer
	}
	*out = storageMedium{}
	o := lookup(this)
	if o == nil {
		return eReverted
	}
	if hr := o.owner.resolve(); hr != 0 {
		return hr
	}
	if hr := o.owner.check(f); hr != 0 {
		return hr
	}
	n := o.owner
	if f.Format == n.formats[1].Format {
		p := allocate(&object{owner: n, kind: 's', index: uint32(f.Index)})
		if p == 0 {
			return eMemory
		}
		*out = storageMedium{Medium: 4, Value: p}
		return 0
	}
	b := n.s.descriptors
	if f.Format == n.formats[2].Format {
		effect := n.s.o.PreferredDropEffect
		if effect == 0 {
			effect = DropEffectCopy
		}
		b = []byte{byte(effect), 0, 0, 0}
	}
	h := globalBytes(b)
	if h == 0 {
		return eMemory
	}
	*out = storageMedium{Medium: 1, Value: h}
	return 0
}
func getDataHere(this uintptr, f *formatEtc, out *storageMedium) uintptr { return eMedium }
func canonical(this uintptr, in, out *formatEtc) uintptr {
	if out == nil {
		return ePointer
	}
	if in == nil {
		*out = formatEtc{}
		return ePointer
	}
	*out = *in
	out.Target = 0
	return 0x40130 // DATA_S_SAMEFORMATETC
}

// setData accepts only the Shell's two write-back feedback formats. Explorer
// reports the performed drop effect and paste success here after a copy; the
// values surface through Offer.Operations at EndOperation. Nothing else is
// writable, and feedback never authorizes deleting or mutating the source.
func setData(this uintptr, f *formatEtc, medium *storageMedium, free uint32) uintptr {
	if f == nil || medium == nil {
		return ePointer
	}
	o := lookup(this)
	if o == nil || o.kind != 'd' || !o.owner.valid() {
		return eReverted
	}
	n := o.owner
	slot := -1
	for i, id := range n.feedback {
		if id != 0 && f.Format == id {
			slot = i
		}
	}
	if slot < 0 {
		return eFormat
	}
	if f.Target != 0 {
		return eTarget
	}
	if f.Aspect != 1 {
		return eAspect
	}
	if f.Index != -1 {
		return eIndex
	}
	if f.Medium != 1 || medium.Medium != 1 || medium.Value == 0 {
		return eMedium
	}
	size, _, _ := globalSize.Call(medium.Value)
	if size != 4 {
		return eInvalid
	}
	p, _, _ := globalLock.Call(medium.Value)
	if p == 0 {
		return eInvalid
	}
	var value uint32
	copyMemory.Call(uintptr(unsafe.Pointer(&value)), p, 4)
	globalUnlock.Call(medium.Value)
	if free != 0 {
		globalFree.Call(medium.Value)
	}
	objects.Lock()
	if slot == 0 {
		o.performed, o.performedValid = value, true
	} else {
		o.pasteOK, o.pasteValid = value != 0, true
	}
	objects.Unlock()
	return 0
}
func advise(this uintptr, f *formatEtc, flags uint32, sink uintptr, connection *uint32) uintptr {
	if connection != nil {
		*connection = 0
	}
	return eAdvise
}
func unadvise(this uintptr, connection uint32) uintptr { return eAdvise }
func enumAdvise(this uintptr, out *uintptr) uintptr {
	if out != nil {
		*out = 0
	}
	return eAdvise
}
func enumData(this uintptr, direction uint32, out *uintptr) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	if direction != 1 {
		return eNotImpl
	}
	o := lookup(this)
	if o == nil || !o.owner.valid() {
		return eReverted
	}
	p := allocate(&object{owner: o.owner, kind: 'e'})
	if p == 0 {
		return eMemory
	}
	*out = p
	return 0
}
func enumNext(this uintptr, count uint32, out *formatEtc, fetched *uint32) uintptr {
	if fetched != nil {
		*fetched = 0
	}
	if (count != 0 && out == nil) || (count != 1 && fetched == nil) {
		return ePointer
	}
	o := lookup(this)
	if o == nil || !o.owner.valid() {
		return eReverted
	}
	if hr := o.owner.resolve(); hr != 0 {
		return hr
	}
	if !o.mu.TryLock() {
		return eInUse
	}
	defer o.mu.Unlock()
	formats := o.owner.enumeration()
	n := min(count, uint32(len(formats))-o.index)
	for i := uint32(0); i < n; i++ {
		*(*formatEtc)(unsafe.Add(unsafe.Pointer(out), uintptr(i)*unsafe.Sizeof(*out))) = formats[o.index+i]
	}
	o.index += n
	if fetched != nil {
		*fetched = n
	}
	if n < count {
		return 1
	}
	return 0
}
func enumSkip(this uintptr, count uint32) uintptr {
	o := lookup(this)
	if o == nil || !o.owner.valid() {
		return eReverted
	}
	if hr := o.owner.resolve(); hr != 0 {
		return hr
	}
	if !o.mu.TryLock() {
		return eInUse
	}
	defer o.mu.Unlock()
	n := min(count, uint32(len(o.owner.enumeration()))-o.index)
	o.index += n
	if n < count {
		return 1
	}
	return 0
}
func enumReset(this uintptr) uintptr {
	o := lookup(this)
	if o == nil || !o.owner.valid() {
		return eReverted
	}
	if !o.mu.TryLock() {
		return eInUse
	}
	defer o.mu.Unlock()
	o.index = 0
	return 0
}
func enumClone(this uintptr, out *uintptr) uintptr {
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
	p := allocate(&object{owner: o.owner, kind: 'e', index: o.index})
	if p == 0 {
		return eMemory
	}
	*out = p
	return 0
}
