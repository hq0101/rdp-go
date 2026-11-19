//go:build windows && (amd64 || arm64)

package clipole

import "context"

// IDataObjectAsyncCapability is a second interface on the same data object,
// with the same controlling IUnknown. It coordinates a copy, never a move or
// deletion. The STA still serializes content callbacks; consumers can marshal
// the interfaces to a background apartment using standard COM marshaling.

func asyncObject(this uintptr) *object {
	o := lookup(this)
	if o == nil || o.kind != 'd' || !o.owner.s.o.RetainOnChange || !o.owner.valid() {
		return nil
	}
	return o
}

func asyncSetMode(this uintptr, enabled uint32) uintptr {
	o := asyncObject(this)
	if o == nil {
		return eReverted
	}
	objects.Lock()
	if o.inOperation {
		objects.Unlock()
		return eInUse
	}
	if enabled != 0 {
		if !o.asyncHeld {
			if o.refs == ^uint32(0) {
				objects.Unlock()
				return eMemory
			}
			o.refs++ // SetAsyncMode's reference is released at EndOperation/disable.
			o.asyncHeld = true
		}
		o.asyncMode = true
		objects.Unlock()
		return 0
	}
	held := o.asyncHeld
	o.asyncMode, o.asyncHeld = false, false
	objects.Unlock()
	if held {
		release(this)
	}
	return 0
}

func asyncGetMode(this uintptr, out *int32) uintptr {
	return asyncState(this, out, false)
}

func asyncInOperation(this uintptr, out *int32) uintptr {
	return asyncState(this, out, true)
}

func asyncState(this uintptr, out *int32, operation bool) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	o := asyncObject(this)
	if o == nil {
		return eReverted
	}
	objects.Lock()
	defer objects.Unlock()
	if (!operation && o.asyncMode) || (operation && o.inOperation) {
		*out = -1 // VARIANT_TRUE in the BOOL-sized interface fields
	}
	return 0
}

func asyncStart(this, reserved uintptr) uintptr {
	if reserved != 0 {
		return eInvalid
	}
	o := asyncObject(this)
	if o == nil {
		return eReverted
	}
	ctx, cancel := context.WithCancel(o.owner.s.ctx)
	objects.Lock()
	if !o.asyncMode {
		objects.Unlock()
		cancel()
		return eDenied
	}
	if o.inOperation {
		objects.Unlock()
		cancel()
		return eInUse
	}
	if !o.asyncHeld {
		if o.refs == ^uint32(0) {
			objects.Unlock()
			cancel()
			return eMemory
		}
		o.refs++ // A later copy after EndOperation needs its own bounded hold.
		o.asyncHeld = true
	}
	if o.opCancel != nil {
		o.opCancel() // a successful previous operation kept its context readable
	}
	o.opCtx, o.opCancel = ctx, cancel
	o.performed, o.performedValid, o.pasteOK, o.pasteValid = 0, false, false, false
	o.inOperation = true
	objects.Unlock()
	return 0
}

func asyncEnd(this uintptr, result uint32, reserved uintptr, effects uint32) uintptr {
	if reserved != 0 {
		return eInvalid
	}
	o := asyncObject(this)
	if o == nil {
		return eReverted
	}
	objects.Lock()
	if !o.inOperation {
		objects.Unlock()
		return eInUse
	}
	held := o.asyncHeld
	o.inOperation, o.asyncHeld = false, false
	op := Operation{Result: result, Effects: effects, Performed: o.performed, PerformedValid: o.performedValid, PasteSucceeded: o.pasteOK, PasteValid: o.pasteValid}
	var cancel context.CancelFunc
	if failed(uintptr(result)) {
		// Failure/cancellation interrupts chunks still reading for this
		// operation. A successful end keeps the context so retained consumers
		// can finish; the next Start or stopAsync retires it.
		cancel, o.opCtx, o.opCancel = o.opCancel, nil, nil
	}
	objects.Unlock()
	if cancel != nil {
		cancel()
	}
	// effects reports the target's outcome; it grants no permission to delete
	// or mutate our source.
	o.owner.s.reportOperation(op)
	if held {
		release(this)
	}
	return 0
}

func (n *nativeOffer) stopAsync() {
	objects.Lock()
	o := objects.live[n.data]
	held := o != nil && o.asyncHeld
	var cancel context.CancelFunc
	if o != nil {
		o.asyncMode, o.asyncHeld, o.inOperation = false, false, false
		cancel, o.opCtx, o.opCancel = o.opCancel, nil, nil
	}
	objects.Unlock()
	if cancel != nil {
		cancel()
	}
	if held {
		release(n.data)
	}
}

// readBase binds stream reads to the active operation while one is running, so
// a failed/canceled EndOperation interrupts in-flight chunks. Outside an
// operation, reads keep the offer lifetime (retained consumers stay readable).
func (n *nativeOffer) readBase() context.Context {
	objects.Lock()
	root := objects.live[n.data]
	base := n.s.ctx
	if root != nil && root.inOperation && root.opCtx != nil {
		base = root.opCtx
	}
	objects.Unlock()
	return base
}
