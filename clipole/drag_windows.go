//go:build windows && (amd64 || arm64)

package clipole

// IDropSource is a third interface on the same data object, sharing the
// controlling IUnknown and reference count with IDataObject and (when retained)
// IDataObjectAsyncCapability. It lets a consumer drive DoDragDrop with our
// virtual files. The interface only reports drag continuation/feedback intent;
// it never moves or deletes the source, and the modal drag loop belongs to the
// consumer. Exposed only when Options.DragSource is set.

func dropSourceObject(this uintptr) *object {
	o := lookup(this)
	if o == nil || o.kind != 'd' || !o.owner.s.o.DragSource {
		return nil
	}
	return o
}

// queryContinueDrag maps Escape and the mouse button state to the OLE drag
// outcomes: Escape or a retired offer cancels, releasing every mouse button
// drops, and any held button continues. Modifier keys are left to DoDragDrop's
// effect negotiation against the allowed effects.
func queryContinueDrag(this uintptr, escape uint32, keys uint32) uintptr {
	o := dropSourceObject(this)
	if o == nil {
		return eReverted
	}
	if !o.owner.valid() {
		return dragDropSCancel
	}
	if escape != 0 {
		return dragDropSCancel
	}
	if keys&(mkLButton|mkRButton|mkMButton) == 0 {
		return dragDropSDrop
	}
	return 0
}

// giveFeedback requests the default OLE cursors. A retired offer fails the call,
// which DoDragDrop treats as cancellation.
func giveFeedback(this uintptr, effect uint32) uintptr {
	o := dropSourceObject(this)
	if o == nil || !o.owner.valid() {
		return eReverted
	}
	return dragDropSUseDefaultCursors
}
