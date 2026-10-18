package ime

import (
	"errors"
	"github.com/hq0101/rdp-go/rail"
	"unsafe"
)

var (
	iidTextEditSink  = rail.GUID{Data1: 0x8127d409, Data2: 0xccd3, Data3: 0x4683, Data4: [8]byte{0x96, 0x7a, 0xb4, 0x3d, 0x5b, 0x48, 0x2b, 0xf7}}
	iidUIElementSink = rail.GUID{Data1: 0xea1ea136, Data2: 0x19df, Data3: 0x11d7, Data4: [8]byte{0xa6, 0xd2, 0, 6, 0x5b, 0x84, 0x43, 0x5c}}
	iidUIElementMgr  = rail.GUID{Data1: 0xea1ea135, Data2: 0x19df, Data3: 0x11d7, Data4: [8]byte{0xa6, 0xd2, 0, 6, 0x5b, 0x84, 0x43, 0x5c}}
	textEditVtable   [4]uintptr
	uiElementVtable  [6]uintptr
)

// TakeChanges consumes accumulated hints, initially TextAllChanged. It may be
// called with pending work, but drain Pump before sampling Presentation or
// Candidates. A failed sample must be retried even after consuming its hint.
// Theme/system-color changes remain the application's window-message concern.
func (d *WindowsDocument) TakeChanges() (TextChanges, error) {
	if err := d.enter(true); err != nil {
		return 0, err
	}
	defer d.leave()
	return d.store.changes.take()
}
func (i *WindowsInput) TakeChanges(t TextFocus) (TextChanges, error) {
	if err := i.enter(); err != nil {
		return 0, err
	}
	defer i.leave()
	if err := i.check(t); err != nil {
		return 0, err
	}
	return i.document.store.changes.take()
}

func sinkTextEdit(this uintptr, context *comObject, cookie uint32, record *comObject) uintptr {
	if context == nil {
		return ePointer
	}
	// The callback's read cookie and record never escape. Reading properties or
	// calling client renderers here would reenter an active TSF lock.
	markTextSink(this, iidTextEditSink, TextAllChanged&^TextCandidatesChanged)
	return 0
}
func sinkUIBegin(this uintptr, id uint32, show *int32) uintptr {
	if show == nil {
		return ePointer
	}
	// Each sink receives its own visibility vote. Permit the service to draw;
	// TSF combines votes, so another sink can still request that it stay hidden.
	*show = 1
	markTextSink(this, iidUIElementSink, TextCandidatesChanged)
	return 0
}
func sinkUIUpdate(this uintptr, id uint32) uintptr {
	markTextSink(this, iidUIElementSink, TextCandidatesChanged)
	return 0
}
func markTextSink(this uintptr, iid rail.GUID, changes TextChanges) {
	sinks.Lock()
	s := sinks.live[this]
	var state *textChangeState
	if s != nil && s.iid == iid {
		state = s.text
	}
	sinks.Unlock()
	if state != nil {
		state.mark(changes)
	}
}
func subscribeText(p *comObject, state *textChangeState, iid rail.GUID) (subscription, error) {
	source, err := queryCOM(p, &iidSource)
	if err != nil {
		return subscription{}, err
	}
	sinkCallbacks()
	vt := uintptr(unsafe.Pointer(&textEditVtable))
	if iid == iidUIElementSink {
		vt = uintptr(unsafe.Pointer(&uiElementVtable))
	}
	sink, err := allocateSink(&tsfSink{refs: 1, iid: iid, text: state}, vt)
	if err != nil {
		comCall(source, 2)
		return subscription{}, err
	}
	sub := subscription{source: source, sink: sink}
	hr := comCall(source, 3, uintptr(unsafe.Pointer(&iid)), sink, uintptr(unsafe.Pointer(&sub.cookie)))
	if hr != 0 {
		sinkRelease(sink)
		comCall(source, 2)
		return subscription{}, hresult("Advise text sink", hr)
	}
	sub.advised = true
	return sub, nil
}
func (d *WindowsDocument) watchText() error {
	var err error
	d.textSub, err = subscribeText(d.context, &d.store.changes, iidTextEditSink)
	if err != nil {
		return err
	}
	d.ui, err = queryCOM(d.adapter.manager, &iidUIElementMgr)
	if err != nil {
		return err
	}
	d.uiSub, err = subscribeText(d.ui, &d.store.changes, iidUIElementSink)
	if err != nil {
		return err
	}
	d.store.changes.mark(TextAllChanged)
	return nil
}
func (d *WindowsDocument) unwatchText() error {
	// A provider retaining a sink after failed Unadvise cannot repopulate the
	// old interval, and the sink does not retain the document or UI manager.
	d.store.changes.close()
	d.dropCandidateTargets()
	err := errors.Join(d.uiSub.close(), d.textSub.close())
	if d.ui != nil {
		comCall(d.ui, 2)
		d.ui = nil
	}
	return err
}
