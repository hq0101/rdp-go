//go:build windows && (amd64 || arm64)

package clipole

import (
	"context"
	"fmt"
	"math"
	"sync"
	"syscall"
	"unsafe"

	"github.com/hq0101/rdp-go/cliprdr"
)

// IDropTarget is the OLE drag-and-drop receiving contract. Unlike the provider
// data object, a target is registered against a window on the caller's thread
// (RegisterDragDrop) and its callbacks run on the thread OLE drives the drag on;
// it owns no apartment of its own. A completed Drop adopts the dropped
// IDataObject into a dedicated source apartment (acquireDrop) so subsequent file
// reads never depend on the caller's message pump. Negotiating or observing a
// move effect never moves or deletes the drag source.

var (
	registerDragDrop = ole.NewProc("RegisterDragDrop")
	revokeDragDrop   = ole.NewProc("RevokeDragDrop")
	iidDropTarget    = guid{A: 0x122, D: iidUnknown.D}
)

// targetObject is rooted in a registry separate from the provider objects so the
// verified clipboard provider is untouched. State (data/entered/effect) is
// guarded by targets; refs is the COM reference count. The native instance holds
// only a permanent vtable address, never a Go pointer.
type targetObject struct {
	t       *DropTarget
	refs    uint32
	data    uintptr
	entered bool
	effect  uint32
}

var targets = struct {
	sync.Mutex
	live map[uintptr]*targetObject
}{live: map[uintptr]*targetObject{}}
var targetCallbacks sync.Once
var dropTargetVtable [7]uintptr

func initTargetCallbacks() {
	targetCallbacks.Do(func() {
		dropTargetVtable = [7]uintptr{
			syscall.NewCallback(targetQuery),
			syscall.NewCallback(targetAddRef),
			syscall.NewCallback(targetRelease),
			syscall.NewCallback(targetDragEnter),
			syscall.NewCallback(targetDragOver),
			syscall.NewCallback(targetDragLeave),
			syscall.NewCallback(targetDrop),
		}
	})
}

func allocateTarget(t *DropTarget) uintptr {
	initTargetCallbacks()
	vt := uintptr(unsafe.Pointer(&dropTargetVtable[0]))
	size := unsafe.Sizeof(uintptr(0))
	p, _, _ := taskAlloc.Call(size)
	if p == 0 {
		return 0
	}
	copyMemory.Call(p, uintptr(unsafe.Pointer(&vt)), size)
	targets.Lock()
	defer targets.Unlock()
	if len(targets.live) >= 512 {
		taskFree.Call(p)
		return 0
	}
	targets.live[p] = &targetObject{t: t, refs: 1}
	return p
}

func lookupTarget(this uintptr) *targetObject {
	targets.Lock()
	defer targets.Unlock()
	return targets.live[this]
}

func targetQuery(this uintptr, iid *guid, out *uintptr) uintptr {
	if out == nil {
		return ePointer
	}
	*out = 0
	if iid == nil {
		return ePointer
	}
	targets.Lock()
	defer targets.Unlock()
	o := targets.live[this]
	if o == nil {
		return eReverted
	}
	if *iid != iidUnknown && *iid != iidDropTarget {
		return eNoInterface
	}
	if o.refs == ^uint32(0) {
		return eMemory
	}
	o.refs++
	*out = this
	return 0
}

func targetAddRef(this uintptr) uintptr {
	targets.Lock()
	defer targets.Unlock()
	o := targets.live[this]
	if o == nil {
		return 0
	}
	if o.refs != ^uint32(0) {
		o.refs++
	}
	return uintptr(o.refs)
}

func targetRelease(this uintptr) uintptr {
	targets.Lock()
	o := targets.live[this]
	if o == nil {
		targets.Unlock()
		return 0
	}
	if o.refs == ^uint32(0) {
		targets.Unlock()
		return uintptr(o.refs)
	}
	o.refs--
	remaining := o.refs
	var t *DropTarget
	if remaining == 0 {
		t = o.t
		delete(targets.live, this)
	}
	targets.Unlock()
	if remaining == 0 {
		taskFree.Call(this)
		t.finish()
	}
	return uintptr(remaining)
}

// negotiateEffect intersects the source's allowed effects with this target's
// allowed mask, then honors the modifier keys (Ctrl=Copy, Shift=Move,
// Ctrl+Shift=Link). When the requested effect is not permitted it falls back to
// Copy, then Move, then Link; an empty intersection yields None. It only chooses
// an effect flag and never authorizes moving or deleting the source.
func negotiateEffect(sourceAllowed, allowed, keys uint32) uint32 {
	effective := sourceAllowed & allowed
	var want uint32
	switch {
	case keys&mkControl != 0 && keys&mkShift != 0:
		want = DropEffectLink
	case keys&mkControl != 0:
		want = DropEffectCopy
	case keys&mkShift != 0:
		want = DropEffectMove
	default:
		want = DropEffectCopy
	}
	if effective&want != 0 {
		return want
	}
	for _, e := range []uint32{DropEffectCopy, DropEffectMove, DropEffectLink} {
		if effective&e != 0 {
			return e
		}
	}
	return DropEffectNone
}

func targetDragEnter(this uintptr, data uintptr, keys uint32, pt uintptr, effect *uint32) uintptr {
	if effect == nil {
		return ePointer
	}
	o := lookupTarget(this)
	if o == nil || o.t.ctx.Err() != nil {
		*effect = DropEffectNone
		return eReverted
	}
	if data == 0 {
		*effect = DropEffectNone
		return ePointer
	}
	invoke(data, 1) // OLE owns data only for the callback; retain it across the drag
	targets.Lock()
	prev := o.data
	o.data = data
	o.entered = true
	eff := negotiateEffect(*effect, o.t.o.AllowedEffects, keys)
	o.effect = eff
	*effect = eff
	targets.Unlock()
	if prev != 0 {
		invoke(prev, 2)
	}
	return 0
}

func targetDragOver(this uintptr, keys uint32, pt uintptr, effect *uint32) uintptr {
	if effect == nil {
		return ePointer
	}
	o := lookupTarget(this)
	if o == nil || o.t.ctx.Err() != nil {
		*effect = DropEffectNone
		return eReverted
	}
	targets.Lock()
	defer targets.Unlock()
	if !o.entered {
		*effect = DropEffectNone
		return eUnexpected
	}
	eff := negotiateEffect(*effect, o.t.o.AllowedEffects, keys)
	o.effect = eff
	*effect = eff
	return 0
}

func targetDragLeave(this uintptr) uintptr {
	o := lookupTarget(this)
	if o == nil {
		return eReverted
	}
	targets.Lock()
	prev := o.data
	o.data = 0
	o.entered = false
	o.effect = DropEffectNone
	targets.Unlock()
	if prev != 0 {
		invoke(prev, 2)
	}
	return 0
}

func targetDrop(this uintptr, data uintptr, keys uint32, pt uintptr, effect *uint32) uintptr {
	if effect == nil {
		return ePointer
	}
	o := lookupTarget(this)
	if o == nil || o.t.ctx.Err() != nil {
		*effect = DropEffectNone
		return eReverted
	}
	if data == 0 {
		*effect = DropEffectNone
		return ePointer
	}
	targets.Lock()
	prev := o.data
	o.data = 0
	o.entered = false
	eff := negotiateEffect(*effect, o.t.o.AllowedEffects, keys)
	o.effect = eff
	*effect = eff
	t := o.t
	targets.Unlock()
	if prev != 0 {
		invoke(prev, 2)
	}
	if eff == DropEffectNone {
		return 0
	}
	offer, err := acquireDrop(t.ctx, data, SourceOptions{MaxTotalSize: t.o.MaxTotalSize, MaxFiles: t.o.MaxFiles})
	if err != nil {
		t.report(err)
		*effect = DropEffectNone
		return 0
	}
	select {
	case t.drops <- Drop{Effect: eff, Source: offer}:
	default:
		offer.Release()
		t.report(fmt.Errorf("clipole: drop delivery queue is full"))
		*effect = DropEffectNone
	}
	return 0
}

// DropTarget is an OLE drop receiving endpoint registered against a window.
// Create it with NewDropTarget, Register it on a window whose thread pumps
// messages, and consume completed drops from Drops. Close revokes registration,
// cancels acquisition and releases the target's root reference; Done closes once
// OLE has released its last reference and native cleanup completes. Keep the
// registration window and its desktop alive until Done.
type DropTarget struct {
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	errors     chan error
	drops      chan Drop
	o          DropTargetOptions
	mu         sync.Mutex
	err        error
	obj        uintptr
	registered uintptr
	closed     bool
	finishOnce sync.Once
}

// NewDropTarget validates options and allocates the COM target object without
// registering it or creating an apartment. ctx bounds the target lifetime and
// each drop's acquisition. Other platforms return ErrUnsupported.
func NewDropTarget(ctx context.Context, o DropTargetOptions) (*DropTarget, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if o.AllowedEffects == 0 {
		o.AllowedEffects = DropEffectCopy
	}
	if o.AllowedEffects&^(DropEffectCopy|DropEffectMove|DropEffectLink) != 0 {
		return nil, ErrInvalid
	}
	if o.MaxFiles == 0 {
		o.MaxFiles = cliprdr.MaxFiles
	}
	if o.MaxFiles < 1 || o.MaxFiles > cliprdr.MaxFiles || o.MaxTotalSize > math.MaxInt64 {
		return nil, ErrInvalid
	}
	t := &DropTarget{o: o, done: make(chan struct{}), errors: make(chan error, 1), drops: make(chan Drop, 4)}
	t.ctx, t.cancel = context.WithCancel(ctx)
	t.obj = allocateTarget(t)
	if t.obj == 0 {
		t.cancel()
		return nil, hresult("drop target allocation", eMemory)
	}
	return t, nil
}

// Register attaches the target to hwnd via RegisterDragDrop. The window's thread
// must pump messages for OLE to deliver drag callbacks. Registering twice without
// an intervening Revoke returns ErrBusy.
func (t *DropTarget) Register(hwnd uintptr) error {
	if hwnd == 0 {
		return ErrInvalid
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return ErrChanged
	}
	if err := t.ctx.Err(); err != nil {
		return err
	}
	if t.registered != 0 {
		return ErrBusy
	}
	hr, _, _ := registerDragDrop.Call(hwnd, t.obj)
	if failed(hr) {
		return hresult("RegisterDragDrop", hr)
	}
	t.registered = hwnd
	return nil
}

// Revoke detaches the target from its window via RevokeDragDrop. It is a no-op
// when not registered. OLE releases its reference asynchronously afterwards.
func (t *DropTarget) Revoke() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.registered == 0 {
		return nil
	}
	hwnd := t.registered
	t.registered = 0
	hr, _, _ := revokeDragDrop.Call(hwnd)
	if failed(hr) {
		return hresult("RevokeDragDrop", hr)
	}
	return nil
}

// Close revokes registration, cancels acquisition and releases the root
// reference. Done waits for OLE's final release and native cleanup. Idempotent.
func (t *DropTarget) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	hwnd := t.registered
	t.registered = 0
	obj := t.obj
	t.mu.Unlock()
	if hwnd != 0 {
		revokeDragDrop.Call(hwnd)
	}
	t.cancel()
	targetRelease(obj)
}

func (t *DropTarget) Done() <-chan struct{} { return t.done }
func (t *DropTarget) Err() error            { t.mu.Lock(); defer t.mu.Unlock(); return t.err }
func (t *DropTarget) Errors() <-chan error  { return t.errors }

// Drops reports completed drops, bounded to four; when full a new drop's offer is
// released and an error is reported rather than blocking the OLE drag thread.
// The channel closes at Done. Each Drop.Source must be released exactly once.
func (t *DropTarget) Drops() <-chan Drop { return t.drops }

func (t *DropTarget) report(err error) {
	if err == nil {
		return
	}
	select {
	case t.errors <- err:
	default:
	}
}

func (t *DropTarget) finish() {
	t.finishOnce.Do(func() {
		t.cancel()
		close(t.errors)
		close(t.drops)
		close(t.done)
	})
}
