package nativeview

import (
	"context"
	"errors"
	"image"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/hq0101/rdp-go/graphics"
	"github.com/hq0101/rdp-go/ime"
)

var nativeClass struct {
	sync.Once
	err      error
	name     []uint16
	instance uintptr
}
var nativeWindows = struct {
	sync.RWMutex
	values map[uintptr]*desktopWindow
}{values: make(map[uintptr]*desktopWindow)}

type ownedRemote struct {
	Remote
	once sync.Once
	err  error
}

func (r *ownedRemote) Close() error { r.once.Do(func() { r.err = r.Remote.Close() }); return r.err }

type desktopWindow struct {
	hwnd, font                           uintptr
	ctx                                  context.Context
	remote                               Remote
	adapter                              *ime.WindowsAdapter
	input                                *ime.WindowsInput
	dispatcher                           *ime.InputDispatcher
	focus                                ime.TextFocus
	loop                                 *inputLoop
	packet                               *packetTranslation
	packetSequence                       uintptr
	pointer                              *pointerWriter
	keyCleanup                           *ime.DeliveryReceipt
	pointerCleanup                       completion
	mailbox                              desktopMailbox
	desktop                              *desktopUpdate
	rasterSource                         *desktopUpdate
	rasterPoint                          image.Point
	rasterPixels                         []byte
	presentation                         ime.TextPresentation
	candidates                           []ime.CandidateList
	buttons                              []candidateButton
	nativeUI                             *candidateInput
	closing, blurRequested, captured     bool
	pressed                              [3]bool
	lastPointer                          image.Point
	pointerSerial                        uint64
	serverPointer                        *image.Point
	warpedClient                         *image.Point
	awaitActivation                      bool
	client                               image.Rectangle
	textY, rowHeight                     int32
	fontDPI                              uint32
	dpiRect                              *winRect
	fullscreen                           fullscreenState
	shortcut                             fullscreenShortcut
	toggleFullscreen, refitFullscreen    bool
	fullscreenPressed                    bool
	dynamicResolution, sizing, minimized bool
	status                               string
	err                                  error
	lastPaint                            time.Time
	barrier                              chan struct{}
}

// Run creates a Windows desktop window on a dedicated locked UI thread. It
// presents one existing desktop session, local TSF preedit and candidate UI.
// Closing/defocusing retires queued input and releases held keys/buttons to the
// original connection. Run does not reconnect, launch RemoteApps, redirect
// devices. DynamicResolution optionally requests remote resolution changes.
// Non-Windows platforms return ErrUnsupported without closing remote.
func Run(ctx context.Context, remote Remote, options Options) error {
	if ctx == nil || remote == nil {
		return ErrInvalid
	}
	o, err := normalize(options)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	info := remote.Info()
	if info.RemoteApp.Enabled() || !info.UnicodeInput {
		return ErrUnsupported
	}
	if info.Width == 0 || info.Height == 0 {
		return ErrInvalid
	}
	if o.DynamicResolution && !remote.DynamicInfo().Managed {
		return errors.New("nativeview: dynamic resolution requires managed dynamic channels")
	}
	channel, id, err := clipboardTransport(remote, o)
	if err != nil {
		return err
	}
	var clipboard *clipboardRemote
	if channel != nil {
		clipboard, err = openClipboardRemote(ctx, remote, channel, id, o)
		if err != nil {
			remote.Close()
			return err
		}
		remote = clipboard
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		result <- runWindow(ctx, &ownedRemote{Remote: remote}, o)
	}()
	err = <-result
	if clipboard != nil {
		clipboard.Close()
		err = errors.Join(err, clipboard.wait())
	}
	return err
}

func runWindow(ctx context.Context, remote Remote, o Options) (err error) {
	defer remote.Close()
	// Per-thread DPI awareness avoids changing a host application's process-wide
	// policy. Restore the exact prior context before returning this UI thread.
	if err = setThreadDPI.Find(); err != nil {
		return err
	}
	previous, _, e := setThreadDPI.Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
	if previous == 0 {
		return nativeError("SetThreadDpiAwarenessContext", e)
	}
	defer setThreadDPI.Call(previous)
	w := &desktopWindow{ctx: ctx, remote: remote, status: "Waiting for desktop", dynamicResolution: o.DynamicResolution}
	if err = w.create(o); err != nil {
		return err
	}
	defer w.destroy()
	if w.adapter, err = ime.OpenWindowsWithOptions(w.hwnd, ime.WindowsOptions{StateBackend: ime.WindowsTSF, UIElementOnly: o.LocalCandidateUI}); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, w.adapter.Close()) }()
	if w.dispatcher, err = ime.NewInputDispatcher(remote.SendText, remote.SendKeys, ime.DispatchOptions{}); err != nil {
		return err
	}
	defer func() {
		if w.dispatcher != nil {
			w.dispatcher.Close()
			<-w.dispatcher.Done()
		}
	}()
	if w.input, err = w.adapter.OpenAsyncTextInput(ime.WindowsInputOptions{}, w.dispatcher); err != nil {
		return err
	}
	defer func() {
		if w.input != nil {
			err = errors.Join(err, w.input.Close())
		}
	}()
	defer func() {
		// Exceptional message-loop exits still join pointer workers. Close is
		// required to unblock every Remote call before this final join.
		if w.pointer != nil {
			w.pointerCleanup = w.pointer.retire()
			w.pointer = nil
		}
		if w.pointerCleanup != nil {
			remote.Close()
			for {
				done, _ := w.pointerCleanup()
				if done {
					break
				}
				time.Sleep(time.Millisecond)
			}
		}
	}()
	readerCtx, stopReader := context.WithCancel(context.Background())
	readerDone := make(chan error, 1)
	go func() { readerDone <- receiveDesktop(readerCtx, remote, o, &w.mailbox) }()
	defer func() { stopReader(); remote.Close(); <-readerDone }()
	if timer, _, e := setTimer.Call(w.hwnd, 1, 16, 0); timer == 0 {
		return nativeError("SetTimer", e)
	}
	defer killTimer.Call(w.hwnd, 1)
	showWindow.Call(w.hwnd, 1)
	if o.Fullscreen {
		w.toggleFullscreen = true
		if err = w.applyWindowMode(); err != nil {
			return err
		}
	}
	updateWindow.Call(w.hwnd)
	readerFinished := false
	for {
		if ctx.Err() != nil {
			w.closing = true
		}
		if !readerFinished {
			select {
			case readErr := <-readerDone:
				readerFinished = true
				// Keep one terminal result for the deferred join, without replaying a
				// completed receiver or leaving a live handle unobserved.
				readerDone <- readErr
				if !w.closing {
					w.err = errors.Join(w.err, readErr)
					w.closing = true
				}
			default:
			}
		}
		if err = w.step(); err != nil {
			w.err = errors.Join(w.err, err)
			w.closing = true
		}
		if w.closing && w.loop == nil && w.keyCleanup == nil && w.pointerCleanup == nil {
			stopReader()
			if !readerFinished {
				remote.Close()
			}
			return errors.Join(w.err, ctx.Err())
		}
		m, found, messageErr := w.nextMessage()
		if messageErr != nil {
			w.err = errors.Join(w.err, messageErr)
			w.closing = true
			w.retire()
			return w.err
		}
		if !found {
			continue
		}
		if m.Message == 0x12 {
			w.closing = true
			continue
		}
		if m.HWND == w.hwnd {
			if w.packetCharacter(m) {
				continue
			}
			if key, isKey := m.KeyMessage(); isKey {
				if !w.closing && !w.blurRequested && m.KeyboardValid {
					if consume, toggle := w.shortcut.key(key, m.Keyboard); consume {
						if toggle {
							w.toggleFullscreen = !w.toggleFullscreen
						}
						continue
					}
				}
				if w.loop != nil && !w.closing && !w.blurRequested && m.KeyboardValid {
					if key.WParam == 0xe7 {
						message := m
						w.enqueue(inputItem{key: key, state: m.Keyboard, packet: &message})
					} else if _, decodeErr := ime.DecodeWindowsKey(key); decodeErr == nil {
						w.enqueue(inputItem{key: key, state: m.Keyboard})
					}
				}
				// Ordinary keys go to RDP after TSF filtering. Translating them
				// here would inject a duplicate local WM_CHAR stream.
				continue
			}
			if m.Message == 0x51 {
				_ = w.adapter.NotifyMessage(m.Message, m.WParam)
			}
		}
		raw := winMessage{HWND: m.HWND, Message: m.Message, WParam: m.WParam, LParam: m.LParam, Time: m.Time, Point: winPoint{m.X, m.Y}, Private: m.Private}
		translateMessage.Call(uintptr(unsafe.Pointer(&raw)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&raw)))
	}
}

func (w *desktopWindow) create(o Options) error {
	nativeClass.Do(func() {
		nativeClass.name, _ = wstr("rdp-go.NativeDesktop.v1")
		nativeClass.instance, _, _ = moduleHandle.Call(0)
		cursor, _, _ := loadCursor.Call(0, 32512)
		class := winClass{Size: uint32(unsafe.Sizeof(winClass{})), Style: 3, Proc: syscall.NewCallback(windowProcedure), Instance: nativeClass.instance, Cursor: cursor, Background: 6, Name: uintptr(unsafe.Pointer(&nativeClass.name[0]))}
		if atom, _, e := registerClass.Call(uintptr(unsafe.Pointer(&class))); atom == 0 {
			nativeClass.err = nativeError("RegisterClassEx", e)
		}
	})
	if nativeClass.err != nil {
		return nativeClass.err
	}
	title, err := wstr(o.Title)
	if err != nil {
		return err
	}
	hwnd, _, e := createWindow.Call(0, uintptr(unsafe.Pointer(&nativeClass.name[0])), uintptr(unsafe.Pointer(&title[0])), 0x00cf0000, 0x80000000, 0x80000000, uintptr(o.Width), uintptr(o.Height), 0, 0, nativeClass.instance, 0)
	if hwnd == 0 {
		return nativeError("CreateWindowEx", e)
	}
	w.hwnd = hwnd
	nativeWindows.Lock()
	nativeWindows.values[hwnd] = w
	nativeWindows.Unlock()
	return nil
}
func (w *desktopWindow) destroy() {
	if w.hwnd != 0 {
		w.captured = false
		releaseCapture.Call()
		destroyWindow.Call(w.hwnd)
		nativeWindows.Lock()
		delete(nativeWindows.values, w.hwnd)
		nativeWindows.Unlock()
		w.hwnd = 0
	}
	if w.font != 0 {
		deleteObject.Call(w.font)
		w.font = 0
	}
}
func windowProcedure(hwnd uintptr, message uint32, wp, lp uintptr) uintptr {
	nativeWindows.RLock()
	w := nativeWindows.values[hwnd]
	nativeWindows.RUnlock()
	if w == nil {
		v, _, _ := defWindow.Call(hwnd, uintptr(message), wp, lp)
		return v
	}
	switch message {
	case packetBeginMarker:
		if w.packet != nil && w.packet.sequence == wp {
			w.packet.started = true
		}
		return 0
	case packetMarker:
		if w.packet != nil && w.packet.sequence == wp {
			w.packet.done = true
			w.packet = nil
		}
		return 0
	case 0x102, 0x106, 0x109:
		return w.character(message, wp, lp)
	case 0x286: // TSF owns committed text; suppress legacy WM_IME_CHAR duplication.
		return 0
	case 0x10:
		w.closing = true
		return 0 // WM_CLOSE; teardown outside callbacks
	case 2:
		w.closing = true
		return 0
	case 8:
		w.blurRequested = true
	case 0x1c:
		if wp == 0 {
			w.blurRequested = true
		}
	case 0x215:
		if w.captured && lp != hwnd {
			w.captured = false
			w.fullscreenPressed = false
			w.blurRequested = true
		}
	case 0x7e: // WM_DISPLAYCHANGE: refit after a monitor topology change.
		w.refitFullscreen = true
	case 5: // WM_SIZE
		w.minimized = wp == 1
	case 0x231: // WM_ENTERSIZEMOVE
		w.sizing = true
		if w.dynamicResolution {
			w.mailbox.requestDisplay(image.Point{}, time.Now())
		}
	case 0x232: // WM_EXITSIZEMOVE
		w.sizing = false
	case 0x2e0:
		if lp != 0 {
			var r winRect
			copyNative.Call(uintptr(unsafe.Pointer(&r)), lp, unsafe.Sizeof(r))
			w.dpiRect = &r
		}
		return 0
	case 0x14:
		return 1
	case 0x20: // WM_SETCURSOR: software AND/XOR/alpha cursors inside the desktop.
		if uint16(lp) == 1 && w.loop != nil && w.desktop != nil && w.desktop.pointer.Kind != graphics.PointerDefault {
			var p winPoint
			getCursorPos.Call(uintptr(unsafe.Pointer(&p)))
			screenToClient.Call(hwnd, uintptr(unsafe.Pointer(&p)))
			if image.Pt(int(p.X), int(p.Y)).In(w.desktopViewport()) {
				setCursor.Call(0)
				return 1
			}
		}
	case 0x0f:
		var ps winPaint
		dc, _, _ := beginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		if dc != 0 {
			if err := w.paint(dc); err != nil {
				w.err = errors.Join(w.err, err)
				w.closing = true
			}
			endPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		}
		return 0
	case 0x200, 0x201, 0x202, 0x204, 0x205, 0x207, 0x208, 0x20a:
		w.mouse(message, wp, lp)
		return 0
	}
	v, _, _ := defWindow.Call(hwnd, uintptr(message), wp, lp)
	return v
}

func (w *desktopWindow) enqueue(item inputItem) {
	if w.loop == nil || w.closing || w.blurRequested {
		return
	}
	if err := w.loop.enqueue(item); err != nil {
		w.err = err
		w.closing = true
	}
}
func (w *desktopWindow) retire() {
	if w.packet != nil {
		w.packet.canceled = true
		w.packet.characters = nil
	}
	if w.loop != nil {
		w.loop = nil
		r, err := w.input.BlurAsync(w.focus)
		if errors.Is(err, ime.ErrStale) {
			r, err = w.input.Cleanup(context.Background())
		}
		if err != nil {
			w.err = errors.Join(w.err, err)
			w.closing = true
		}
		w.keyCleanup = r
		if w.pointer != nil {
			w.pointerCleanup = w.pointer.retire()
			w.pointer = nil
		}
	}
	w.pressed = [3]bool{}
	w.fullscreenPressed = false
	w.shortcut = fullscreenShortcut{}
	w.captured = false
	releaseCapture.Call()
	w.presentation = ime.TextPresentation{}
	w.candidates = nil
	w.buttons = nil
	w.nativeUI = nil
	w.warpedClient = nil
	w.blurRequested = false
}
func (w *desktopWindow) step() error {
	if w.err != nil {
		w.closing = true
	}
	if update := w.mailbox.take(); update != nil {
		if update.retire != nil && update.display.phase == displayPreparing {
			suspended, err := w.displaySuspended()
			if err != nil {
				return err
			}
			if suspended {
				// Cancel this not-yet-sent plan without retiring active text.
				w.mailbox.requestDisplay(image.Point{}, time.Now())
				close(update.retire)
				update.retire = nil
				update.display.phase = displayIdle
			}
		}
		if point, changed := consumePointerPosition(update, &w.pointerSerial); changed {
			w.lastPointer = point
			w.serverPointer = &point
		}
		if update.retire != nil {
			w.barrier = update.retire
			update.retire = nil
			w.blurRequested = true
		}
		if w.desktop != nil && w.desktop.generation != update.generation {
			w.blurRequested = true
		}
		w.desktop = update
	}
	foreground, _, _ := getForeground.Call()
	focused, _, _ := getFocus.Call()
	wants := foreground == w.hwnd && focused == w.hwnd && !w.closing && !w.awaitActivation && w.barrier == nil && w.desktop != nil && w.desktop.ready && w.desktop.info.Active && w.desktop.info.UnicodeInput && !w.desktop.display.busy()
	if w.loop != nil && !wants || w.blurRequested {
		w.retire()
	}
	if w.keyCleanup != nil {
		result, done := w.keyCleanup.Result()
		if done {
			w.keyCleanup = nil
			if result.Err != nil && !((w.barrier != nil || w.awaitActivation) && onlyDeactivated(result.Err)) {
				return result.Err
			}
		}
	}
	if w.pointerCleanup != nil {
		done, err := w.pointerCleanup()
		if done {
			w.pointerCleanup = nil
			if err != nil && !((w.barrier != nil || w.awaitActivation) && onlyDeactivated(err)) {
				return err
			}
		}
	}
	if w.closing {
		return nil
	}
	if w.barrier != nil && w.loop == nil && w.keyCleanup == nil && w.pointerCleanup == nil {
		if w.input != nil {
			if err := w.input.Close(); err != nil {
				return err
			}
			w.input = nil
			w.dispatcher.Close()
		}
		select {
		case <-w.dispatcher.Done():
		default:
			return nil
		}
		var err error
		w.dispatcher, err = ime.NewInputDispatcher(w.remote.SendText, w.remote.SendKeys, ime.DispatchOptions{})
		if err != nil {
			return err
		}
		w.input, err = w.adapter.OpenAsyncTextInput(ime.WindowsInputOptions{}, w.dispatcher)
		if err != nil {
			return err
		}
		close(w.barrier)
		w.barrier = nil
		w.awaitActivation = false
	}
	if err := w.applyWindowMode(); err != nil {
		return err
	}
	if err := w.geometry(); err != nil {
		return err
	}
	if w.dynamicResolution {
		// Composition and held input are allowed to finish before an automatic
		// resize retires the input context. Candidate panel growth is not a new
		// target, and interactive move/resize never floods the control channel.
		suspended, err := w.displaySuspended()
		if err != nil {
			return err
		}
		w.mailbox.requestDisplay(displayTarget(w.client, w.rowHeight, suspended), time.Now())
	}
	if w.serverPointer != nil {
		point := *w.serverPointer
		w.serverPointer = nil // never replay an old request on a later refocus
		if wants && !w.blurRequested {
			if err := w.positionCursor(point); err != nil {
				return err
			}
		}
	}
	if wants && w.loop == nil && w.keyCleanup == nil && w.pointerCleanup == nil && w.packet == nil {
		token, err := w.input.Focus()
		if busy(err) || errors.Is(err, ime.ErrNotFocused) {
			return nil
		}
		if err != nil {
			return err
		}
		w.focus = token
		w.blurRequested = false
		w.pointer = &pointerWriter{remote: w.remote}
		w.loop = &inputLoop{host: w.input, token: token, sendMouse: w.pointer.submit, translatePacket: w.translatePacket}
		var state ime.WindowsKeyboardState
		ok, _, e := getKeyboardState.Call(uintptr(unsafe.Pointer(&state[0])))
		if ok == 0 {
			return nativeError("GetKeyboardState", e)
		}
		var toggles uint32
		for j, key := range []int{0x91, 0x90, 0x14, 0x15} {
			if state[key]&1 != 0 {
				toggles |= 1 << j
			}
		}
		job, err := w.pointer.submit(w.ctx, mouseAction{kind: mouseSync, toggles: toggles})
		if err != nil {
			return err
		}
		w.loop.pending = job
	}
	if w.loop != nil {
		if w.nativeUI != nil && len(w.loop.queue) == 0 && w.loop.pending == nil {
			request := *w.nativeUI
			w.nativeUI = nil
			_, err := w.input.ApplyCandidate(w.focus, request.token, request.action)
			if err != nil && !busy(err) && !errors.Is(err, ime.ErrChanged) && !errors.Is(err, ime.ErrStale) {
				return err
			}
		}
		if err := w.loop.advance(w.ctx); err != nil {
			if errors.Is(err, errCharacterInput) {
				w.status = "Invalid Unicode input discarded; focus reset"
				w.retire()
				return nil
			}
			if onlyDeactivated(err) {
				w.awaitActivation = true
				w.status = "Waiting for desktop reactivation"
				w.retire()
				return nil
			}
			if errors.Is(err, errCompositionClick) {
				w.status = "Composition canceled; click the desktop again"
				w.retire()
				return nil
			}
			if errors.Is(err, ime.ErrNotFocused) || errors.Is(err, ime.ErrStale) {
				w.retire()
				return nil
			}
			return err
		}
		if time.Since(w.lastPaint) >= 16*time.Millisecond {
			if err := w.sampleText(); err != nil {
				if errors.Is(err, ime.ErrNotFocused) || errors.Is(err, ime.ErrStale) {
					w.retire()
					return nil
				}
				if busy(err) || errors.Is(err, ime.ErrChanged) {
					return nil
				}
				return err
			}
		}
	}
	if time.Since(w.lastPaint) >= 16*time.Millisecond {
		invalidateRect.Call(w.hwnd, 0, 0)
		w.lastPaint = time.Now()
	}
	return nil
}
