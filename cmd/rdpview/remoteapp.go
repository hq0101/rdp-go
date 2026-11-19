package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/pdu"
	"github.com/hq0101/rdp-go/rail"
	"github.com/hq0101/rdp-go/remoteapp"
	"github.com/hq0101/rdp-go/vchan"
)

// frameMu protects the RAIL consumer, scene and presented geometry. The sole
// receive loop synchronizes Scene after RAIL/window/GFX changes; GFX writes are
// still protected by displayMu. HTTP never reads the mutable GFX consumer.
type viewerRemoteApp struct {
	balloons                remoteapp.BalloonTracker
	client                  *rail.Client
	windows                 *rail.WindowState
	scene                   remoteapp.Scene
	channel                 uint16
	decoder                 vchan.Decoder
	desktop                 image.Rectangle
	monitors                []image.Rectangle
	parametersDirty         bool
	parametersState         string
	preferences             appPreferences
	localFocus              bool
	focusEpoch, focusSerial uint64
	focusPending            bool
	moves                   *remoteapp.MoveController
	moveStart               remoteapp.MoveSnapshot
	movePointer             image.Point
	moveButton              rdp.MouseButton
	moveEdges               byte
	moveKeys                map[uint16]bool
	moveTarget              rail.WindowIdentity
	moveDeadline            time.Time
	request                 rail.ExecuteRequest
	autoLaunch              bool
	launch                  string
	result                  uint16
	rawResult               uint32
	presented               []*remoteapp.View // topmost first, from the last published PNG
	presentedToken          string
	selected                *remoteapp.View
	selectedServerActive    uint32
	pending                 int
	layoutRevision          uint64
	layoutMode              byte
	layoutDigest            string
}

type appWindowStatus struct {
	ID       uint32 `json:"id"`
	Lifetime string `json:"lifetime"`
	Title    string `json:"title"`
	Show     byte   `json:"show"`
	Cloaked  bool   `json:"cloaked"`
}
type appStatus struct {
	NotificationRevision string              `json:"notification_revision"`
	Cloaking             bool                `json:"cloaking"`
	Enabled              bool                `json:"enabled"`
	Ready                bool                `json:"ready"`
	Enhanced             bool                `json:"enhanced"`
	Launch               string              `json:"launch"`
	Result               uint16              `json:"result"`
	RawResult            uint32              `json:"raw_result"`
	Layout               string              `json:"layout"`
	Syncing              bool                `json:"syncing"`
	Pending              int                 `json:"pending"`
	SelectedLifetime     string              `json:"selected_lifetime"`
	Selected             uint32              `json:"selected"`
	Windows              []appWindowStatus   `json:"windows"`
	Parameters           string              `json:"parameters"` // sent is not a server acknowledgement
	Settings             rail.SettingsStatus `json:"settings"`
	FocusToken           string              `json:"focus_token"`
	LocalFocus           bool                `json:"local_focus"`
	Move                 appMoveStatus       `json:"move"`
}

func appWindowOptions(info rdp.SessionInfo) rail.WindowOptions {
	return rail.WindowOptions{Extended: info.RemoteApp.ExtendedWindows(), ResizeMargins: true, IconCaches: info.RemoteApp.IconCaches, IconEntries: info.RemoteApp.IconEntries}
}

func (v *viewer) initRemoteApp(info rdp.SessionInfo) error {
	if !info.RemoteApp.Enabled() {
		return nil
	}
	r, ok := v.remote.(channelRemote)
	if !ok {
		return errors.New("RemoteApp requires static channels")
	}
	id, ok := r.ChannelID("rail")
	if !ok {
		return errors.New("RemoteApp rail channel missing")
	}
	ws, err := rail.NewWindowState(appWindowOptions(info))
	if err != nil {
		return err
	}
	area := rail.Rectangle{Right: info.Width, Bottom: info.Height}
	c, err := rail.NewClient(rail.Options{Cloaking: info.RemoteApp.Cloaking(), BidirectionalCloak: true, HandshakeEx: info.RemoteApp.HandshakeEx(), Enhanced: info.RemoteAppEnhancedRequested, ResizeMargins: true, LocalMoveSize: true, ZOrderSync: true, Parameters: rail.SystemParameters{DragFullWindows: true, WorkArea: area, Display: area}})
	if err != nil {
		return err
	}
	v.app = &viewerRemoteApp{client: c, windows: ws, channel: id, decoder: vchan.Decoder{Limit: rail.MaxMessage}, desktop: image.Rect(0, 0, int(info.Width), int(info.Height)), launch: "waiting"}
	v.app.monitors = []image.Rectangle{v.app.desktop}
	v.app.moves, err = remoteapp.NewMoveController(c, ws, v.app.desktop)
	if err != nil {
		return err
	}
	v.app.parametersState = "waiting"
	v.frame.WindowState = ws
	if v.gfx != nil {
		v.gfx.WindowMapping = info.RemoteAppEnhancedRequested
	}
	return nil
}

// Called before receiving, including for a private reconnect candidate. A new
// connection never automatically replays a previously submitted Execute.
func (v *viewer) configureRemoteApp(request rail.ExecuteRequest, launch bool) error {
	if v.app == nil {
		return errors.New("RemoteApp was not negotiated")
	}
	if _, err := rail.EncodeExecute(request); err != nil {
		return err
	}
	v.app.request = request
	v.app.autoLaunch = launch
	return nil
}

func (v *viewer) appTokenLocked() string {
	a := v.app
	status := a.client.Status()
	mode := byte(0)
	if status.Ready {
		mode |= 1
	}
	if status.Enhanced {
		mode |= 2
	}
	if a.layoutDigest == "" || a.layoutRevision != a.windows.Revision() || a.layoutMode != mode {
		d := a.windows.Snapshot()
		hash := sha256.New()
		var encoded [8]byte
		put := func(value uint64) { binary.LittleEndian.PutUint64(encoded[:], value); hash.Write(encoded[:]) }
		put(uint64(mode))
		flags := uint64(0)
		if d.Monitored {
			flags |= 1
		}
		if d.Syncing {
			flags |= 2
		}
		if d.ZOrderKnown {
			flags |= 4
		}
		put(flags)
		if status.MarkerKnown {
			put(1)
			put(uint64(status.MarkerWindowID))
		} else {
			put(0)
		}
		put(uint64(len(d.ZOrder)))
		for _, id := range d.ZOrder {
			put(uint64(id))
		}
		mask := uint32(rail.FieldEnforceZOrder | rail.FieldShow | rail.FieldWindowOffset | rail.FieldWindowSize | rail.FieldWindowRects | rail.FieldResizeMarginX | rail.FieldResizeMarginY)
		if !status.Enhanced {
			mask |= rail.FieldVisibility
		}
		rects := func(rs []rail.Rectangle) {
			put(uint64(len(rs)))
			for _, r := range rs {
				put(uint64(r.Left))
				put(uint64(r.Top))
				put(uint64(r.Right))
				put(uint64(r.Bottom))
			}
		}
		put(uint64(len(d.Windows)))
		for _, w := range d.Windows {
			for _, n := range []uint64{uint64(w.ID), w.Generation, uint64(w.KnownFields & mask), uint64(uint32(w.X)), uint64(uint32(w.Y)), uint64(w.Width), uint64(w.Height), w.CloakSerial, uint64(w.ShowState), uint64(w.EnforceZOrder)} {
				put(n)
			}
			if w.KnownFields&rail.FieldResizeMarginX != 0 {
				put(uint64(w.MarginLeft))
				put(uint64(w.MarginRight))
			}
			if w.KnownFields&rail.FieldResizeMarginY != 0 {
				put(uint64(w.MarginTop))
				put(uint64(w.MarginBottom))
			}
			if w.KnownFields&rail.FieldWindowRects != 0 {
				rects(w.WindowRects)
			}
			if !status.Enhanced && w.KnownFields&rail.FieldVisibility != 0 {
				rects(w.VisibilityRects)
			}
		}
		a.layoutRevision = d.Revision
		a.layoutMode = mode
		a.layoutDigest = hex.EncodeToString(hash.Sum(nil))
	}
	return strconv.FormatUint(v.renderEpoch, 10) + ":" + a.layoutDigest
}
func (v *viewer) appStatusLocked() appStatus {
	if v.app == nil {
		return appStatus{}
	}
	a := v.app
	s := a.client.Status()
	d := a.windows.Snapshot()
	out := appStatus{Enabled: true, Ready: s.Ready && !s.Closed, Enhanced: s.Enhanced, Launch: a.launch, Result: a.result, RawResult: a.rawResult, Layout: a.presentedToken, Syncing: d.Syncing || !d.Monitored, Pending: a.pending}
	out.NotificationRevision = strconv.FormatUint(a.windows.NotificationRevision(), 10)
	out.Cloaking = s.Cloaking
	out.Parameters = a.parametersState
	out.Settings = a.client.SettingsStatus()
	out.Move = a.moveStatus()
	out.FocusToken, out.LocalFocus = v.appFocusTokenLocked(), a.localFocus
	if a.selected != nil {
		out.Selected = a.selected.Identity().ID
		out.SelectedLifetime = strconv.FormatUint(a.selected.Identity().Generation, 10)
	}
	for _, w := range d.Windows {
		if s.MarkerKnown && w.ID == s.MarkerWindowID {
			continue
		}
		out.Windows = append(out.Windows, appWindowStatus{w.ID, strconv.FormatUint(w.Generation, 10), w.Title, w.ShowState, w.Cloaked})
	}
	return out
}
func (v *viewer) syncAppSceneLocked() error {
	if v.app == nil {
		return nil
	}
	v.dirty = true
	v.pruneAppBalloonsLocked()
	if v.gfx == nil {
		return nil
	}
	return v.app.scene.Sync(v.app.client.Status(), v.app.windows, v.gfx)
}

func (v *viewer) sendRailLocked(ctx context.Context, b []byte) error {
	return writeFailure(v.remote.(channelRemote).WriteChannel(ctx, v.app.channel, b))
}
func (v *viewer) launchAppLocked(ctx context.Context) error {
	a := v.app
	if a.request.ExeOrFile == "" {
		return rail.ErrNotReady
	}
	b, err := a.client.Execute(a.request)
	if err != nil {
		return err
	}
	a.launch = "pending"
	a.result = 0
	a.rawResult = 0
	// A failed write is uncertain. Do not return to the launchable state.
	return v.sendRailLocked(ctx, b)
}
func (v *viewer) receiveRemoteApp(ctx context.Context, chunk []byte) error {
	v.inputMu.Lock()
	defer v.inputMu.Unlock()
	v.frameMu.Lock()
	defer v.frameMu.Unlock()
	a := v.app
	b, complete, err := a.decoder.Feed(chunk)
	if err != nil || !complete {
		return err
	}
	events, replies, err := a.client.Handle(b)
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for _, reply := range replies {
		if err = v.sendRailLocked(writeCtx, reply); err != nil {
			return err
		}
	}
	for _, event := range events {
		switch event.Order {
		case rail.OrderHandshake, rail.OrderHandshakeEx:
			a.launch = "ready"
			a.parametersState = "sent"
			if a.autoLaunch {
				a.autoLaunch = false
				if err = v.launchAppLocked(writeCtx); err != nil {
					return err
				}
			}
		case rail.OrderExecuteResult:
			a.result, a.rawResult = uint16(event.Execute.Code), event.Execute.RawResult
			a.launch = "failed"
			if event.Execute.Code == rail.ExecuteOK {
				a.launch = "launched"
			}
		case rail.OrderCloak:
			if _, err = a.windows.ApplyCloak(event.Cloak); err != nil {
				return err
			}
		case rail.OrderZOrderSync:
			a.layoutDigest = "" // marker IDs change rendering without a window revision
			a.focusPending = true
		case rail.OrderMinMaxInfo, rail.OrderLocalMoveSize:
			if err = v.appMoveEventLocked(writeCtx, event); err != nil {
				return err
			}
		}
	}
	return v.syncAppSceneLocked()
}

func (v *viewer) reconfigureAppLocked(info rdp.SessionInfo) error {
	if v.app == nil {
		return nil
	}
	if !info.RemoteApp.Enabled() {
		return pdu.ErrRemoteAppUnsupported
	}
	if err := v.app.client.ReconfigureCloaking(info.RemoteApp.Cloaking()); err != nil {
		return err
	}
	if err := v.app.windows.Reconfigure(appWindowOptions(info)); err != nil {
		return err
	}
	if v.app.desktop.Size() != image.Pt(int(info.Width), int(info.Height)) {
		if err := v.setAppDesktopLocked(image.Rect(0, 0, int(info.Width), int(info.Height))); err != nil {
			return err
		}
	}
	v.app.presented = nil
	v.app.presentedToken = ""
	v.app.selected = nil
	v.app.balloons.Reset()
	v.app.localFocus = false
	v.app.focusPending = false
	return v.syncAppSceneLocked()
}

// Basic Monitor Layout is delivered as a Data event. GFX uses its own confirmed
// RESET topology. These bounds are never taken from an unconfirmed UI request.
func (v *viewer) appBasicMonitorsLocked(payload []byte) error {
	monitors, err := pdu.ParseMonitorLayout(payload)
	if err != nil {
		return err
	}
	var rects []image.Rectangle
	for _, m := range monitors {
		rects = append(rects, image.Rect(int(m.Left), int(m.Top), int(m.Right)+1, int(m.Bottom)+1))
	}
	return v.setAppMonitorsLocked(rects)
}
func (v *viewer) appGraphicsMonitorsLocked() error {
	var rects []image.Rectangle
	for _, m := range v.gfx.Monitors() {
		rects = append(rects, image.Rect(int(m.Left), int(m.Top), int(m.Right)+1, int(m.Bottom)+1))
	}
	// Empty RESET topology represents this viewer's requested single monitor.
	if len(rects) == 0 {
		rects = []image.Rectangle{image.Rect(0, 0, v.width, v.height)}
	}
	return v.setAppMonitorsLocked(rects)
}
func (v *viewer) setAppDesktopLocked(bounds image.Rectangle) error {
	return v.setAppMonitorsLocked([]image.Rectangle{bounds})
}

type appRender struct {
	token   string
	views   []*remoteapp.View
	pending int
}

// Compose only server-ordered windows into the existing browser workspace.
// One completed image plus transient per-window images are retained. Sum of
// window rendering work is bounded to 64 Mi pixels per publication. Unknown
// geometry or ambiguous multi-surface mappings pause input, visibly reported.
func (v *viewer) renderAppLocked() (*image.RGBA, *appRender) {
	a := v.app
	d := a.windows.Snapshot()
	out := image.NewRGBA(image.Rect(0, 0, v.width, v.height))
	draw.Draw(out, out.Rect, image.NewUniform(color.RGBA{24, 29, 37, 255}), image.Point{}, draw.Src)
	result := &appRender{token: v.appTokenLocked()}
	if !a.client.Status().Ready || !d.Monitored || d.Syncing || !d.ZOrderKnown {
		result.pending = 1
		return out, result
	}
	mode := remoteapp.BasePresentation
	if a.client.Status().Enhanced {
		mode = remoteapp.EnhancedPresentation
	}
	windows := make(map[uint32]rail.Window, len(d.Windows))
	for _, w := range d.Windows {
		windows[w.ID] = w
	}
	bindings := make(map[uint32][]remoteapp.Binding)
	for _, b := range a.scene.Bindings() {
		bindings[b.Window.ID] = append(bindings[b.Window.ID], b)
	}
	var desktop *image.RGBA
	if mode == remoteapp.BasePresentation {
		desktop = v.frame.Snapshot()
	}
	stack, err := remoteapp.PlanStacking(a.client.Status(), d)
	if err != nil {
		result.pending = 1
		return out, result
	}
	var pixels int64
	views := make(map[uint32]*remoteapp.View)
	// Standard Windows Z-order is top to bottom; paint from back to front.
	for i := len(stack.Order) - 1; i >= 0; i-- {
		id := stack.Order[i]
		w, ok := windows[id]
		if !ok {
			result.pending++
			continue
		}
		if w.Cloaked || w.KnownFields&rail.FieldShow != 0 && (w.ShowState == 0 || w.ShowState == 2) {
			continue
		}
		view, err := remoteapp.NewView(w, a.desktop, mode)
		if err != nil {
			result.pending++
			continue
		}
		pixels += int64(w.Width) * int64(w.Height)
		if pixels > 64<<20 {
			result.pending++
			continue
		}
		var img *image.NRGBA
		if mode == remoteapp.BasePresentation {
			img, err = view.RenderBase(desktop)
		} else if len(bindings[id]) == 1 {
			b := bindings[id][0]
			img, err = view.RenderEnhanced(b, a.scene.Frame(b.Mapping.SurfaceID))
		} else {
			err = remoteapp.ErrIncomplete
		}
		if err != nil {
			result.pending++
			continue
		}
		draw.Draw(out, view.Bounds().Sub(a.desktop.Min), img, image.Point{}, draw.Over)
		views[id] = view
	}
	for _, id := range stack.Order {
		if view := views[id]; view != nil {
			result.views = append(result.views, view)
		}
	}
	v.drawAppMoveLocked(out)
	return out, result
}

func (v *viewer) appCurrentLocked(view *remoteapp.View) bool {
	if view == nil {
		return false
	}
	w, ok := v.app.windows.Window(view.Identity().ID)
	return ok && view.Current(w) && view.Desktop() == v.app.desktop && view.Shown()
}

// Called after receive locks are released, still inside connectionMu. Geometry,
// server activation and desktop synchronization changes release held input.
func (v *viewer) reconcileAppInput(ctx context.Context) error {
	if v.app == nil {
		return nil
	}
	v.inputMu.Lock()
	defer v.inputMu.Unlock()
	v.frameMu.Lock()
	defer v.frameMu.Unlock()
	a := v.app
	if err := v.syncAppMoveLocked(ctx); err != nil {
		return err
	}
	if err := v.syncAppFocusLocked(ctx); err != nil {
		return err
	}
	if a.selected == nil || !v.active {
		return nil
	}
	d := a.windows.Snapshot()
	activeChanged := d.ActiveKnown && d.ActiveWindowID != a.selectedServerActive
	if d.ActiveKnown {
		a.selectedServerActive = d.ActiveWindowID
	}
	if v.appCurrentLocked(a.selected) && d.Monitored && !d.Syncing && (!a.localFocus || !activeChanged || d.ActiveWindowID == a.selected.Identity().ID) {
		return nil
	}
	releaseCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := v.send(releaseCtx, input{Kind: "release"})
	a.selected = nil
	return writeFailure(err)
}

// inputMu and frameMu are held through validation, activation and the write.
// Mouse capture comes from successfully pressed server buttons, never a browser
// claim. Keyboard/text require a previously chosen, still-current window.
func (v *viewer) sendAppInputLocked(ctx context.Context, e input) error {
	a := v.app
	if e.Kind == "blur" {
		return v.blurAppLocked(ctx)
	}
	if a.moves.SuppressInput() {
		return v.sendAppMoveInputLocked(ctx, e)
	}
	if (e.Kind == "key" || e.Kind == "text" || e.Kind == "wheel") && e.AppFocus != v.appFocusTokenLocked() {
		return remoteapp.ErrStale
	}
	if e.Kind == "key" {
		key := moveKey(e)
		if !e.Down {
			delete(a.moveKeys, key)
			if !v.keys[key] {
				return nil
			}
		} else if a.moveKeys[key] {
			return nil
		}
	}
	if e.Kind == "key" && !a.localFocus {
		return remoteapp.ErrStale
	}
	if e.Kind == "button" && !e.Down && !v.buttons[rdp.MouseButton(e.Button)] {
		return nil
	}
	if e.Kind == "release" {
		clear(a.moveKeys)
		return v.send(ctx, e)
	}
	if !a.client.Status().Ready || a.pending != 0 || a.presentedToken != v.appTokenLocked() {
		return remoteapp.ErrStale
	}
	target := a.selected
	if e.Kind == "move" || e.Kind == "button" {
		if len(v.buttons) == 0 {
			target = nil
			point := image.Pt(e.X, e.Y).Add(a.desktop.Min)
			for _, view := range a.presented {
				if view.HitTest(point.Sub(view.Bounds().Min)) {
					target = view
					break
				}
			}
		}
		if target == nil && len(v.buttons) == 0 {
			if e.Kind == "button" && e.Down {
				return v.blurAppLocked(ctx)
			}
			return nil
		}
		if !v.appCurrentLocked(target) {
			return remoteapp.ErrOutside
		}
		current, _ := a.windows.Window(target.Identity().ID)
		point := image.Pt(e.X, e.Y).Add(a.desktop.Min).Sub(target.Bounds().Min)
		if _, err := target.Pointer(current, point, len(v.buttons) != 0); err != nil {
			return err
		}
		// Hover does not steal keyboard focus. A button press explicitly activates.
		if e.Kind == "button" && e.Down {
			if a.selected == nil || a.selected.Identity() != target.Identity() {
				if err := v.send(ctx, input{Kind: "release"}); err != nil {
					return err
				}
			}
			b, err := a.client.Activate(target.Identity().ID, true)
			if err != nil {
				return err
			}
			if err = v.sendRailLocked(ctx, b); err != nil {
				return err
			}
			a.localFocus = true
			a.focusPending = false
			a.selected = target
			a.moveTarget = rail.WindowIdentity{}
			a.selectedServerActive = a.windows.Snapshot().ActiveWindowID
		}
	} else if !v.appCurrentLocked(target) {
		return remoteapp.ErrStale
	}
	if e.Kind == "text" && !a.localFocus {
		return v.sendUnfocusedAppTextLocked(ctx, e)
	}
	return v.send(ctx, e)
}

func (v *viewer) serveRemoteApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		w.WriteHeader(415)
		return
	}
	var request struct {
		Action   string `json:"action"`
		Window   uint32 `json:"window"`
		Lifetime string `json:"lifetime"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		w.WriteHeader(400)
		return
	}
	v.inputMu.Lock()
	defer v.inputMu.Unlock()
	v.frameMu.Lock()
	defer v.frameMu.Unlock()
	a := v.app
	if a == nil || !v.active || r.Header.Get("X-RdpGo-Generation") != strconv.FormatUint(v.generation, 10) || !a.client.Status().Ready {
		w.WriteHeader(409)
		return
	}
	if a.moves.Status().Phase != remoteapp.MoveIdle {
		w.WriteHeader(409)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var err error
	if request.Action == "launch" {
		err = v.launchAppLocked(ctx)
	} else {
		if state := a.client.Status(); state.MarkerKnown && request.Window == state.MarkerWindowID {
			w.WriteHeader(409)
			return
		}
		window, ok := a.windows.Window(request.Window)
		if !ok || strconv.FormatUint(window.Generation, 10) != request.Lifetime {
			w.WriteHeader(409)
			return
		}
		commands := map[string]rail.SystemCommand{"minimize": rail.CommandMinimize, "maximize": rail.CommandMaximize, "restore": rail.CommandRestore, "close": rail.CommandClose, "move": rail.CommandMove, "size": rail.CommandSize}
		var b []byte
		if request.Action == "cloak" || request.Action == "uncloak" {
			err = v.setAppCloakLocked(ctx, window, request.Action == "cloak")
		} else if window.Cloaked && request.Action != "close" {
			w.WriteHeader(409)
			return
		} else if request.Action == "activate" || request.Action == "move" || request.Action == "size" {
			var view *remoteapp.View
			for _, p := range a.presented {
				if p.Identity().ID == request.Window && v.appCurrentLocked(p) {
					view = p
					break
				}
			}
			if view == nil || a.pending != 0 || a.presentedToken != v.appTokenLocked() {
				w.WriteHeader(409)
				return
			}
			b, err = a.client.Activate(request.Window, true)
			if err == nil {
				err = v.send(ctx, input{Kind: "release"})
			}
			if err == nil {
				err = v.sendRailLocked(ctx, b)
			}
			if err == nil {
				a.localFocus = true
				a.focusPending = false
				a.selected = view
				a.moveTarget = rail.WindowIdentity{}
				a.selectedServerActive = a.windows.Snapshot().ActiveWindowID
			}
			if err == nil && request.Action != "activate" {
				b, err = a.client.SystemCommand(request.Window, commands[request.Action])
				if err == nil {
					err = v.sendRailLocked(ctx, b)
				}
			}
		} else if command, ok := commands[request.Action]; ok {
			b, err = a.client.SystemCommand(request.Window, command)
			if err == nil {
				err = v.send(ctx, input{Kind: "release"})
			}
			if err == nil {
				err = v.sendRailLocked(ctx, b)
			}
		} else {
			w.WriteHeader(400)
			return
		}
	}
	if err != nil {
		var failure *protocolWriteError
		if errors.As(err, &failure) {
			v.stopWithReason("RemoteApp write failed")
			w.WriteHeader(502)
		} else {
			w.WriteHeader(409)
		}
		return
	}
	w.WriteHeader(204)
}

func (v *viewer) serveAppInputLocked(w http.ResponseWriter, r *http.Request, events []input) {
	onlyRelease := true
	for _, event := range events {
		if err := v.validate(event); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		onlyRelease = onlyRelease && (event.Kind == "release" || event.Kind == "blur")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := v.syncAppMoveLocked(ctx); err != nil {
		v.writeInterrupted("RemoteApp move synchronization failed")
		w.WriteHeader(502)
		return
	}
	if !onlyRelease && (r.Header.Get("X-RdpGo-App-Revision") != v.app.presentedToken || v.app.presentedToken != v.appTokenLocked()) {
		if err := v.sendAppInputLocked(ctx, input{Kind: "release"}); err != nil {
			v.writeInterrupted("RemoteApp release failed")
			w.WriteHeader(502)
			return
		}
		v.app.selected = nil
		http.Error(w, "window layout changed; refresh image", 409)
		return
	}
	for index, event := range events {
		if err := v.sendAppInputLocked(ctx, event); err != nil {
			if errors.Is(err, remoteapp.ErrStale) || errors.Is(err, remoteapp.ErrOutside) || errors.Is(err, remoteapp.ErrHidden) {
				if index > 0 {
					w.Header().Set("X-RdpGo-Input-Partial", "1")
				}
				http.Error(w, "choose a current remote window", 409)
			} else if errors.Is(err, rdp.ErrUnsupportedOperation) {
				w.WriteHeader(422)
			} else {
				v.writeInterrupted("RemoteApp input failed")
				w.WriteHeader(502)
			}
			return
		}
	}
	w.WriteHeader(204)
}
