package main

import (
	"context"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"strconv"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/rail"
	"github.com/hq0101/rdp-go/remoteapp"
)

type appMoveStatus struct {
	Phase  string `json:"phase"`
	Token  string `json:"token"`
	Window uint32 `json:"window"`
	Type   uint16 `json:"type"`
}

func (a *viewerRemoteApp) moveStatus() appMoveStatus {
	s := a.moves.Status()
	out := appMoveStatus{Window: s.Window.ID, Type: s.Type}
	switch s.Phase {
	case remoteapp.MoveLocal:
		out.Phase, out.Token = "moving", strconv.FormatUint(s.Token, 10)
	case remoteapp.MoveAwaitEnd:
		out.Phase = "waiting"
	case remoteapp.MoveInvalidated:
		out.Phase = "invalidated"
	}
	return out
}

// inputMu then frameMu are held for every input/RAIL transition below. The
// canvas is the local window manager: it presents an outline while the remote
// application owns the final pixels/geometry. No OS windows are manipulated.
func (v *viewer) appMoveEventLocked(ctx context.Context, e rail.Event) error {
	a := v.app
	if _, err := a.moves.Sync(a.desktop); err != nil {
		return err
	}
	if e.Order == rail.OrderMinMaxInfo {
		_, err := a.moves.SetLimits(e.MinMax)
		return err
	}
	if !e.MoveSize.Start {
		before := a.moves.Status()
		_, _, err := a.moves.End(e.MoveSize)
		if err != nil {
			return err
		}
		if a.moves.Status().Phase == remoteapp.MoveIdle && before.Phase != remoteapp.MoveIdle {
			a.moveDeadline = time.Time{}
			v.dirty = true
			// An early server End also ends browser ownership. Release only input
			// this connection actually pressed; never replay local modal keys.
			return writeFailure(v.send(ctx, input{Kind: "release"}))
		}
		return nil
	}
	var target *remoteapp.View
	for _, view := range a.presented {
		if view.Identity().ID == e.MoveSize.WindowID && v.appCurrentLocked(view) {
			target = view
			break
		}
	}
	// Without a local presented window there is no local WM target. Keep normal
	// remote input forwarding, as with an unknown local window in MS-RDPERP.
	if target == nil {
		return nil
	}
	s, ok, err := a.moves.Begin(e.MoveSize)
	if err != nil || !ok {
		return err
	}
	a.moveStart = s
	a.movePointer = image.Pt(int(v.x), int(v.y)).Add(a.desktop.Min)
	a.moveButton = rdp.MouseLeft
	if len(v.buttons) == 1 {
		for button := range v.buttons {
			a.moveButton = button
		}
	}
	a.moveEdges = 0
	a.moveKeys = make(map[uint16]bool)
	for key := range v.keys {
		a.moveKeys[key] = true
	}
	a.moveTarget = target.Identity()
	a.selected = target
	a.selectedServerActive, _ = a.windows.ActiveWindow()
	v.dirty = true
	if s.Type == rail.MoveSizeMouse && (!s.StartPosition.In(image.Rectangle{Max: s.Outer.Size()}) || !s.Outer.Min.Add(s.StartPosition).In(a.desktop)) {
		return v.finishAppMoveLocked(ctx, true)
	}
	// A quick browser release may have reached the server before its Start.
	// Cancel instead of waiting for an up event that can no longer arrive.
	if s.Type <= rail.MoveSizeMouse && (len(v.buttons) != 1 || !v.buttons[a.moveButton]) {
		return v.finishAppMoveLocked(ctx, true)
	}
	return nil
}

func (v *viewer) syncAppMoveLocked(ctx context.Context) error {
	a := v.app
	invalid, err := a.moves.Sync(a.desktop)
	if err != nil {
		return err
	}
	if invalid || a.moves.Status().Phase == remoteapp.MoveInvalidated && a.moveDeadline.IsZero() {
		a.moveTarget = rail.WindowIdentity{}
		a.selected = nil
		a.moveDeadline = time.Now().Add(5 * time.Second)
		v.dirty = true
		if v.active {
			return writeFailure(v.send(ctx, input{Kind: "release"}))
		}
	}
	// Follow confirmed server geometry for the same window after completion.
	// The next input still requires the matching published frame revision.
	if !a.moves.SuppressInput() && a.moveTarget.Generation != 0 {
		w, ok := a.windows.Window(a.moveTarget.ID)
		id, known := a.windows.ActiveWindow()
		if !ok || w.Generation != a.moveTarget.Generation || known && id != a.selectedServerActive && id != w.ID {
			a.moveTarget = rail.WindowIdentity{}
		} else if a.selected != nil && !a.selected.Current(w) {
			mode := remoteapp.BasePresentation
			if a.client.Status().Enhanced {
				mode = remoteapp.EnhancedPresentation
			}
			if view, err := remoteapp.NewView(w, a.desktop, mode); err == nil && view.Shown() {
				a.selected = view
			}
			a.moveTarget = rail.WindowIdentity{}
		}
	}
	return nil
}

func (v *viewer) expireAppMoveLocked(now time.Time) bool {
	if v.app == nil || v.app.moveDeadline.IsZero() || now.Before(v.app.moveDeadline) {
		return false
	}
	v.stopWithReason("RemoteApp move completion timed out")
	return true
}

func (v *viewer) drawAppMoveLocked(out *image.RGBA) {
	s := v.app.moves.Status()
	if s.Phase != remoteapp.MoveLocal && s.Phase != remoteapp.MoveAwaitEnd {
		return
	}
	r := s.Outer.Sub(v.app.desktop.Min)
	c := color.RGBA{0, 210, 245, 255}
	if s.Phase == remoteapp.MoveAwaitEnd {
		c = color.RGBA{245, 190, 70, 255}
	}
	brush := image.NewUniform(c)
	for _, edge := range []image.Rectangle{
		image.Rect(r.Min.X, r.Min.Y, r.Max.X, r.Min.Y+2),
		image.Rect(r.Min.X, r.Max.Y-2, r.Max.X, r.Max.Y),
		image.Rect(r.Min.X, r.Min.Y, r.Min.X+2, r.Max.Y),
		image.Rect(r.Max.X-2, r.Min.Y, r.Max.X, r.Max.Y),
	} {
		draw.Draw(out, edge, brush, image.Point{}, draw.Src)
	}
}

func moveKey(e input) uint16 {
	k := uint16(e.Code)
	if e.Extended {
		k |= 0x100
	}
	return k
}

func (v *viewer) finishAppMoveLocked(ctx context.Context, cancel bool) error {
	a := v.app
	s := a.moves.Status()
	var plan remoteapp.MoveCompletion
	var err error
	if cancel {
		plan, err = a.moves.Cancel(s.Token, a.movePointer)
	} else {
		plan, err = a.moves.Finish(s.Token, s.Body, a.movePointer)
	}
	if err != nil {
		return err
	}
	a.moveDeadline = time.Now().Add(5 * time.Second)
	v.dirty = true
	if len(plan.WindowMove) != 0 {
		if err = v.sendRailLocked(ctx, plan.WindowMove); err != nil {
			return err
		}
	}
	for key := range v.keys {
		if err = v.send(ctx, input{Kind: "key", Code: int(key & 127), Extended: key&0x100 != 0}); err != nil {
			return writeFailure(err)
		}
	}
	if plan.Cancel {
		for _, down := range []bool{true, false} {
			if err = v.send(ctx, input{Kind: "key", Code: 1, Down: down}); err != nil {
				return writeFailure(err)
			}
		}
		a.moveTarget = rail.WindowIdentity{}
		a.selected = nil
	}
	// Release the actually tracked initiating button (including right/middle).
	// Keyboard operations with no pressed button use the protocol's up signal.
	if err = v.send(ctx, input{Kind: "button", Button: int(a.moveButton), X: plan.Pointer.X, Y: plan.Pointer.Y}); err != nil {
		return writeFailure(err)
	}
	return writeFailure(v.send(ctx, input{Kind: "release"}))
}

func (v *viewer) appMovePreviewLocked(body image.Rectangle) error {
	a := v.app
	s := a.moves.Status()
	if s.Type != rail.MoveSizeMouse && s.Type != rail.MoveSizeKeyMove {
		edges := appMoveEdges(s.Type)
		if s.Type == rail.MoveSizeKeySize {
			edges = a.moveEdges
		}
		margin := a.moveStart.Outer.Size().Sub(a.moveStart.Body.Size())
		lo, hi := image.Pt(1, 1), image.Pt(8192, 8192)
		if s.HasLimits {
			lo.X = max(lo.X, int(s.Limits.MinTrackWidth)-margin.X)
			lo.Y = max(lo.Y, int(s.Limits.MinTrackHeight)-margin.Y)
			if s.Limits.MaxTrackWidth > 0 {
				hi.X = min(hi.X, int(s.Limits.MaxTrackWidth)-margin.X)
			}
			if s.Limits.MaxTrackHeight > 0 {
				hi.Y = min(hi.Y, int(s.Limits.MaxTrackHeight)-margin.Y)
			}
		}
		if lo.X > hi.X || lo.Y > hi.Y {
			return remoteapp.ErrGeometry
		}
		width, height := max(lo.X, min(hi.X, body.Dx())), max(lo.Y, min(hi.Y, body.Dy()))
		if edges&1 != 0 {
			body.Min.X = body.Max.X - width
		} else {
			body.Max.X = body.Min.X + width
		}
		if edges&4 != 0 {
			body.Min.Y = body.Max.Y - height
		} else {
			body.Max.Y = body.Min.Y + height
		}
	}
	_, err := a.moves.Preview(s.Token, body)
	if errors.Is(err, remoteapp.ErrGeometry) {
		return nil
	} // retain last valid outline at a size limit
	if err == nil {
		v.dirty = true
	}
	return err
}

func appMoveEdges(typ uint16) byte {
	switch typ {
	case 1:
		return 1
	case 2:
		return 2
	case 3:
		return 4
	case 4:
		return 5
	case 5:
		return 6
	case 6:
		return 8
	case 7:
		return 9
	case 8:
		return 10
	}
	return 0
}

func appSizeDelta(r image.Rectangle, edges byte, delta image.Point) image.Rectangle {
	if edges&1 != 0 {
		r.Min.X += delta.X
	}
	if edges&2 != 0 {
		r.Max.X += delta.X
	}
	if edges&4 != 0 {
		r.Min.Y += delta.Y
	}
	if edges&8 != 0 {
		r.Max.Y += delta.Y
	}
	return r
}

func (v *viewer) appMovePointerLocked(p image.Point) error {
	a := v.app
	s := a.moves.Status()
	var body image.Rectangle
	switch s.Type {
	case rail.MoveSizeMouse:
		body = a.moveStart.Body.Add(p.Sub(a.moveStart.Outer.Min.Add(s.StartPosition)))
	case rail.MoveSizeKeyMove:
		body = s.Body.Add(p.Sub(a.movePointer))
	case rail.MoveSizeKeySize:
		body = appSizeDelta(s.Body, a.moveEdges, p.Sub(a.movePointer))
	default:
		body = appSizeDelta(a.moveStart.Body, appMoveEdges(s.Type), p.Sub(s.StartPosition))
	}
	a.movePointer = p
	v.x, v.y = uint16(p.X-a.desktop.Min.X), uint16(p.Y-a.desktop.Min.Y)
	return v.appMovePreviewLocked(body)
}

func (v *viewer) sendAppMoveInputLocked(ctx context.Context, e input) error {
	a := v.app
	s := a.moves.Status()
	if e.Kind == "release" {
		return v.finishAppMoveLocked(ctx, true)
	}
	if e.AppMove != strconv.FormatUint(s.Token, 10) {
		// Stale pre-Start motion/keys cannot move a new operation. A release
		// still cancels, so a quick click or missed status poll cannot stick it.
		if e.Kind == "button" && !e.Down && rdp.MouseButton(e.Button) == a.moveButton {
			return v.finishAppMoveLocked(ctx, true)
		}
		return nil
	}
	if e.Kind == "move" || e.Kind == "button" {
		if err := v.appMovePointerLocked(image.Pt(e.X, e.Y).Add(a.desktop.Min)); err != nil {
			return err
		}
		if e.Kind == "button" && !e.Down && rdp.MouseButton(e.Button) == a.moveButton {
			return v.finishAppMoveLocked(ctx, false)
		}
		return nil
	}
	if e.Kind != "key" {
		return nil
	}
	k := moveKey(e)
	if !e.Down {
		delete(a.moveKeys, k)
		return nil
	}
	a.moveKeys[k] = true
	if e.Code == 1 && !e.Extended {
		return v.finishAppMoveLocked(ctx, true)
	}
	if e.Code == 28 {
		return v.finishAppMoveLocked(ctx, false)
	}
	if !e.Extended {
		return nil
	}
	step := 8
	if a.moveKeys[29] || a.moveKeys[0x11d] {
		step = 1
	}
	var delta image.Point
	switch e.Code {
	case 75:
		delta.X = -step
	case 77:
		delta.X = step
	case 72:
		delta.Y = -step
	case 80:
		delta.Y = step
	default:
		return nil
	}
	body := s.Body
	if s.Type == rail.MoveSizeKeyMove {
		body = body.Add(delta)
	} else if s.Type == rail.MoveSizeMouse {
		// A mouse-driven move remains anchored to the actual pointer offset.
		return nil
	} else {
		edges := appMoveEdges(s.Type)
		if s.Type == rail.MoveSizeKeySize {
			if a.moveEdges&3 == 0 {
				if delta.X < 0 {
					a.moveEdges |= 1
				}
				if delta.X > 0 {
					a.moveEdges |= 2
				}
			}
			if a.moveEdges&12 == 0 {
				if delta.Y < 0 {
					a.moveEdges |= 4
				}
				if delta.Y > 0 {
					a.moveEdges |= 8
				}
			}
			edges = a.moveEdges
		}
		body = appSizeDelta(body, edges, delta)
	}
	return v.appMovePreviewLocked(body)
}
