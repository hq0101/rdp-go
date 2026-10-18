package remoteapp

import (
	"errors"
	"image"
	"slices"

	"github.com/hq0101/rdp-go/rail"
)

var ErrGeometry = errors.New("remoteapp: invalid or mismatched window geometry")
var ErrIncomplete = errors.New("remoteapp: window presentation metadata is incomplete")
var ErrHidden = errors.New("remoteapp: window is hidden, minimized or cloaked")
var ErrStale = errors.New("remoteapp: window identity or presentation geometry changed")
var ErrOutside = errors.New("remoteapp: pointer outside the window or desktop")
var ErrRenderLimit = errors.New("remoteapp: presentation resource limit exceeded")

type PresentationMode uint8

const (
	BasePresentation PresentationMode = iota
	EnhancedPresentation
)

const maxViewDimension = 8192
const maxViewPixels = 16 << 20
const maxRegionRects = 16384
const maxRegionWork = 64 << 20

// View is an immutable, connection-local window geometry snapshot, constructed
// with NewView. Methods may run concurrently. It contains no pixels, OS handles,
// transport or goroutines. A new View is required when presentation geometry
// changes. Identity and geometry are rechecked by Pointer against current state.
type View struct {
	window                       rail.Window
	mode                         PresentationMode
	bounds, desktop, interactive image.Rectangle
	shape, visibility            []image.Rectangle
	shown                        bool
}

// NewView uses actual desktop bounds relative to the primary monitor, from the
// accepted monitor topology; do not pass requested/unconfirmed monitor bounds.
// For one monitor this is (0,0,width,height). Window offsets are primary-relative;
// RDP pointer positions and the desktop framebuffer are desktop-origin-relative.
//
// Offset, size and ShowState must have arrived; base mode also needs visibility.
// Absent window shape means rectangular. An explicitly empty shape/visibility
// has no pixels. Region coordinates are window-relative; VisibleX/Y describe a
// bounding rectangle, not an additional translation of these coordinates.
// Right/bottom region edges use the Windows RECT exclusive-edge convention;
// MS-RDPERP itself does not specify edge inclusion, so real RDS remains to verify.
// Enhanced ignores server occlusion visibility but still applies window shape.
// Hidden/minimized windows produce a valid View but cannot render or receive input.
func NewView(w rail.Window, desktop image.Rectangle, mode PresentationMode) (*View, error) {
	if mode != BasePresentation && mode != EnhancedPresentation {
		return nil, ErrMode
	}
	if w.Generation == 0 {
		return nil, ErrState
	}
	required := uint32(rail.FieldWindowOffset | rail.FieldWindowSize | rail.FieldShow)
	if mode == BasePresentation {
		required |= rail.FieldVisibility
	}
	if w.KnownFields&required != required {
		return nil, ErrIncomplete
	}
	if desktop.Min.X > 0 || desktop.Min.Y > 0 || desktop.Max.X <= 0 || desktop.Max.Y <= 0 || desktop.Min.X < -maxViewDimension || desktop.Min.Y < -maxViewDimension || desktop.Max.X > maxViewDimension || desktop.Max.Y > maxViewDimension || !viewSize(desktop.Dx(), desktop.Dy()) {
		return nil, ErrGeometry
	}
	if !viewSize64(int64(w.Width), int64(w.Height)) {
		return nil, ErrGeometry
	}
	right, bottom := int64(w.X)+int64(w.Width), int64(w.Y)+int64(w.Height)
	if right > 1<<31-1 || bottom > 1<<31-1 {
		return nil, ErrGeometry
	}
	if w.ShowState != 0 && w.ShowState != 2 && w.ShowState != 3 && w.ShowState != 5 {
		return nil, ErrGeometry
	}
	v := &View{mode: mode, desktop: desktop, bounds: image.Rect(int(w.X), int(w.Y), int(right), int(bottom)), shown: !w.Cloaked && (w.ShowState == 3 || w.ShowState == 5)}
	var ml, mr, mt, mb int64
	if w.KnownFields&rail.FieldResizeMarginX != 0 {
		ml, mr = int64(w.MarginLeft), int64(w.MarginRight)
	}
	if w.KnownFields&rail.FieldResizeMarginY != 0 {
		mt, mb = int64(w.MarginTop), int64(w.MarginBottom)
	}
	if ml > maxViewDimension || mr > maxViewDimension || mt > maxViewDimension || mb > maxViewDimension || int64(w.X)-ml < -1<<31 || int64(w.Y)-mt < -1<<31 || right+mr > 1<<31-1 || bottom+mb > 1<<31-1 {
		return nil, ErrGeometry
	}
	v.interactive = image.Rect(-int(ml), -int(mt), int(w.Width)+int(mr), int(w.Height)+int(mb))
	if len(w.WindowRects) > maxRegionRects || len(w.VisibilityRects) > maxRegionRects {
		return nil, ErrRenderLimit
	}
	local := image.Rectangle{Max: v.bounds.Size()}
	work := int64(0)
	regions := func(rects []rail.Rectangle) ([]image.Rectangle, error) {
		out := make([]image.Rectangle, 0, len(rects))
		for _, r := range rects {
			if r.Left > r.Right || r.Top > r.Bottom {
				return nil, ErrGeometry
			}
			q := image.Rect(int(r.Left), int(r.Top), int(r.Right), int(r.Bottom)).Intersect(local)
			if q.Empty() {
				continue
			}
			work += int64(q.Dx()) * int64(q.Dy())
			if work > maxRegionWork {
				return nil, ErrRenderLimit
			}
			out = append(out, q)
		}
		return out, nil
	}
	var err error
	if w.KnownFields&rail.FieldWindowRects != 0 {
		v.shape, err = regions(w.WindowRects)
	} else {
		v.shape = []image.Rectangle{local}
		work = int64(w.Width) * int64(w.Height)
	}
	if err != nil {
		return nil, err
	}
	if mode == BasePresentation {
		v.visibility, err = regions(w.VisibilityRects)
		if err != nil {
			return nil, err
		}
	}
	// Retain only fields needed to reject stale inputs; no title or icon ownership.
	v.window = rail.Window{Cloaked: w.Cloaked, CloakSerial: w.CloakSerial, ID: w.ID, Generation: w.Generation, KnownFields: w.KnownFields, WindowProperties: rail.WindowProperties{X: w.X, Y: w.Y, Width: w.Width, Height: w.Height, ShowState: w.ShowState, MarginLeft: w.MarginLeft, MarginRight: w.MarginRight, MarginTop: w.MarginTop, MarginBottom: w.MarginBottom, WindowRects: slices.Clone(w.WindowRects)}}
	if mode == BasePresentation {
		v.window.VisibilityRects = slices.Clone(w.VisibilityRects)
	}
	return v, nil
}

func viewSize(w, h int) bool { return viewSize64(int64(w), int64(h)) }
func viewSize64(w, h int64) bool {
	return w > 0 && h > 0 && w <= maxViewDimension && h <= maxViewDimension && w*h <= maxViewPixels
}

func (v *View) Identity() rail.WindowIdentity {
	return rail.WindowIdentity{ID: v.window.ID, Generation: v.window.Generation}
}
func (v *View) Bounds() image.Rectangle  { return v.bounds }
func (v *View) Desktop() image.Rectangle { return v.desktop }
func (v *View) Shown() bool              { return v.shown }

func inside(p image.Point, regions []image.Rectangle) bool {
	for _, r := range regions {
		if p.In(r) {
			return true
		}
	}
	return false
}

// HitTest uses unscaled, window-local pixels. Transparent resize margins are
// interactive even though they are outside the rendered body. Alpha in a GFX
// image does not by itself determine input transparency; use window geometry.
func (v *View) HitTest(p image.Point) bool {
	if !v.shown || !p.In(v.interactive) {
		return false
	}
	if !p.In(image.Rectangle{Max: v.bounds.Size()}) {
		return true
	}
	return inside(p, v.shape) && (v.mode == EnhancedPresentation || inside(p, v.visibility))
}

// Current checks identity plus fields used for presentation/input. Title/icon
// updates do not invalidate geometry. Caller must obtain current from the same
// connection's WindowState; identities are not global across connections.
func (v *View) Current(current rail.Window) bool {
	w := v.window
	mask := uint32(rail.FieldWindowOffset | rail.FieldWindowSize | rail.FieldShow | rail.FieldWindowRects | rail.FieldResizeMarginX | rail.FieldResizeMarginY)
	if v.mode == BasePresentation {
		mask |= rail.FieldVisibility
	}
	if current.Cloaked != w.Cloaked || current.CloakSerial != w.CloakSerial || current.ID != w.ID || current.Generation != w.Generation || current.KnownFields&mask != w.KnownFields&mask || current.X != w.X || current.Y != w.Y || current.Width != w.Width || current.Height != w.Height || current.ShowState != w.ShowState {
		return false
	}
	if mask&current.KnownFields&rail.FieldWindowRects != 0 && !slices.Equal(current.WindowRects, w.WindowRects) {
		return false
	}
	if v.mode == BasePresentation && !slices.Equal(current.VisibilityRects, w.VisibilityRects) {
		return false
	}
	if current.KnownFields&rail.FieldResizeMarginX != 0 && (current.MarginLeft != w.MarginLeft || current.MarginRight != w.MarginRight) {
		return false
	}
	if current.KnownFields&rail.FieldResizeMarginY != 0 && (current.MarginTop != w.MarginTop || current.MarginBottom != w.MarginBottom) {
		return false
	}
	return true
}

// Pointer resolves window-local coordinates to zero-origin RDP desktop pixels.
// The application must convert any UI zoom/CSS scale to window pixels first.
// captured may be true only during an application-tracked mouse capture, allowing
// a held drag to leave window shape/visibility; desktop bounds still apply.
// Validate with current metadata immediately before sending, serialized with
// geometry updates. No clamping, transport writes or activation is performed.
func (v *View) Pointer(current rail.Window, p image.Point, captured bool) (image.Point, error) {
	if !v.Current(current) {
		return image.Point{}, ErrStale
	}
	if !v.shown {
		return image.Point{}, ErrHidden
	}
	if !captured && !v.HitTest(p) {
		return image.Point{}, ErrOutside
	}
	if p.X < -1<<31 || p.X > 1<<31-1 || p.Y < -1<<31 || p.Y > 1<<31-1 {
		return image.Point{}, ErrOutside
	}
	x, y := int64(v.bounds.Min.X)+int64(p.X)-int64(v.desktop.Min.X), int64(v.bounds.Min.Y)+int64(p.Y)-int64(v.desktop.Min.Y)
	if x < 0 || y < 0 || x >= int64(v.desktop.Dx()) || y >= int64(v.desktop.Dy()) {
		return image.Point{}, ErrOutside
	}
	return image.Pt(int(x), int(y)), nil
}

// MoveBounds translates desired visible-body bounds into WindowMove/WindowSnap
// bounds, which also include the negotiated transparent resize margins. It does
// not send anything or constrain windows to the desktop. The RAIL wire uses
// signed 16-bit coordinates; an unrepresentable request is rejected, never wrapped.
func (v *View) MoveBounds(current rail.Window, body image.Rectangle) (rail.WindowRectangle, error) {
	if !v.Current(current) {
		return rail.WindowRectangle{}, ErrStale
	}
	if body.Min.X < -32768 || body.Min.X > 32767 || body.Min.Y < -32768 || body.Min.Y > 32767 || body.Max.X < -32768 || body.Max.X > 32767 || body.Max.Y < -32768 || body.Max.Y > 32767 || !viewSize(body.Dx(), body.Dy()) {
		return rail.WindowRectangle{}, ErrGeometry
	}
	l, t := body.Min.X+v.interactive.Min.X, body.Min.Y+v.interactive.Min.Y
	r, b := body.Max.X+(v.interactive.Max.X-v.bounds.Dx()), body.Max.Y+(v.interactive.Max.Y-v.bounds.Dy())
	if l < -32768 || t < -32768 || r > 32767 || b > 32767 {
		return rail.WindowRectangle{}, ErrGeometry
	}
	return rail.WindowRectangle{Left: int16(l), Top: int16(t), Right: int16(r), Bottom: int16(b)}, nil
}
