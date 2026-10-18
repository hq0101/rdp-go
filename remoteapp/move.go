package remoteapp

import (
	"image"

	"github.com/hq0101/rdp-go/rail"
)

type MovePhase uint8

const (
	MoveIdle MovePhase = iota
	MoveLocal
	MoveAwaitEnd
	MoveInvalidated
)

// MoveSnapshot contains only owned values. Token identifies one operation on
// this controller; Window additionally identifies one observed window lifetime.
// All rectangles/positions are unscaled pixels relative to the primary monitor.
// Body excludes transparent resize margins, Outer includes them. StartPosition
// is the server's raw position: an offset from the outer top-left for mouse move,
// otherwise the last button-down coordinate. MaxWidth/Height and MaxX/Y describe
// maximization, not the tracking limits used by Preview.
type MoveSnapshot struct {
	Token         uint64
	Window        rail.WindowIdentity
	Type          uint16
	Phase         MovePhase
	Body, Outer   image.Rectangle
	StartPosition image.Point
	HasLimits     bool
	Limits        rail.MinMaxInfo
}

// MoveCompletion is a one-use transmission plan, not a server acknowledgement.
// Send WindowMove, if nonempty, through the rail channel. For Cancel, first send
// an Escape key press and release through core input (reconcile/release tracked
// keys before Escape). Then release the initiating mouse button at Pointer through core input
// for every completion, including keyboard operations, and resume normal input.
// The application tracks the initiating button; keyboard operations without a
// pressed button need an explicit button-up policy (the viewer uses left).
// Pointer is already converted to zero-origin RDP desktop coordinates.
// Any failed/uncertain write must close the connection; never replay this plan.
// End and subsequent window orders remain authoritative, including after Cancel.
type MoveCompletion struct {
	WindowMove []byte
	Pointer    image.Point
	Cancel     bool
}

// MoveEnd carries the server's final outer top-left. The PDU has no width or
// height. Apply this position to the local window; obtain authoritative size
// separately from WindowState, rather than treating a requested size as acked.
type MoveEnd struct {
	Window rail.WindowIdentity
	Origin image.Point
}

type moveLimits struct {
	window rail.WindowIdentity
	info   rail.MinMaxInfo
}

// MoveController coordinates server-initiated local move/size with a caller's
// window manager. It creates no OS windows, changes no WindowState metadata and
// performs no IO. Use one controller per connection, with the same Client and
// WindowState for its entire lifetime; create new objects on reconnect.
//
// Serialize all access with the RAIL/window receive path and core input writes.
// Call Sync after every window batch/reactivation/topology change and before
// forwarding input. Advertise Options.LocalMoveSize only when the application
// consumes this protocol AND implements a local window-manager interaction.
// While SuppressInput is true, the local window manager owns keyboard/mouse
// events; do not release already-pressed remote buttons just because Begin ran.
// Finish/Cancel resume input before End; End is not required to resume forwarding.
// A missing End requires application timeout/disconnect policy, not an automatic
// retry or a new overlapping operation. Server PDUs have no operation serial;
// unobserved cross-stream ID reuse or duplicate End cannot be reconstructed.
type MoveController struct {
	client            *rail.Client
	windows           *rail.WindowState
	desktop           image.Rectangle
	limits            map[uint32]moveLimits
	next              uint64
	state             MoveSnapshot
	view              *View
	usable            bool
	serverActive      uint32
	serverActiveKnown bool
}

func NewMoveController(c *rail.Client, w *rail.WindowState, desktop image.Rectangle) (*MoveController, error) {
	if c == nil || w == nil || w.Options().MaxWindows == 0 || !moveDesktop(desktop) {
		return nil, ErrState
	}
	m := &MoveController{client: c, windows: w, desktop: desktop, limits: make(map[uint32]moveLimits)}
	_, err := m.Sync(desktop)
	return m, err
}

func moveDesktop(d image.Rectangle) bool {
	return d.Min.X >= -maxViewDimension && d.Min.Y >= -maxViewDimension && d.Min.X <= 0 && d.Min.Y <= 0 && d.Max.X > 0 && d.Max.Y > 0 && d.Max.X <= maxViewDimension && d.Max.Y <= maxViewDimension && viewSize(d.Dx(), d.Dy())
}

func (m *MoveController) Status() MoveSnapshot { return m.state }
func (m *MoveController) SuppressInput() bool  { return m.state.Phase == MoveLocal }

// Invalidate stops local ownership when the surrounding RDP session deactivates
// or the application loses its presentation context without a window order.
// The caller reconciles held input when the transport permits it. A tombstone
// remains until matching End or connection close, as with Sync invalidation.
func (m *MoveController) Invalidate() bool {
	if m == nil || m.state.Phase == MoveIdle || m.state.Phase == MoveInvalidated {
		return false
	}
	m.state.Phase = MoveInvalidated
	return true
}

func (m *MoveController) ready() error {
	if m == nil || m.client == nil || m.windows == nil {
		return ErrState
	}
	s := m.client.Status()
	if s.Closed {
		return rail.ErrClosed
	}
	if !s.Ready {
		return rail.ErrNotReady
	}
	if s.ClientFlags&1 == 0 {
		return rail.ErrUnsupported
	}
	return nil
}

// Sync prunes limits for deleted/recreated windows and invalidates a local
// operation on geometry, margin, visibility-state, desktop or connection changes.
// Title/icon/occlusion updates do not cancel a move. Geometry updates while
// awaiting End are expected; they never acknowledge the requested size here.
// true tells the application to stop its local interaction and resume/reconcile
// tracked core input if the transport is still usable. A changed server active
// window also invalidates the operation. No input is synthesized.
// An invalidated operation keeps a tombstone until its matching End, preventing
// a late server End from being applied to a newer operation or window lifetime.
// Invalid desktop arguments leave all state unchanged.
func (m *MoveController) Sync(desktop image.Rectangle) (bool, error) {
	if m == nil || m.client == nil || m.windows == nil {
		return false, ErrState
	}
	if !moveDesktop(desktop) {
		return false, ErrGeometry
	}
	changed := desktop != m.desktop
	m.desktop = desktop
	monitored, syncing := m.windows.Monitoring()
	m.usable = monitored && !syncing
	active, activeKnown := m.windows.ActiveWindow()
	focusChanged := activeKnown && (!m.serverActiveKnown || active != m.serverActive) && active != m.state.Window.ID
	m.serverActive, m.serverActiveKnown = active, activeKnown
	identities := m.windows.Identities()
	known := make(map[uint32]rail.WindowIdentity, len(identities))
	for _, id := range identities {
		known[id.ID] = id
	}
	for id, l := range m.limits {
		if known[id] != l.window {
			delete(m.limits, id)
		}
	}
	if m.ready() != nil {
		wasActive := m.state.Phase != MoveIdle
		m.state, m.view = MoveSnapshot{}, nil
		clear(m.limits)
		return wasActive, nil
	}
	if m.state.Phase == MoveIdle || m.state.Phase == MoveInvalidated {
		return false, nil
	}
	if changed || focusChanged || !m.usable || !m.current() {
		m.state.Phase = MoveInvalidated
		return true, nil
	}
	return false, nil
}

// SetLimits binds a MinMaxInfo to the currently observed window lifetime.
// Unknown windows are ignored, not cached for a possible later ID reuse.
// Zero dimension limits are treated as unspecified; negative sizes or inverted
// nonzero tracking ranges are rejected atomically. This zero-value profile and
// native window-manager interpretation still require real RDS interoperability.
func (m *MoveController) SetLimits(info rail.MinMaxInfo) (bool, error) {
	if err := m.ready(); err != nil {
		return false, err
	}
	w, ok := m.windows.Window(info.WindowID)
	if !ok {
		return false, nil
	}
	if info.MaxWidth < 0 || info.MaxHeight < 0 || info.MinTrackWidth < 0 || info.MinTrackHeight < 0 || info.MaxTrackWidth < 0 || info.MaxTrackHeight < 0 || info.MaxTrackWidth != 0 && info.MinTrackWidth > info.MaxTrackWidth || info.MaxTrackHeight != 0 && info.MinTrackHeight > info.MaxTrackHeight {
		return false, ErrGeometry
	}
	// Bound storage even if a caller forgets Sync between window replacements.
	for id, l := range m.limits {
		current, exists := m.windows.Window(id)
		if !exists || current.Generation != l.window.Generation {
			delete(m.limits, id)
		}
	}
	id := rail.WindowIdentity{ID: w.ID, Generation: w.Generation}
	m.limits[w.ID] = moveLimits{id, info}
	if m.state.Window == id && m.state.Phase != MoveIdle {
		m.state.Limits, m.state.HasLimits = info, true
	}
	return true, nil
}

// Begin consumes a Start event after the RAIL Client accepted it. The bool is
// false for an unknown window. A known target must have complete, shown geometry
// and the desktop must be monitored. A second Start is rejected until End.
func (m *MoveController) Begin(start rail.MoveSize) (MoveSnapshot, bool, error) {
	if err := m.ready(); err != nil {
		return MoveSnapshot{}, false, err
	}
	if !start.Start || start.Type < rail.MoveSizeLeft || start.Type > rail.MoveSizeKeySize {
		return MoveSnapshot{}, false, rail.ErrInvalid
	}
	w, ok := m.windows.Window(start.WindowID)
	if !ok {
		return MoveSnapshot{}, false, nil
	}
	if m.state.Phase != MoveIdle {
		return MoveSnapshot{}, false, rail.ErrBusy
	}
	if !m.usable {
		return MoveSnapshot{}, false, ErrStale
	}
	// Movement uses geometry only; ordinary occlusion does not restrict a drag.
	v, err := NewView(w, m.desktop, EnhancedPresentation)
	if err != nil {
		return MoveSnapshot{}, false, err
	}
	if !v.Shown() {
		return MoveSnapshot{}, false, ErrHidden
	}
	r, err := v.MoveBounds(w, v.Bounds())
	if err != nil {
		return MoveSnapshot{}, false, err
	}
	if m.next == ^uint64(0) {
		return MoveSnapshot{}, false, ErrState
	}
	m.next++
	m.view = v
	m.serverActive, m.serverActiveKnown = m.windows.ActiveWindow()
	m.state = MoveSnapshot{Token: m.next, Window: v.Identity(), Type: start.Type, Phase: MoveLocal, Body: v.Bounds(), Outer: moveRect(r), StartPosition: image.Pt(int(start.X), int(start.Y))}
	if l, exists := m.limits[w.ID]; exists && l.window == v.Identity() {
		m.state.HasLimits, m.state.Limits = true, l.info
	}
	return m.state, true, nil
}

func moveRect(r rail.WindowRectangle) image.Rectangle {
	return image.Rect(int(r.Left), int(r.Top), int(r.Right), int(r.Bottom))
}

// current intentionally excludes title, icons, shape and occlusion rectangles.
// While local, remote changes of body geometry invalidate the interaction.
func (m *MoveController) current() bool {
	active, known := m.windows.ActiveWindow()
	if known && (!m.serverActiveKnown || active != m.serverActive) && active != m.state.Window.ID {
		return false
	}
	w, ok := m.windows.Window(m.state.Window.ID)
	if !ok || m.view == nil || w.Generation != m.state.Window.Generation {
		return false
	}
	a := m.view.window
	mask := uint32(rail.FieldWindowOffset | rail.FieldWindowSize | rail.FieldShow | rail.FieldResizeMarginX | rail.FieldResizeMarginY)
	if w.Cloaked || w.CloakSerial != a.CloakSerial || w.KnownFields&mask != a.KnownFields&mask || w.ShowState != a.ShowState || w.MarginLeft != a.MarginLeft || w.MarginRight != a.MarginRight || w.MarginTop != a.MarginTop || w.MarginBottom != a.MarginBottom {
		return false
	}
	return m.state.Phase != MoveLocal || w.X == a.X && w.Y == a.Y && w.Width == a.Width && w.Height == a.Height
}

func (m *MoveController) local(token uint64) error {
	if err := m.ready(); err != nil {
		return err
	}
	if token == 0 || token != m.state.Token || m.state.Phase != MoveLocal || !m.usable || !m.current() {
		return ErrStale
	}
	return nil
}

func (m *MoveController) proposed(body image.Rectangle) (rail.WindowRectangle, error) {
	r, err := m.view.MoveBounds(m.view.window, body)
	if err != nil {
		return rail.WindowRectangle{}, err
	}
	original := m.view.bounds
	move := m.state.Type == rail.MoveSizeMouse || m.state.Type == rail.MoveSizeKeyMove
	if move {
		if body.Size() != original.Size() {
			return rail.WindowRectangle{}, ErrGeometry
		}
	} else {
		if m.state.Type != rail.MoveSizeKeySize {
			left := m.state.Type == rail.MoveSizeLeft || m.state.Type == rail.MoveSizeTopLeft || m.state.Type == rail.MoveSizeBottomLeft
			right := m.state.Type == rail.MoveSizeRight || m.state.Type == rail.MoveSizeTopRight || m.state.Type == rail.MoveSizeBottomRight
			top := m.state.Type == rail.MoveSizeTop || m.state.Type == rail.MoveSizeTopLeft || m.state.Type == rail.MoveSizeTopRight
			bottom := m.state.Type == rail.MoveSizeBottom || m.state.Type == rail.MoveSizeBottomLeft || m.state.Type == rail.MoveSizeBottomRight
			if !left && body.Min.X != original.Min.X || !right && body.Max.X != original.Max.X || !top && body.Min.Y != original.Min.Y || !bottom && body.Max.Y != original.Max.Y {
				return rail.WindowRectangle{}, ErrGeometry
			}
		}
		if m.state.HasLimits {
			l := m.state.Limits
			width, height := int(r.Right)-int(r.Left), int(r.Bottom)-int(r.Top)
			if width < int(l.MinTrackWidth) || height < int(l.MinTrackHeight) || l.MaxTrackWidth != 0 && width > int(l.MaxTrackWidth) || l.MaxTrackHeight != 0 && height > int(l.MaxTrackHeight) {
				return rail.WindowRectangle{}, ErrGeometry
			}
		}
	}
	return r, nil
}

// Preview validates a local window-manager proposal without sending input or
// overwriting remote geometry. Tracking limits apply to outer bounds, including
// resize margins. Fixed edges remain anchored for the eight mouse resize types.
// It rejects, never silently clamps, invalid geometry or unrepresentable int16
// wire coordinates. The caller can use Limits to constrain its local UI.
func (m *MoveController) Preview(token uint64, body image.Rectangle) (MoveSnapshot, error) {
	if err := m.local(token); err != nil {
		return MoveSnapshot{}, err
	}
	r, err := m.proposed(body)
	if err != nil {
		return MoveSnapshot{}, err
	}
	m.state.Body, m.state.Outer = body, moveRect(r)
	return m.state, nil
}

// Finish takes the final body rectangle and actual primary-relative pointer.
// Mouse moves are completed by button-up alone, so pointer must equal the final
// outer origin plus the Start offset. Keyboard moves and all sizes additionally
// produce WindowMove. Off-desktop pointers are rejected; no silent clamping.
// Validate and send the returned plan while still holding application locks.
func (m *MoveController) Finish(token uint64, body image.Rectangle, pointer image.Point) (MoveCompletion, error) {
	if err := m.local(token); err != nil {
		return MoveCompletion{}, err
	}
	r, err := m.proposed(body)
	if err != nil {
		return MoveCompletion{}, err
	}
	if !pointer.In(m.desktop) {
		return MoveCompletion{}, ErrOutside
	}
	if m.state.Type == rail.MoveSizeMouse && pointer != moveRect(r).Min.Add(m.state.StartPosition) {
		return MoveCompletion{}, ErrGeometry
	}
	var packet []byte
	if m.state.Type != rail.MoveSizeMouse {
		packet, err = m.client.WindowMove(m.state.Window.ID, r)
		if err != nil {
			return MoveCompletion{}, err
		}
	}
	m.state.Body, m.state.Outer, m.state.Phase = body, moveRect(r), MoveAwaitEnd
	return MoveCompletion{WindowMove: packet, Pointer: pointer.Sub(m.desktop.Min)}, nil
}

// Cancel ends local suppression and requests server-side Escape cancellation.
// Escape is an explicit application cancellation policy, not a separate RAIL
// cancellation PDU or a guaranteed restoration of the original rectangle.
// It does not send a guessed final rectangle or declare that cancellation took
// effect. The caller must implement the MoveCompletion input sequence and wait
// for End/window metadata. Use for Escape/focus loss only while this operation
// is still current; never send cancellation to a deleted/recreated target.
func (m *MoveController) Cancel(token uint64, pointer image.Point) (MoveCompletion, error) {
	if err := m.local(token); err != nil {
		return MoveCompletion{}, err
	}
	if !pointer.In(m.desktop) {
		return MoveCompletion{}, ErrOutside
	}
	m.state.Phase = MoveAwaitEnd
	return MoveCompletion{Pointer: pointer.Sub(m.desktop.Min), Cancel: true}, nil
}

// End accepts a matching server End, including one arriving before local Finish.
// Unknown/unmatched IDs are ignored. An invalidated or reused target consumes
// the matching tombstone but produces no window action. Duplicate callbacks and
// unmatched End cannot move a newly created local window. Type mismatches leave
// the pending state unchanged and return ErrState.
func (m *MoveController) End(end rail.MoveSize) (MoveEnd, bool, error) {
	if err := m.ready(); err != nil {
		return MoveEnd{}, false, err
	}
	if end.Start || end.Type < rail.MoveSizeLeft || end.Type > rail.MoveSizeKeySize {
		return MoveEnd{}, false, rail.ErrInvalid
	}
	if m.state.Phase == MoveIdle || end.WindowID != m.state.Window.ID {
		return MoveEnd{}, false, nil
	}
	if end.Type != m.state.Type {
		return MoveEnd{}, false, rail.ErrState
	}
	current := m.state.Phase != MoveInvalidated && m.current()
	result := MoveEnd{Window: m.state.Window, Origin: image.Pt(int(end.X), int(end.Y))}
	m.state, m.view = MoveSnapshot{}, nil
	if !current {
		return MoveEnd{}, false, nil
	}
	return result, true, nil
}
