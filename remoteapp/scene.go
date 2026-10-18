// Package remoteapp associates RAIL window identities with completed GFX window
// frames. It creates no OS windows and sends no input or application launches.
package remoteapp

import (
	"errors"
	"sort"

	"github.com/hq0101/rdp-go/rail"
	"github.com/hq0101/rdp-go/rdpgfx"
)

var ErrState = errors.New("remoteapp: invalid scene source")
var ErrMode = errors.New("remoteapp: window graphics disagree with RAIL mode")

type PendingReason uint8

const (
	UnknownWindow PendingReason = iota + 1
	WindowIDOutOfRange
	ReusedWindow
)

// Binding connects one surface to one observed lifetime of a RAIL window.
// Multiple surfaces may identify the same window; this layer does not invent
// their compositing order. Mapping preserves the complete 64-bit wire ID.
type Binding struct {
	Window  rail.WindowIdentity
	Mapping rdpgfx.WindowMapping
	FrameID uint32
}

type Pending struct {
	Mapping rdpgfx.WindowMapping
	Reason  PendingReason
}

type entry struct {
	mapping rdpgfx.WindowMapping
	window  rail.WindowIdentity
	reason  PendingReason
	frame   *rdpgfx.WindowFrame
}

// Scene is a connection-local view of completed frames. The zero value is ready.
// Serialize Sync with RAIL/GFX consumers and all Scene access. Call Sync after
// each accepted window batch, GFX message, handshake, reactivation or close,
// before presenting or dispatching input. Sync never retains mutable snapshots.
// Caller-held frames remain immutable but the caller must bound their lifetime.
// Do not copy/reset a live WindowState or GFX Client in place: use Reset/Close or
// new objects so changes of identity are visible.
//
// Unknown mappings can bind when RAIL metadata later arrives. Once associated,
// deletion/recreation invalidates a mapping until a fresh Map command or GFX
// channel lifetime. Protocols carry no shared window incarnation; unobserved
// cross-stream deletion/recreation cannot be reconstructed. A Map received before
// the corresponding RAIL recreation can conservatively remain pending. Real RDS
// sequencing and any application reconciliation policy still require validation.
type Scene struct {
	windows           *rail.WindowState
	graphics          *rdpgfx.Client
	channelGeneration uint64
	entries           map[uint16]entry
}

// Reset drops all associations and retained frames. It performs no protocol IO.
func (s *Scene) Reset() { *s = Scene{} }

// Sync publishes only after the caller-owned RAIL Client confirms Enhanced.
// Before handshake, on Close, or after base-mode fallback, it clears output.
// Unexpected window mappings in base mode fail with ErrMode. A changed source
// object or GFX channel lifetime starts fresh association. Any error clears output.
// Pending graphics may be decoded with WindowMapping set from the request before
// the RAIL handshake, but must not be presented independently of this mode gate.
func (s *Scene) Sync(status rail.Status, w *rail.WindowState, g *rdpgfx.Client) error {
	if w == nil || g == nil {
		s.Reset()
		return ErrState
	}
	if !status.Ready || status.Closed {
		s.Reset()
		return nil
	}
	if !status.Enhanced {
		s.Reset()
		if len(g.WindowMappings()) != 0 {
			return ErrMode
		}
		return nil
	}
	if g.Open() && !g.WindowMapping {
		s.Reset()
		return ErrMode
	}
	if s.windows != w || s.graphics != g || s.channelGeneration != g.Generation() {
		s.Reset()
		s.windows, s.graphics, s.channelGeneration = w, g, g.Generation()
	}
	identities := make(map[uint32]rail.WindowIdentity)
	for _, id := range w.Identities() {
		identities[id.ID] = id
	}
	next := make(map[uint16]entry)
	for _, m := range g.WindowMappings() {
		e := s.entries[m.SurfaceID]
		if e.mapping.Generation != m.Generation {
			e = entry{}
		}
		e.mapping = m
		if m.WindowID > uint64(^uint32(0)) {
			e.reason, e.frame = WindowIDOutOfRange, nil
		} else {
			id, exists := identities[uint32(m.WindowID)]
			switch {
			case e.reason == ReusedWindow || e.window.Generation != 0 && (!exists || id != e.window):
				e.reason, e.frame = ReusedWindow, nil
			case !exists:
				e.reason, e.frame = UnknownWindow, nil
			default:
				e.reason, e.window = 0, id
				if e.frame == nil || e.frame.Mapping().Revision != m.Revision {
					e.frame = g.WindowSnapshot(m.SurfaceID)
					if e.frame == nil {
						s.Reset()
						return ErrState
					}
				}
			}
		}
		next[m.SurfaceID] = e
	}
	s.entries = next
	return nil
}

// Bindings returns owned scalar values, sorted by surface ID.
func (s *Scene) Bindings() []Binding {
	var out []Binding
	for _, e := range s.entries {
		if e.reason == 0 && e.frame != nil {
			out = append(out, Binding{Window: e.window, Mapping: e.mapping, FrameID: e.frame.FrameID()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mapping.SurfaceID < out[j].Mapping.SurfaceID })
	return out
}

func (s *Scene) Pending() []Pending {
	var out []Pending
	for _, e := range s.entries {
		if e.reason != 0 {
			out = append(out, Pending{e.mapping, e.reason})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mapping.SurfaceID < out[j].Mapping.SurfaceID })
	return out
}

// Frame returns an immutable completed snapshot only for a bound surface.
// Repeated reads of unchanged frames share storage; Source/Image return copies.
func (s *Scene) Frame(surfaceID uint16) *rdpgfx.WindowFrame {
	return s.entries[surfaceID].frame
}
