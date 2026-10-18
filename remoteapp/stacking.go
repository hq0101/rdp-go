package remoteapp

import "github.com/hq0101/rdp-go/rail"

// StackingPlan contains a local top-to-bottom order and a server activation
// decision. It owns its slices and does not alter WindowState or activate OS
// windows. Unknown non-marker IDs stay in Order and Missing; callers must wait
// for their metadata rather than treating them as drawable windows.
type StackingPlan struct {
	Order, Missing, Enforced []uint32
	Epoch, ActivationSerial  uint64
	// ActivationDecided=false means relevant desktop/marker/window state is
	// missing. Once decided, a zero Activation means do not activate a window.
	ActivationDecided bool
	Activation        rail.WindowIdentity
}

// PlanStacking interprets a snapshot from this connection's WindowState and
// Client. The marker is never rendered. Enforced windows form one consecutive
// block at the first member's position, preserving their server order and the
// relative order of all other windows. Activation is compared against the raw
// server list, before that local grouping. No group member crosses a marker
// for purposes of the activation decision.
//
// Advertised Z-order sync with no marker/list entry yet defers activation;
// without that feature the ordinary server activation rule is used. A caller
// must still honor local focus/visibility policy, release input before changing
// targets, and bind the decision to the snapshot's window generation. A server
// activation must not be echoed back as a new Client Activate request.
func PlanStacking(status rail.Status, d rail.DesktopSnapshot) (StackingPlan, error) {
	p := StackingPlan{Epoch: d.Epoch, ActivationSerial: d.ActivationSerial}
	if len(d.ZOrder) > 255 || len(d.Windows) > 4096 {
		return p, ErrRenderLimit
	}
	windows := make(map[uint32]rail.Window, len(d.Windows))
	for _, w := range d.Windows {
		if _, ok := windows[w.ID]; ok || w.Generation == 0 {
			return p, ErrState
		}
		windows[w.ID] = w
	}
	if !status.Ready || status.Closed || !d.Monitored || d.Syncing {
		return p, nil
	}
	markerIndex, activeIndex := -1, -1
	seen := make(map[uint32]bool, len(d.ZOrder))
	for i, id := range d.ZOrder {
		if seen[id] {
			return p, ErrState
		}
		seen[id] = true
		if status.MarkerKnown && id == status.MarkerWindowID {
			markerIndex = i
			continue
		}
		if id == d.ActiveWindowID {
			activeIndex = i
		}
		w, ok := windows[id]
		if !ok {
			p.Missing = append(p.Missing, id)
		}
		if ok && w.KnownFields&rail.FieldEnforceZOrder != 0 && w.EnforceZOrder == 1 {
			p.Enforced = append(p.Enforced, id)
		}
	}
	forced := make(map[uint32]bool, len(p.Enforced))
	for _, id := range p.Enforced {
		forced[id] = true
	}
	added := false
	for _, id := range d.ZOrder {
		if status.MarkerKnown && id == status.MarkerWindowID {
			continue
		}
		if forced[id] {
			if !added {
				p.Order = append(p.Order, p.Enforced...)
				added = true
			}
			continue
		}
		p.Order = append(p.Order, id)
	}
	if !d.ActiveKnown {
		p.ActivationDecided = true
		return p, nil
	}
	if status.MarkerKnown && d.ActiveWindowID == status.MarkerWindowID {
		p.ActivationDecided = true
		return p, nil
	}
	if !d.ZOrderKnown {
		return p, nil
	}
	if status.ClientFlags&4 != 0 {
		if !status.MarkerKnown || markerIndex < 0 || activeIndex < 0 {
			return p, nil
		}
		if activeIndex > markerIndex {
			p.ActivationDecided = true
			return p, nil
		}
	}
	w, ok := windows[d.ActiveWindowID]
	if ok && w.Cloaked {
		p.ActivationDecided = true
		return p, nil
	}
	if !ok || w.KnownFields&rail.FieldShow == 0 {
		return p, nil
	}
	p.ActivationDecided = true
	if activeIndex >= 0 && (w.ShowState == 3 || w.ShowState == 5) {
		p.Activation = rail.WindowIdentity{ID: w.ID, Generation: w.Generation}
	}
	return p, nil
}
