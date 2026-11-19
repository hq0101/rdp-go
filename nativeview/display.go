package nativeview

import (
	"fmt"
	"image"
	"time"

	"github.com/hq0101/rdp-go/disp"
	"github.com/hq0101/rdp-go/dynvc"
)

const displayDebounce = 350 * time.Millisecond
const displayConfirmationTimeout = 15 * time.Second

type displayPhase uint8

const (
	displayIdle displayPhase = iota
	displayPreparing
	displayPending
	displayApplied
	displayAdjusted
	displayUnconfirmed
	displayUnsupported
)

type displayStatus struct {
	enabled, available bool
	phase              displayPhase
	requested          image.Point
}

func (s displayStatus) busy() bool { return s.phase == displayPreparing || s.phase == displayPending }
func (s displayStatus) label() string {
	if !s.enabled {
		return ""
	}
	if !s.available {
		return "Waiting for display control"
	}
	switch s.phase {
	case displayPreparing, displayPending:
		return fmt.Sprintf("Changing resolution to %d x %d", s.requested.X, s.requested.Y)
	case displayAdjusted:
		return "Server selected a different resolution"
	case displayUnconfirmed:
		return "Resolution change not confirmed"
	case displayUnsupported:
		return "Window size exceeds display limits"
	}
	return ""
}

type displayRequest struct {
	serial    uint64
	size      image.Point
	changed   time.Time
	suspended bool
}

// Requests are replaced, not queued, while a previous resize is in flight.
// A zero size suspends automatic requests while the window is minimized or
// being dragged; it never produces a zero-sized wire layout.
func (m *desktopMailbox) requestDisplay(size image.Point, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if size == (image.Point{}) {
		if !m.displayTarget.suspended {
			m.displayTarget.suspended = true
			m.displayTarget.changed = now
		}
		return
	}
	if m.displayTarget.size == size && !m.displayTarget.suspended {
		return
	}
	if m.displayTarget.size != size {
		m.displayTarget.serial++
	}
	m.displayTarget.size, m.displayTarget.changed, m.displayTarget.suspended = size, now, false
}
func (m *desktopMailbox) requestedDisplay() displayRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.displayTarget
}

// The receiver goroutine owns all protocol state. A request is confirmed only
// by observed activation/RESET dimensions, never by successful SendDynamic.
type displayControl struct {
	client    disp.Client
	id        uint32
	open      bool
	attempted uint64
	status    displayStatus
	deadline  time.Time
}

func (d *displayControl) event(e dynvc.Event) error {
	switch e.Kind {
	case dynvc.Opened:
		if d.open {
			return dynvc.ErrChannel
		}
		d.client, d.id, d.open = disp.Client{}, e.ID, true
		d.attempted = 0
		d.status = displayStatus{enabled: true}
	case dynvc.Data:
		if !d.open || e.ID != d.id {
			return dynvc.ErrChannel
		}
		if err := d.client.Handle(e.Data); err != nil {
			return err
		}
		d.status.available = true
	case dynvc.Closed:
		if !d.open || e.ID != d.id {
			return dynvc.ErrChannel
		}
		d.client, d.open = disp.Client{}, false
		d.status = displayStatus{enabled: true}
	default:
		return dynvc.ErrProtocol
	}
	return nil
}

func (d *displayControl) prepare(r displayRequest, now time.Time, actual image.Point, active bool) []byte {
	if !active || !d.open || !d.status.available || !d.client.Ready() || d.status.busy() || r.serial == 0 || r.serial == d.attempted || r.suspended || r.size == (image.Point{}) || now.Sub(r.changed) < displayDebounce {
		return nil
	}
	if r.size == actual {
		d.attempted = r.serial
		d.status.phase, d.status.requested = displayApplied, r.size
		return nil
	}
	packet, err := d.client.Layout(r.size.X, r.size.Y)
	if err != nil {
		d.attempted = r.serial
		d.status.phase, d.status.requested = displayUnsupported, r.size
		return nil
	}
	d.status.phase, d.status.requested = displayPreparing, r.size
	return packet
}

func (d *displayControl) sent(r displayRequest, now time.Time) {
	d.attempted = r.serial
	d.status.phase = displayPending
	d.deadline = now.Add(displayConfirmationTimeout)
}

func (d *displayControl) expire(now time.Time) bool {
	if d.status.phase != displayPending || now.Before(d.deadline) {
		return false
	}
	d.status.phase = displayUnconfirmed
	return true
}

func (d *displayControl) observed(size image.Point) {
	if d.status.phase != displayPending && d.status.phase != displayUnconfirmed {
		return
	}
	d.status.phase = displayAdjusted
	if size == d.status.requested {
		d.status.phase = displayApplied
	}
}

// Keep the requested area independent of transient preedit/candidate panels.
// Resizing for every candidate-list change would interrupt typing and create a
// feedback loop. Width rounds down to the protocol's required even value.
func displayTarget(client image.Rectangle, rowHeight int32, suspended bool) image.Point {
	if suspended {
		return image.Point{}
	}
	w, h := client.Dx()&^1, client.Dy()-2*int(rowHeight)
	if w < 200 || h < 200 {
		return image.Point{}
	}
	return image.Pt(w, h)
}
