package rail

// MonitorWorkArea describes one monitor and its usable area in virtual-screen
// coordinates relative to the primary monitor. Right and Bottom are exclusive.
// Negative coordinates are valid. It does not read or change host OS settings.
type MonitorWorkArea struct {
	Monitor, WorkArea WindowRectangle
}

// DesktopLayout supplies signed virtual-screen geometry for system parameters.
// TS_RECTANGLE_16 transports unsigned words, but these three system parameters
// use virtual-screen coordinates (signed 16-bit values). Window shape/visibility
// Rectangle coordinates remain unsigned and must not use this interpretation.
// Display must equal the bounding rectangle of 1..16 nonoverlapping monitors.
// Each WorkArea must fit its monitor. Taskbar may be zero to denote no taskbar.
// These PDUs change RAIL settings, not the RDP display size or monitor topology;
// synchronize them with the separately negotiated desktop geometry.
type DesktopLayout struct {
	Display, Taskbar WindowRectangle
	Monitors         []MonitorWorkArea
}

func screenNonempty(r WindowRectangle) bool { return r.Left < r.Right && r.Top < r.Bottom }
func screenContains(r, s WindowRectangle) bool {
	return r.Left <= s.Left && r.Top <= s.Top && r.Right >= s.Right && r.Bottom >= s.Bottom
}
func screenBytes(r WindowRectangle) []byte {
	return (Rectangle{uint16(r.Left), uint16(r.Top), uint16(r.Right), uint16(r.Bottom)}).bytes()
}

// Validate checks the complete layout without modifying client state.
func (d DesktopLayout) Validate() error {
	if !screenNonempty(d.Display) || len(d.Monitors) < 1 || len(d.Monitors) > 16 {
		return ErrInvalid
	}
	if d.Taskbar != (WindowRectangle{}) && (!screenNonempty(d.Taskbar) || !screenContains(d.Display, d.Taskbar)) {
		return ErrInvalid
	}
	bounds := d.Monitors[0].Monitor
	for i, m := range d.Monitors {
		if !screenNonempty(m.Monitor) || !screenNonempty(m.WorkArea) || !screenContains(d.Display, m.Monitor) || !screenContains(m.Monitor, m.WorkArea) {
			return ErrInvalid
		}
		for _, prev := range d.Monitors[:i] {
			if max(prev.Monitor.Left, m.Monitor.Left) < min(prev.Monitor.Right, m.Monitor.Right) && max(prev.Monitor.Top, m.Monitor.Top) < min(prev.Monitor.Bottom, m.Monitor.Bottom) {
				return ErrInvalid
			}
		}
		bounds.Left, bounds.Top = min(bounds.Left, m.Monitor.Left), min(bounds.Top, m.Monitor.Top)
		bounds.Right, bounds.Bottom = max(bounds.Right, m.Monitor.Right), max(bounds.Bottom, m.Monitor.Bottom)
	}
	if bounds != d.Display {
		return ErrInvalid
	}
	return nil
}

// UpdateDesktop prepares display, taskbar and per-monitor work-area PDUs in that
// order. Before the handshake it replaces the queued initial geometry and
// returns no packets; after the handshake the caller must send all returned
// packets in order. All validation precedes any state change. The caller's
// slice is not retained. No server acknowledgement exists: successful writing
// means sent, not applied. On an uncertain write close the connection, as with
// other Client methods; do not retry a partial batch on that connection.
// This complements UpdateSystemParameters without changing its legacy unsigned
// rectangle API. A newly reconnected Client needs its own layout snapshot.
func (c *Client) UpdateDesktop(d DesktopLayout) ([][]byte, error) {
	if c.closed || c.pending == nil {
		return nil, ErrClosed
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	p := make([][]byte, 0, 2+len(d.Monitors))
	p = append(p, systemParameter(0xf001, screenBytes(d.Display)), systemParameter(0xf000, screenBytes(d.Taskbar)))
	for _, m := range d.Monitors {
		p = append(p, systemParameter(0x2f, screenBytes(m.WorkArea)))
	}
	if !c.ready {
		// The first five baseline packets contain non-geometric preferences.
		c.initial = append(c.initial[:5:5], p...)
		return nil, nil
	}
	return p, nil
}
