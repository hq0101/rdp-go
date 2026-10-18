// Package display describes requested monitor geometry shared by initial GCC
// negotiation and the DisplayControl dynamic channel. It does not enumerate
// operating-system monitors, rotate pixels, or infer server acceptance.
package display

import (
	"errors"
	"fmt"
	"image"
)

const MaxMonitors = 16
const MaxDimension = 8192
const MaxPixels = 16 << 20

var ErrLayout = errors.New("display: invalid monitor layout")

// Monitor uses desktop pixel coordinates relative to the primary monitor at
// (0,0). Width/Height already describe the oriented desktop; Orientation does
// not swap them. Physical dimensions are millimeters (both zero means unknown).
// Zero scale factors default to 100. These are requests, not confirmed values.
type Monitor struct {
	Left, Top                             int32
	Width, Height                         uint32
	Primary                               bool
	PhysicalWidth, PhysicalHeight         uint32
	Orientation                           uint32
	DesktopScaleFactor, DeviceScaleFactor uint32
}

// Normalize returns an owned copy with default scales and its exclusive pixel
// bounds. Limits apply to the complete framebuffer, including gaps. Each monitor
// must touch at least one other (corners count) unless it is the sole monitor.
// Overlap is forbidden. All explicit attributes are validated before sending;
// invalid optional attributes are not silently replaced with server defaults.
func Normalize(monitors []Monitor) ([]Monitor, image.Rectangle, error) {
	bad := func(reason string) ([]Monitor, image.Rectangle, error) {
		return nil, image.Rectangle{}, fmt.Errorf("%w: %s", ErrLayout, reason)
	}
	if len(monitors) < 1 || len(monitors) > MaxMonitors {
		return bad("monitor count must be 1..16")
	}
	result := append([]Monitor(nil), monitors...)
	var bounds image.Rectangle
	var boxes [MaxMonitors][4]int64
	primary := 0
	for i := range result {
		m := &result[i]
		if m.Width < 200 || m.Width > MaxDimension || m.Width&1 != 0 || m.Height < 200 || m.Height > MaxDimension {
			return bad(fmt.Sprintf("monitor %d dimensions must be 200..8192 with even width", i))
		}
		if m.Primary {
			primary++
			if m.Left != 0 || m.Top != 0 {
				return bad("primary monitor must start at (0,0)")
			}
		}
		if m.PhysicalWidth != 0 || m.PhysicalHeight != 0 {
			if m.PhysicalWidth < 10 || m.PhysicalWidth > 10000 || m.PhysicalHeight < 10 || m.PhysicalHeight > 10000 {
				return bad("physical dimensions must both be 10..10000 mm or both zero")
			}
		}
		if m.Orientation != 0 && m.Orientation != 90 && m.Orientation != 180 && m.Orientation != 270 {
			return bad("orientation must be 0, 90, 180 or 270")
		}
		if m.DesktopScaleFactor == 0 {
			m.DesktopScaleFactor = 100
		}
		if m.DeviceScaleFactor == 0 {
			m.DeviceScaleFactor = 100
		}
		if m.DesktopScaleFactor < 100 || m.DesktopScaleFactor > 500 || (m.DeviceScaleFactor != 100 && m.DeviceScaleFactor != 140 && m.DeviceScaleFactor != 180) {
			return bad("invalid desktop or device scale")
		}
		boxes[i] = [4]int64{int64(m.Left), int64(m.Top), int64(m.Left) + int64(m.Width), int64(m.Top) + int64(m.Height)}
	}
	if primary != 1 {
		return bad("exactly one primary monitor is required")
	}
	b := boxes[0]
	for i := 0; i < len(result); i++ {
		a := boxes[i]
		b = [4]int64{min(b[0], a[0]), min(b[1], a[1]), max(b[2], a[2]), max(b[3], a[3])}
		adjacent := len(result) == 1
		for j := 0; j < len(result); j++ {
			if i == j {
				continue
			}
			c := boxes[j]
			if max(a[0], c[0]) < min(a[2], c[2]) && max(a[1], c[1]) < min(a[3], c[3]) {
				return bad("monitors overlap")
			}
			if max(a[0], c[0]) <= min(a[2], c[2]) && max(a[1], c[1]) <= min(a[3], c[3]) {
				adjacent = true
			}
		}
		if !adjacent {
			return bad("each monitor must touch another monitor")
		}
	}
	w, h := b[2]-b[0], b[3]-b[1]
	if w > MaxDimension || h > MaxDimension || w*h > MaxPixels {
		return bad("desktop exceeds framebuffer limits")
	}
	// Bounds include the primary at zero, so the checks above also bound all
	// signed coordinates before conversion to int, including on 32-bit targets.
	bounds = image.Rect(int(b[0]), int(b[1]), int(b[2]), int(b[3]))
	return result, bounds, nil
}
