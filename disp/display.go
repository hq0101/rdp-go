// Package disp implements MS-RDPEDISP display control messages.
// Transport messages on the DisplayControl dynamic channel using package dynvc.
package disp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/hq0101/rdp-go/display"
	"math"
)

const ChannelName = "Microsoft::Windows::RDS::DisplayControl"
const MaxPixels = display.MaxPixels

var ErrProtocol = errors.New("disp: invalid display control capabilities")
var ErrNotReady = errors.New("disp: display control capabilities not received")
var ErrDimensions = errors.New("disp: unsupported desktop dimensions")

type Capabilities struct {
	MaxMonitors uint32 `json:"max_monitors"`
	MaxArea     uint64 `json:"max_area"`
}

// Client requires serialized access and a fresh instance on each channel open.
// Receiving capabilities does not resize the desktop. A layout request has no
// protocol acknowledgement; verify geometry using Session.MonitorLayout or
// rdpgfx.Client.Monitors after activation/reset. DPI has no wire confirmation.
type Client struct{ caps Capabilities }

func (c *Client) Ready() bool                { return c.caps.MaxMonitors != 0 }
func (c *Client) Capabilities() Capabilities { return c.caps }

func (c *Client) Handle(b []byte) error {
	if c.Ready() || len(b) != 20 || binary.LittleEndian.Uint32(b) != 5 || binary.LittleEndian.Uint32(b[4:]) != 20 {
		return ErrProtocol
	}
	n := binary.LittleEndian.Uint32(b[8:])
	a, z := uint64(binary.LittleEndian.Uint32(b[12:])), uint64(binary.LittleEndian.Uint32(b[16:]))
	if n == 0 || a == 0 || z == 0 || a*z > math.MaxUint64/uint64(n) {
		return ErrProtocol
	}
	c.caps = Capabilities{MaxMonitors: n, MaxArea: uint64(n) * a * z}
	return nil
}

// Layout requests one primary landscape monitor at (0,0), 100% scale. Width
// must be even. Physical dimensions are unspecified (zero). Bounds include
// the server's advertised area and this client's 16M-pixel framebuffer limit.
func (c *Client) Layout(width, height int) ([]byte, error) {
	if !c.Ready() {
		return nil, ErrNotReady
	}
	if width < 200 || width > 8192 || height < 200 || height > 8192 {
		return nil, ErrDimensions
	}
	return c.LayoutMonitors([]display.Monitor{{Primary: true, Width: uint32(width), Height: uint32(height)}})
}

// LayoutMonitors encodes the entire requested topology, including DPI and
// orientation. Server limits apply to monitor count and total monitor pixels;
// display.Normalize also bounds the complete framebuffer including empty gaps.
// Success only returns a packet; it does not change or confirm remote geometry.
func (c *Client) LayoutMonitors(monitors []display.Monitor) ([]byte, error) {
	if !c.Ready() {
		return nil, ErrNotReady
	}
	ms, _, err := display.Normalize(monitors)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDimensions, err)
	}
	var area uint64
	for _, m := range ms {
		area += uint64(m.Width) * uint64(m.Height)
	}
	if uint32(len(ms)) > c.caps.MaxMonitors || area > c.caps.MaxArea {
		return nil, ErrDimensions
	}
	b := make([]byte, 0, 16+40*len(ms))
	for _, value := range []uint32{2, uint32(16 + 40*len(ms)), 40, uint32(len(ms))} {
		b = binary.LittleEndian.AppendUint32(b, value)
	}
	for _, m := range ms {
		flags := uint32(0)
		if m.Primary {
			flags = 1
		}
		for _, value := range []uint32{flags, uint32(m.Left), uint32(m.Top), m.Width, m.Height, m.PhysicalWidth, m.PhysicalHeight, m.Orientation, m.DesktopScaleFactor, m.DeviceScaleFactor} {
			b = binary.LittleEndian.AppendUint32(b, value)
		}
	}
	return b, nil
}
