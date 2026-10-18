// Package rdpgfx implements graphics-pipeline wire messages and a bounded
// software pipeline for ThinClient, Progressive and AVC profiles through
// Version 10.7 (including AVC420/444/444v2 and output/window mapping).
package rdpgfx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
)

const ChannelName = "Microsoft::Windows::RDS::Graphics"
const MaxMessage = 64 << 20
const MaxCommands = 4096

const (
	WireToSurface1 uint16 = 1 + iota
	WireToSurface2
	DeleteEncodingContext
	SolidFill
	SurfaceToSurface
	SurfaceToCache
	CacheToSurface
	EvictCacheEntry
	CreateSurface
	DeleteSurface
	StartFrame
	EndFrame
	FrameAcknowledge
	ResetGraphics
	MapSurfaceToOutput
	CacheImportOffer
	CacheImportReply
	CapsAdvertise
	CapsConfirm
)

const (
	MapSurfaceToWindow       uint16 = 0x15
	MapSurfaceToScaledWindow uint16 = 0x18
	MapSurfaceToScaledOutput uint16 = 0x17
	Version8                 uint32 = 0x00080004
	Version81                uint32 = 0x00080105
	Version10                uint32 = 0x000a0002
	Version102               uint32 = 0x000a0200
	Version103               uint32 = 0x000a0301
	Version104               uint32 = 0x000a0400
	Version105               uint32 = 0x000a0502
	Version106               uint32 = 0x000a0600
	Version107               uint32 = 0x000a0701
	ThinClient               uint32 = 1
	SmallCache               uint32 = 2
	AVC420Enabled            uint32 = 0x10
	AVCDisabled              uint32 = 0x20
	AVCThinClient            uint32 = 0x40 // preference for AVC444, not the Version 8 ThinClient flag
	ScaledMapDisable         uint32 = 0x80
	PixelXRGB                byte   = 0x20
	PixelARGB                byte   = 0x21
	CodecRaw                 uint16 = 0
	CodecRemoteFX            uint16 = 3
	CodecClear               uint16 = 8
	CodecProgressive         uint16 = 9
	CodecPlanar              uint16 = 10
	CodecAVC420              uint16 = 11
	CodecAlpha               uint16 = 12
	CodecAVC444              uint16 = 14
	CodecAVC444V2            uint16 = 15
)

var ErrInvalid = errors.New("rdpgfx: invalid graphics message")
var ErrUnsupported = errors.New("rdpgfx: unsupported graphics operation or codec")

// Capability is a wire description, not a claim that this package implements
// its codecs. Callers must only offer profiles supported by their renderer.
type Capability struct {
	Version uint32
	Data    []byte
}
type Monitor struct {
	Left, Top, Right, Bottom int32
	Flags                    uint32
} // inclusive bounds

// Command is one owned server PDU. Rectangles use exclusive right/bottom bounds.
// Unused fields are zero. Parsing verifies framing and field bounds; reference
// existence, resource budgets and codec semantics are checked by the pipeline.
type Command struct {
	ID                        uint16
	SurfaceID, DestSurfaceID  uint16
	CodecID                   uint16
	ContextID                 uint32
	PixelFormat               byte
	Rect                      image.Rectangle
	Rects                     []image.Rectangle
	Points                    []image.Point
	Color                     [4]byte // blue, green, red, alpha
	CacheSlot                 uint16
	CacheKey                  uint64
	Width, Height             int
	WindowID                  uint64 // never narrowed to a platform handle or 32-bit RAIL ID
	MappedWidth, MappedHeight int
	Origin                    image.Point
	FrameID                   uint32
	// Timestamp is uninterpreted server metadata. It may not be a valid packed
	// UTC time and must not be used as a local deadline or ordering guarantee.
	Timestamp  uint32
	Capability Capability
	Monitors   []Monitor
	Data       []byte
}

func pixelValid(p byte) bool { return p == PixelXRGB || p == PixelARGB }
func rectangle(b []byte) (image.Rectangle, error) {
	x0, y0, x1, y1 := int(binary.LittleEndian.Uint16(b)), int(binary.LittleEndian.Uint16(b[2:])), int(binary.LittleEndian.Uint16(b[4:])), int(binary.LittleEndian.Uint16(b[6:]))
	if x1 < x0 || y1 < y0 {
		return image.Rectangle{}, ErrInvalid
	}
	return image.Rect(x0, y0, x1, y1), nil
}
func pointList(b []byte, n int) ([]image.Point, error) {
	if n > len(b)/4 || len(b) != n*4 {
		return nil, ErrInvalid
	}
	p := make([]image.Point, n)
	for i := range p {
		p[i] = image.Pt(int(binary.LittleEndian.Uint16(b[i*4:])), int(binary.LittleEndian.Uint16(b[i*4+2:])))
	}
	return p, nil
}

// Parse accepts one decompressed GFX channel message containing complete PDUs.
// PDUs may be coalesced but cannot span separate RDP_SEGMENTED_DATA structures.
// All commands are returned only after the entire input has passed validation.
func Parse(b []byte) ([]Command, error) {
	if len(b) == 0 || len(b) > MaxMessage {
		return nil, ErrInvalid
	}
	var commands []Command
	for len(b) > 0 {
		if len(b) < 8 || len(commands) >= MaxCommands || binary.LittleEndian.Uint16(b[2:]) != 0 {
			return nil, ErrInvalid
		}
		id := binary.LittleEndian.Uint16(b)
		n := uint64(binary.LittleEndian.Uint32(b[4:]))
		if n < 8 || n > uint64(len(b)) {
			return nil, ErrInvalid
		}
		c, err := parseCommand(id, b[8:int(n)])
		if err != nil {
			return nil, fmt.Errorf("graphics command 0x%04x: %w", id, err)
		}
		commands = append(commands, c)
		b = b[int(n):]
	}
	return commands, nil
}

func parseCommand(id uint16, b []byte) (Command, error) {
	c := Command{ID: id}
	bad := func() (Command, error) { return Command{}, ErrInvalid }
	switch id {
	case WireToSurface1, WireToSurface2:
		n := 17
		if id == WireToSurface2 {
			n = 13
		}
		if len(b) < n {
			return bad()
		}
		c.SurfaceID, c.CodecID = binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:])
		if id == WireToSurface1 {
			c.PixelFormat = b[4]
			var err error
			c.Rect, err = rectangle(b[5:])
			if err != nil {
				return bad()
			}
		} else {
			c.ContextID = binary.LittleEndian.Uint32(b[4:])
			c.PixelFormat = b[8]
			if c.CodecID != CodecProgressive {
				return bad()
			}
		}
		if !pixelValid(c.PixelFormat) || uint64(binary.LittleEndian.Uint32(b[n-4:])) != uint64(len(b)-n) {
			return bad()
		}
		c.Data = append([]byte(nil), b[n:]...)
	case DeleteEncodingContext:
		if len(b) != 6 {
			return bad()
		}
		c.SurfaceID = binary.LittleEndian.Uint16(b)
		c.ContextID = binary.LittleEndian.Uint32(b[2:])
	case SolidFill:
		if len(b) < 8 {
			return bad()
		}
		c.SurfaceID = binary.LittleEndian.Uint16(b)
		copy(c.Color[:], b[2:6])
		count := int(binary.LittleEndian.Uint16(b[6:]))
		if count != (len(b)-8)/8 || len(b) != 8+count*8 {
			return bad()
		}
		c.Rects = make([]image.Rectangle, count)
		for i := range c.Rects {
			var err error
			c.Rects[i], err = rectangle(b[8+i*8:])
			if err != nil {
				return bad()
			}
		}
	case SurfaceToSurface:
		if len(b) < 14 {
			return bad()
		}
		c.SurfaceID = binary.LittleEndian.Uint16(b)
		c.DestSurfaceID = binary.LittleEndian.Uint16(b[2:])
		var err error
		c.Rect, err = rectangle(b[4:])
		if err != nil {
			return bad()
		}
		c.Points, err = pointList(b[14:], int(binary.LittleEndian.Uint16(b[12:])))
		if err != nil {
			return bad()
		}
	case SurfaceToCache:
		if len(b) != 20 {
			return bad()
		}
		c.SurfaceID = binary.LittleEndian.Uint16(b)
		c.CacheKey = binary.LittleEndian.Uint64(b[2:])
		c.CacheSlot = binary.LittleEndian.Uint16(b[10:])
		var err error
		c.Rect, err = rectangle(b[12:])
		if err != nil || c.CacheSlot == 0 {
			return bad()
		}
	case CacheToSurface:
		if len(b) < 6 {
			return bad()
		}
		c.CacheSlot = binary.LittleEndian.Uint16(b)
		c.SurfaceID = binary.LittleEndian.Uint16(b[2:])
		var err error
		c.Points, err = pointList(b[6:], int(binary.LittleEndian.Uint16(b[4:])))
		if err != nil || c.CacheSlot == 0 {
			return bad()
		}
	case EvictCacheEntry:
		if len(b) != 2 {
			return bad()
		}
		c.CacheSlot = binary.LittleEndian.Uint16(b)
		if c.CacheSlot == 0 {
			return bad()
		}
	case CreateSurface:
		if len(b) != 7 {
			return bad()
		}
		c.SurfaceID = binary.LittleEndian.Uint16(b)
		c.Width = int(binary.LittleEndian.Uint16(b[2:]))
		c.Height = int(binary.LittleEndian.Uint16(b[4:]))
		c.PixelFormat = b[6]
		if c.Width == 0 || c.Height == 0 || !pixelValid(c.PixelFormat) {
			return bad()
		}
	case DeleteSurface:
		if len(b) != 2 {
			return bad()
		}
		c.SurfaceID = binary.LittleEndian.Uint16(b)
	case StartFrame:
		if len(b) != 8 {
			return bad()
		}
		c.Timestamp = binary.LittleEndian.Uint32(b)
		c.FrameID = binary.LittleEndian.Uint32(b[4:])
		// Timestamp is advisory metadata, never a clock or resource bound.
		// Windows 10 has emitted 0xb6ff5800, outside the documented packed
		// UTC ranges. Preserve the raw uint32 without terminating rendering;
		// frame grouping and acknowledgements depend solely on FrameID.
	case EndFrame:
		if len(b) != 4 {
			return bad()
		}
		c.FrameID = binary.LittleEndian.Uint32(b)
	case ResetGraphics:
		if len(b) != 332 {
			return bad()
		}
		w, h, n := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint32(b[8:])
		if w == 0 || h == 0 || w > 32766 || h > 32766 || n > 16 {
			return bad()
		}
		c.Width, c.Height = int(w), int(h)
		c.Monitors = make([]Monitor, n)
		for i := range c.Monitors {
			v := b[12+i*20:]
			m := Monitor{int32(binary.LittleEndian.Uint32(v)), int32(binary.LittleEndian.Uint32(v[4:])), int32(binary.LittleEndian.Uint32(v[8:])), int32(binary.LittleEndian.Uint32(v[12:])), binary.LittleEndian.Uint32(v[16:])}
			if m.Right < m.Left || m.Bottom < m.Top || m.Flags&^uint32(1) != 0 {
				return bad()
			}
			c.Monitors[i] = m
		}
		// The remaining bytes are required padding with unspecified contents.
	case MapSurfaceToOutput, MapSurfaceToScaledOutput:
		n := 12
		if id == MapSurfaceToScaledOutput {
			n = 20
		}
		if len(b) != n || binary.LittleEndian.Uint16(b[2:]) != 0 {
			return bad()
		}
		c.SurfaceID = binary.LittleEndian.Uint16(b)
		x, y := binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint32(b[8:])
		if x > 32766 || y > 32766 {
			return bad()
		}
		c.Origin = image.Pt(int(x), int(y))
		if id == MapSurfaceToScaledOutput {
			w, h := binary.LittleEndian.Uint32(b[12:]), binary.LittleEndian.Uint32(b[16:])
			if w == 0 || h == 0 || w > 32766 || h > 32766 {
				return bad()
			}
			c.Width, c.Height = int(w), int(h)
		}
	case MapSurfaceToWindow, MapSurfaceToScaledWindow:
		n := 18
		if id == MapSurfaceToScaledWindow {
			n = 26
		}
		if len(b) != n {
			return bad()
		}
		c.SurfaceID = binary.LittleEndian.Uint16(b)
		c.WindowID = binary.LittleEndian.Uint64(b[2:])
		w, h := binary.LittleEndian.Uint32(b[10:]), binary.LittleEndian.Uint32(b[14:])
		if w == 0 || h == 0 || w > 8192 || h > 8192 {
			return bad()
		}
		c.MappedWidth, c.MappedHeight = int(w), int(h)
		if id == MapSurfaceToScaledWindow {
			w, h = binary.LittleEndian.Uint32(b[18:]), binary.LittleEndian.Uint32(b[22:])
			if w == 0 || h == 0 || w > 8192 || h > 8192 {
				return bad()
			}
			c.Width, c.Height = int(w), int(h)
		}
	case CapsConfirm:
		if len(b) < 8 || uint64(binary.LittleEndian.Uint32(b[4:])) != uint64(len(b)-8) {
			return bad()
		}
		c.Capability = Capability{binary.LittleEndian.Uint32(b), append([]byte(nil), b[8:]...)}
	default:
		return Command{}, ErrUnsupported
	}
	return c, nil
}

func marshal(id uint16, b []byte) []byte {
	h := binary.LittleEndian.AppendUint16(nil, id)
	h = append(h, 0, 0)
	h = binary.LittleEndian.AppendUint32(h, uint32(8+len(b)))
	return append(h, b...)
}

// Advertise marshals capability descriptions supplied by a fully capable
// renderer. This low-level encoder does not enable GFX on an RDP session.
func Advertise(caps []Capability) ([]byte, error) {
	if len(caps) == 0 || len(caps) > 16 {
		return nil, ErrInvalid
	}
	b := binary.LittleEndian.AppendUint16(nil, uint16(len(caps)))
	seen := map[uint32]bool{}
	for _, c := range caps {
		if seen[c.Version] || len(c.Data) > 65535 {
			return nil, ErrInvalid
		}
		seen[c.Version] = true
		b = binary.LittleEndian.AppendUint32(b, c.Version)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(c.Data)))
		b = append(b, c.Data...)
	}
	return marshal(CapsAdvertise, b), nil
}

// Acknowledge encodes an acknowledgement only after the caller has decoded and
// presented the complete frame. A received EndFrame alone is insufficient.
func Acknowledge(frameID, totalDecoded, queueBytes uint32) []byte {
	b := binary.LittleEndian.AppendUint32(nil, queueBytes)
	b = binary.LittleEndian.AppendUint32(b, frameID)
	b = binary.LittleEndian.AppendUint32(b, totalDecoded)
	return marshal(FrameAcknowledge, b)
}
