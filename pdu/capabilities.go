package pdu

import "encoding/binary"

type Capability struct {
	Type uint16
	Data []byte
}
type Demand struct {
	ShareID                     uint32
	Source                      uint16
	Width, Height, BitsPerPixel uint16
	Capabilities                []Capability
	RefreshRect, SuppressOutput bool
	UnicodeInput                bool
	ChannelChunkSize            uint32
	ChannelCompression          bool
	BitmapCacheV2               bool
	BitmapCacheV3               bool
	SurfaceCommands             uint32
	FrameAcknowledge            bool
	NSCodec                     bool
	MultifragmentMaxRequestSize uint32
	LargePointerFlags           uint16
	AutoReconnect               bool
	RemoteApp                   RemoteAppCapabilities
}

// ParseDemand checks every capability boundary/count, including unknown types.
// Capability Data slices alias the input. Unknown capabilities are not echoed.
func ParseDemand(s Share) (Demand, error) {
	d := Demand{ChannelChunkSize: 1600}
	b := s.Body
	if s.Type != DemandActive || s.Source < 1001 || len(b) < 16 {
		return d, ErrInvalid
	}
	d.ShareID, d.Source = binary.LittleEndian.Uint32(b), s.Source
	desc, combined := int(binary.LittleEndian.Uint16(b[4:])), int(binary.LittleEndian.Uint16(b[6:]))
	if combined < 4 || 8+desc+combined+4 != len(b) {
		return d, ErrInvalid
	}
	b = b[8+desc : 8+desc+combined]
	count := int(binary.LittleEndian.Uint16(b))
	b = b[4:]
	if count > 128 {
		return d, ErrInvalid
	}
	seen := map[uint16]bool{}
	for i := 0; i < count; i++ {
		if len(b) < 4 {
			return d, ErrInvalid
		}
		typ, n := binary.LittleEndian.Uint16(b), int(binary.LittleEndian.Uint16(b[2:]))
		if n < 4 || n > len(b) || seen[typ] {
			return d, ErrInvalid
		}
		seen[typ] = true
		p := b[4:n]
		switch typ {
		case 23:
			if len(p) != 4 {
				return d, ErrInvalid
			}
			d.RemoteApp.RailSupportLevel = binary.LittleEndian.Uint32(p)
			// Defined extension bits require base RAIL support. Reserved bits
			// are retained for reporting and are never blindly echoed.
			if d.RemoteApp.RailSupportLevel&1 == 0 && d.RemoteApp.RailSupportLevel&0xfe != 0 {
				return d, ErrInvalid
			}
		case 24:
			if len(p) != 7 {
				return d, ErrInvalid
			}
			d.RemoteApp.WindowSupportLevel = binary.LittleEndian.Uint32(p)
			if d.RemoteApp.WindowSupportLevel > WindowLevelExtended {
				return d, ErrInvalid
			}
			d.RemoteApp.IconCaches = p[4]
			d.RemoteApp.IconEntries = binary.LittleEndian.Uint16(p[5:])
		case 8:
			if len(p) != 4 && len(p) != 6 {
				return d, ErrInvalid
			}
		case 26:
			if len(p) != 4 {
				return d, ErrInvalid
			}
			d.MultifragmentMaxRequestSize = binary.LittleEndian.Uint32(p)
		case 27:
			if len(p) != 2 {
				return d, ErrInvalid
			}
			d.LargePointerFlags = binary.LittleEndian.Uint16(p) & 3
		case 1:
			if len(p) < 20 || binary.LittleEndian.Uint16(p[4:]) != 0x200 {
				return d, ErrInvalid
			}
			d.RefreshRect, d.SuppressOutput = p[18] != 0, p[19] != 0
			d.AutoReconnect = binary.LittleEndian.Uint16(p[10:])&8 != 0
		case 2:
			if len(p) < 24 {
				return d, ErrInvalid
			}
			d.BitsPerPixel = binary.LittleEndian.Uint16(p)
			d.Width, d.Height = binary.LittleEndian.Uint16(p[8:]), binary.LittleEndian.Uint16(p[10:])
		case 3:
			if len(p) < 84 {
				return d, ErrInvalid
			}
			d.BitmapCacheV3 = binary.LittleEndian.Uint16(p[30:])&0x80 != 0 && binary.LittleEndian.Uint16(p[66:])&2 != 0
		case 13:
			if len(p) < 84 {
				return d, ErrInvalid
			}
			d.UnicodeInput = binary.LittleEndian.Uint16(p)&0x10 != 0
		case 20:
			if len(p) != 4 && len(p) != 8 {
				return d, ErrInvalid
			}
			d.ChannelCompression = binary.LittleEndian.Uint32(p)&2 != 0
			if len(p) == 8 {
				d.ChannelChunkSize = binary.LittleEndian.Uint32(p[4:])
				if d.ChannelChunkSize == 0 {
					return d, ErrInvalid
				}
			}
		case 18:
			if len(p) != 4 {
				return d, ErrInvalid
			}
			d.BitmapCacheV2 = p[0]&1 != 0
		case 28:
			if len(p) != 8 {
				return d, ErrInvalid
			}
			d.SurfaceCommands = binary.LittleEndian.Uint32(p)
		case 30:
			if len(p) != 4 {
				return d, ErrInvalid
			}
			d.FrameAcknowledge = true
		case 29:
			var err error
			d.NSCodec, err = parseBitmapCodecs(p)
			if err != nil {
				return d, err
			}
		}
		d.Capabilities = append(d.Capabilities, Capability{Type: typ, Data: p})
		b = b[n:]
	}
	if len(b) != 0 || !seen[1] || !seen[2] || d.Width < 200 || d.Height < 200 || d.Width > 8192 || d.Height > 8192 {
		return d, ErrInvalid
	}
	switch d.BitsPerPixel {
	case 8, 15, 16, 24, 32:
	default:
		return d, ErrInvalid
	}
	return d, nil
}

// Confirm uses a baseline bitmap profile with fast-path output: no drawing orders,
// persistent caches, bulk compression, codecs or auto-reconnect. Desktop resize
// is supported through reactivation; DisplayControl uses a separate channel.
// Bitmap/pointer data is delivered to the caller as opaque update payloads.
func Confirm(source uint16, d Demand, layout uint32) ([]byte, error) {
	return ConfirmGraphics(source, d, layout, GraphicsOptions{})
}

// ConfirmDrawingOrders enables DstBlt, PatBlt/OpaqueRect, ScrBlt, MemBlt and
// Mem3Blt with solid/monochrome pattern brushes and volatile Revision 1 caches.
// Only 24/32-bit sessions use this profile; other depths retain bitmap-only output.
// Consumers must decode every update in order with graphics.Framebuffer.Apply.
func ConfirmDrawingOrders(source uint16, d Demand, layout uint32) ([]byte, error) {
	return ConfirmGraphics(source, d, layout, GraphicsOptions{DrawingOrders: true})
}

// GraphicsOptions requests explicitly supported output paths. Effective returns
// the subset usable with the server's capabilities; caches remain volatile.
type GraphicsOptions struct {
	// AutoReconnect enables the General capability flag independently of graphics.
	AutoReconnect bool
	// BulkCompression advertises receive-side virtual channel compression.
	BulkCompression                               bool
	DrawingOrders, BitmapCacheV2, SurfaceCommands bool
	NSCodec, BitmapCacheV3                        bool
	BrushCache, OffscreenCache                    bool
	ExtendedOrders                                bool
	GlyphCache, GlyphCacheV2                      bool
	ShapeOrders                                   bool
	NewPointer, LargePointer                      bool
	// LargePointerFlags is computed by Effective; request LargePointer instead.
	LargePointerFlags uint16
}

func (g GraphicsOptions) Effective(d Demand) GraphicsOptions {
	g.AutoReconnect = g.AutoReconnect && d.AutoReconnect
	g.LargePointerFlags = 0
	if g.NewPointer && g.LargePointer {
		if d.MultifragmentMaxRequestSize >= 38055 {
			g.LargePointerFlags = d.LargePointerFlags & 1
		}
		if d.MultifragmentMaxRequestSize >= 608299 {
			g.LargePointerFlags |= d.LargePointerFlags & 2
		}
	}
	g.LargePointer = g.LargePointerFlags != 0
	g.DrawingOrders = g.DrawingOrders && (d.BitsPerPixel == 24 || d.BitsPerPixel == 32)
	g.BitmapCacheV2 = g.BitmapCacheV2 && g.DrawingOrders && d.BitmapCacheV2
	g.BitmapCacheV3 = g.BitmapCacheV3 && g.BitmapCacheV2 && d.BitmapCacheV3
	// This profile implements all three surface commands at 32-bit session depth.
	g.SurfaceCommands = g.SurfaceCommands && d.BitsPerPixel == 32 && d.SurfaceCommands&0x52 == 0x52
	g.NSCodec = g.NSCodec && g.SurfaceCommands && d.NSCodec
	// These capabilities are client-to-server only; no server echo is required.
	g.BrushCache = g.BrushCache && g.DrawingOrders
	g.OffscreenCache = g.OffscreenCache && g.DrawingOrders
	g.ExtendedOrders = g.ExtendedOrders && g.DrawingOrders
	g.ShapeOrders = g.ShapeOrders && g.DrawingOrders
	g.GlyphCache = g.GlyphCache && g.DrawingOrders
	g.GlyphCacheV2 = g.GlyphCacheV2 && g.GlyphCache
	return g
}

func ConfirmGraphics(source uint16, d Demand, layout uint32, requested GraphicsOptions) ([]byte, error) {
	return confirmGraphics(source, d, layout, requested, nil)
}

func confirmGraphics(source uint16, d Demand, layout uint32, requested GraphicsOptions, remote *RemoteAppCapabilities) ([]byte, error) {
	g := requested.Effective(d)
	orders := g.DrawingOrders
	switch d.BitsPerPixel {
	case 8, 15, 16, 24, 32:
	default:
		return nil, ErrInvalid
	}
	if d.Width < 200 || d.Height < 200 || d.Width > 8192 || d.Height > 8192 {
		return nil, ErrInvalid
	}
	if layout == 0 {
		layout = 0x409
	}
	var caps []byte
	count := uint16(0)
	add := func(typ uint16, n int) []byte {
		start := len(caps)
		caps = append(caps, make([]byte, n)...)
		binary.LittleEndian.PutUint16(caps[start:], typ)
		binary.LittleEndian.PutUint16(caps[start+2:], uint16(n))
		count++
		return caps[start:]
	}
	b := add(1, 24)
	binary.LittleEndian.PutUint16(b[4:], 1) // Windows
	binary.LittleEndian.PutUint16(b[6:], 3) // NT
	binary.LittleEndian.PutUint16(b[8:], 0x200)
	// Modern Windows requires LONG_CREDENTIALS_SUPPORTED together with fast-path.
	// The session layer validates short/long/extended Save Session Info and
	// delivers a typed notification without exposing reconnect material.
	binary.LittleEndian.PutUint16(b[14:], 0x405) // fast-path, long credentials, no bitmap compression header
	if g.AutoReconnect {
		binary.LittleEndian.PutUint16(b[14:], 0x40d)
	}
	b = add(2, 28)
	binary.LittleEndian.PutUint16(b[4:], d.BitsPerPixel)
	for _, off := range []int{6, 8, 10, 18, 20, 24} {
		binary.LittleEndian.PutUint16(b[off:], 1)
	}
	binary.LittleEndian.PutUint16(b[12:], d.Width)
	binary.LittleEndian.PutUint16(b[14:], d.Height)
	b[23] = 0x08 // Planar skip-alpha; request lossless color (no fidelity loss/subsampling).
	b = add(3, 88)
	binary.LittleEndian.PutUint16(b[24:], 1)
	binary.LittleEndian.PutUint16(b[26:], 20)
	binary.LittleEndian.PutUint16(b[30:], 1)
	binary.LittleEndian.PutUint16(b[34:], 0x0a) // required order flags, no orders supported
	if orders {
		binary.LittleEndian.PutUint16(b[34:], 0x4a) // SOLIDPATTERNBRUSHONLY; cache support is a separate capability
		for i := 0; i < 5; i++ {
			b[36+i] = 1
		} // Negotiation indices differ from encoding indices.
	}
	if g.ExtendedOrders {
		for _, i := range []int{8, 15, 16, 17, 18, 22} {
			b[36+i] = 1
		}
	}
	if g.ShapeOrders {
		for _, i := range []int{20, 21, 25, 26} {
			b[36+i] = 1
		}
	}
	if g.GlyphCache {
		for _, i := range []int{19, 24, 27} {
			b[36+i] = 1
		}
	}
	if g.BitmapCacheV3 {
		binary.LittleEndian.PutUint16(b[34:], 0xca) // extended order flags are valid
		binary.LittleEndian.PutUint16(b[70:], 2)    // Revision 3 cache; no alternate frame markers
	}
	if g.BitmapCacheV2 {
		b = add(19, 40)
		binary.LittleEndian.PutUint16(b[4:], 2) // waiting list, no persistent keys
		b[7] = 3
		for i, entries := range []uint32{120, 120, 256} {
			binary.LittleEndian.PutUint32(b[8+i*4:], entries)
		}
	} else {
		b = add(4, 40)
		if orders {
			// Matches the bounded Revision 1 profile in graphics/orders.go.
			for i, value := range []uint16{120, 1024, 120, 4096, 256, 16384} {
				binary.LittleEndian.PutUint16(b[28+i*2:], value)
			}
		}
	}
	pointerLength := 8
	if g.NewPointer {
		pointerLength = 10
	}
	b = add(8, pointerLength)
	binary.LittleEndian.PutUint16(b[4:], 1)
	binary.LittleEndian.PutUint16(b[6:], 20)
	if g.NewPointer {
		binary.LittleEndian.PutUint16(b[8:], 20)
	}
	b = add(13, 88)
	binary.LittleEndian.PutUint16(b[4:], 0x11) // scancodes and Unicode; slow-path input
	binary.LittleEndian.PutUint32(b[8:], layout)
	binary.LittleEndian.PutUint32(b[12:], 4)
	binary.LittleEndian.PutUint32(b[20:], 12)
	b = add(15, 8)
	if g.BrushCache {
		binary.LittleEndian.PutUint32(b[4:], 1)
	} // cached 8x8 color/mono patterns
	b = add(16, 52)
	if g.GlyphCache {
		for i, size := range []uint16{4, 4, 8, 8, 16, 32, 64, 128, 256, 2048} {
			entries := uint16(254)
			if i == 9 {
				entries = 64
			}
			binary.LittleEndian.PutUint16(b[4+i*4:], entries)
			binary.LittleEndian.PutUint16(b[6+i*4:], size)
		}
		binary.LittleEndian.PutUint32(b[44:], 0x01000100) // 256 fragments of up to 256 bytes.
		level := uint16(2)
		if g.GlyphCacheV2 {
			level = 3
		}
		binary.LittleEndian.PutUint16(b[48:], level)
	}
	b = add(17, 12)
	if g.OffscreenCache {
		binary.LittleEndian.PutUint32(b[4:], 1)
		binary.LittleEndian.PutUint16(b[8:], 7680) // KiB, matches graphics' budget
		binary.LittleEndian.PutUint16(b[10:], 100)
	}
	b = add(20, 12)
	if g.BulkCompression {
		binary.LittleEndian.PutUint32(b[4:], 1)
	} // VCCAPS_COMPR_SC
	binary.LittleEndian.PutUint32(b[8:], 1600) // virtual-channel chunk size
	add(12, 8)                                 // no sound beeps
	b = add(26, 8)
	binary.LittleEndian.PutUint32(b[4:], MaxFastPathUpdate)
	if g.LargePointer {
		b = add(27, 6)
		binary.LittleEndian.PutUint16(b[4:], g.LargePointerFlags)
	}
	if g.SurfaceCommands {
		b = add(28, 12)
		binary.LittleEndian.PutUint32(b[4:], 0x52)
		if d.FrameAcknowledge {
			b = add(30, 8)
			binary.LittleEndian.PutUint32(b[4:], 2)
		}
	}
	if g.NSCodec {
		b = add(29, 27)
		b[4] = 1 // one codec
		copy(b[5:21], nsCodecGUID[:])
		b[21] = 1 // fixed NSCodec ID
		binary.LittleEndian.PutUint16(b[22:], 3)
		b[24], b[25], b[26] = 0, 0, 1 // no dynamic fidelity or subsampling; minimum color loss
	}
	if remote != nil {
		b = add(23, 8)
		binary.LittleEndian.PutUint32(b[4:], remote.RailSupportLevel)
		b = add(24, 11)
		binary.LittleEndian.PutUint32(b[4:], remote.WindowSupportLevel)
		b[8] = remote.IconCaches
		binary.LittleEndian.PutUint16(b[9:], remote.IconEntries)
	}
	desc := []byte("openrdp\x00")
	body := binary.LittleEndian.AppendUint32(nil, d.ShareID)
	body = binary.LittleEndian.AppendUint16(body, 1002) // specified originatorID
	body = binary.LittleEndian.AppendUint16(body, uint16(len(desc)))
	body = binary.LittleEndian.AppendUint16(body, uint16(len(caps)+4))
	body = append(body, desc...)
	body = binary.LittleEndian.AppendUint16(body, count)
	body = append(body, 0, 0)
	return share(ConfirmActive, source, append(body, caps...))
}
