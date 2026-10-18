package graphics

import (
	"encoding/binary"
	"image"
)

// PointerCacheSize matches both pointer cache sizes advertised by the client.
const PointerCacheSize = 20

const (
	LargePointer96      uint16 = 1
	LargePointer384     uint16 = 2
	MaxPointerDimension        = 384
)

type PointerKind uint8

const (
	PointerDefault PointerKind = iota
	PointerHidden
	PointerColor
)

// PointerShape stores top-down RGB XOR bytes and one AND byte (0 or 255) per
// pixel. (desktop AND mask) XOR color preserves transparent and inverted pixels,
// which cannot in general be represented by a transparent PNG cursor. When
// Alpha is nonempty, XOR contains straight RGB and AND is not used.
type PointerShape struct {
	Width, Height int
	Hotspot       image.Point
	XOR, AND      []byte
	Alpha         []byte
}

// Composite draws the shape with its hotspot at position. The destination is
// clipped to its bounds; desktop alpha is preserved.
func (s *PointerShape) Composite(dst *image.RGBA, position image.Point) error {
	if s == nil || dst == nil || s.Width < 1 || s.Height < 1 || s.Width > MaxPointerDimension || s.Height > MaxPointerDimension || len(s.XOR) != s.Width*s.Height*3 || len(s.AND) != s.Width*s.Height || len(s.Alpha) != 0 && len(s.Alpha) != s.Width*s.Height || s.Hotspot.X < 0 || s.Hotspot.Y < 0 || s.Hotspot.X >= s.Width || s.Hotspot.Y >= s.Height {
		return ErrInvalid
	}
	origin := position.Sub(s.Hotspot)
	r := image.Rect(origin.X, origin.Y, origin.X+s.Width, origin.Y+s.Height).Intersect(dst.Bounds())
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			i := (y-origin.Y)*s.Width + x - origin.X
			off := dst.PixOffset(x, y)
			for c := 0; c < 3; c++ {
				if len(s.Alpha) != 0 {
					// Match DrawIconEx: quantize the premultiplied source first,
					// then add the rounded destination contribution.
					dst.Pix[off+c] = byte(min(255, int(s.XOR[i*3+c])*int(s.Alpha[i])/255+(int(dst.Pix[off+c])*(255-int(s.Alpha[i]))+127)/255))
				} else {
					dst.Pix[off+c] = dst.Pix[off+c]&s.AND[i] ^ s.XOR[i*3+c]
				}
			}
		}
	}
	return nil
}

type PointerState struct {
	Kind        PointerKind
	Shape       *PointerShape
	Position    image.Point
	HasPosition bool
}

// PointerDecoder handles normalized pdu.Pointer payloads, including cache
// selection. Its zero value selects the default system cursor. Like Framebuffer,
// it requires caller synchronization. An invalid update leaves state unchanged.
type PointerDecoder struct {
	// Match the effective SessionInfo values after each activation. Retain
	// the decoder on reactivation; use a new decoder for a new connection.
	AllowNewPointer   bool
	LargePointerFlags uint16
	cache             [PointerCacheSize]*PointerShape
	state             PointerState
	palette           *[256][3]byte
	stats             PointerStats
}

type PointerStats struct {
	Color    uint64 `json:"color"`
	New      uint64 `json:"new"`
	Large    uint64 `json:"large"`
	Alpha    uint64 `json:"alpha"`
	Cached   uint64 `json:"cached"`
	System   uint64 `json:"system"`
	Position uint64 `json:"position"`
}

func (d *PointerDecoder) Stats() PointerStats { return d.stats }

// ApplyPalette accepts a Palette Update, before any following indexed pointers.
// Cached pointers keep the resolved colors from when their shape was received.
func (d *PointerDecoder) ApplyPalette(payload []byte) error {
	p, err := parsePalette(payload)
	if err != nil {
		return err
	}
	d.palette = p
	return nil
}

// Snapshot owns its slices; changes to it cannot corrupt cached pointer shapes.
func (d *PointerDecoder) Snapshot() PointerState {
	s := d.state
	if s.Shape != nil {
		shape := *s.Shape
		shape.XOR = append([]byte(nil), shape.XOR...)
		shape.AND = append([]byte(nil), shape.AND...)
		shape.Alpha = append([]byte(nil), shape.Alpha...)
		s.Shape = &shape
	}
	return s
}

// Apply accepts System, Position, Color, New and Cached pointer updates from
// either the slow path or the normalized fast path. Large updates use ApplyLarge.
func (d *PointerDecoder) Apply(payload []byte) error {
	if len(payload) < 4 {
		return ErrInvalid
	}
	b := payload[4:]
	u16 := binary.LittleEndian.Uint16
	switch u16(payload) {
	case 1:
		if len(b) != 4 {
			return ErrInvalid
		}
		switch binary.LittleEndian.Uint32(b) {
		case 0:
			d.state.Kind = PointerHidden
		case 0x7f00:
			d.state.Kind = PointerDefault
		default:
			return ErrUnsupported
		}
		d.state.Shape = nil
		d.stats.System++
	case 3:
		if len(b) != 4 {
			return ErrInvalid
		}
		d.state.Position = image.Pt(int(u16(b)), int(u16(b[2:])))
		d.state.HasPosition = true
		d.stats.Position++
	case 6, 8:
		depth := 24
		if u16(payload) == 8 {
			if !d.AllowNewPointer {
				return ErrUnsupported
			}
			if len(b) < 2 {
				return ErrInvalid
			}
			depth = int(u16(b))
			b = b[2:]
		}
		limit := 32
		if d.LargePointerFlags&LargePointer96 != 0 {
			limit = 96
		}
		if err := d.readShape(b, depth, limit, false); err != nil {
			return err
		}
		if u16(payload) == 6 {
			d.stats.Color++
		} else {
			d.stats.New++
		}
	case 7:
		if len(b) != 2 || int(u16(b)) >= PointerCacheSize || d.cache[u16(b)] == nil {
			return ErrInvalid
		}
		d.state.Kind, d.state.Shape = PointerColor, d.cache[u16(b)]
		d.stats.Cached++
	default:
		return ErrUnsupported
	}
	return nil
}

// ApplyLarge accepts the reassembled fast-path Large Pointer body, starting at
// xorBpp, without a fabricated slow-path message type or fast-path headers.
func (d *PointerDecoder) ApplyLarge(payload []byte) error {
	if !d.AllowNewPointer || d.LargePointerFlags&LargePointer384 == 0 {
		return ErrUnsupported
	}
	if len(payload) < 2 {
		return ErrInvalid
	}
	if err := d.readShape(payload[2:], int(binary.LittleEndian.Uint16(payload)), MaxPointerDimension, true); err != nil {
		return err
	}
	d.stats.Large++
	return nil
}

func (d *PointerDecoder) readShape(b []byte, depth, limit int, wide bool) error {
	header := 14
	if wide {
		header = 18
	}
	if len(b) < header {
		return ErrInvalid
	}
	u16 := binary.LittleEndian.Uint16
	index, hx, hy := int(u16(b)), int(u16(b[2:])), int(u16(b[4:]))
	w, h := int(u16(b[6:])), int(u16(b[8:]))
	if index >= PointerCacheSize || w < 1 || h < 1 || w > limit || h > limit || hx >= w || hy >= h {
		return ErrInvalid
	}
	switch depth {
	case 1, 4, 8, 15, 16, 24, 32:
	default:
		return ErrUnsupported
	}
	if (depth == 4 || depth == 8) && d.palette == nil {
		return ErrInvalid
	}
	wireBits := depth
	if depth == 15 {
		wireBits = 16
	}
	andStride, xorStride := ((w+15)/16)*2, ((w*wireBits+15)/16)*2
	an, xn := uint64(u16(b[10:])), uint64(u16(b[12:]))
	if wide {
		an = uint64(binary.LittleEndian.Uint32(b[10:]))
		xn = uint64(binary.LittleEndian.Uint32(b[14:]))
	}
	if (an != uint64(andStride*h) && !(depth == 32 && an == 0)) || xn != uint64(xorStride*h) || uint64(len(b)) < uint64(header)+an+xn || uint64(len(b)) > uint64(header)+an+xn+1 {
		return ErrInvalid
	}
	xor, and := b[header:header+int(xn)], b[header+int(xn):header+int(xn+an)]
	shape := &PointerShape{Width: w, Height: h, Hotspot: image.Pt(hx, hy), XOR: make([]byte, w*h*3), AND: make([]byte, w*h)}
	if depth == 32 {
		shape.Alpha = make([]byte, w*h)
	}
	alpha := false
	for y := 0; y < h; y++ {
		row := xor[(h-1-y)*xorStride:]
		for x := 0; x < w; x++ {
			i := y*w + x
			var rgb [3]byte
			switch depth {
			case 1:
				if row[x/8]&(0x80>>uint(x&7)) != 0 {
					rgb = [3]byte{255, 255, 255}
				}
			case 4:
				idx := row[x/2]
				if x&1 == 0 {
					idx >>= 4
				}
				rgb = d.palette[idx&15]
			case 8:
				rgb = d.palette[row[x]]
			case 15, 16:
				v := uint32(u16(row[x*2:]))
				rgb = [3]byte{expand5(v >> 10), expand5(v >> 5), expand5(v)}
				if depth == 16 {
					g := (v >> 5) & 63
					rgb[0], rgb[1] = expand5(v>>11), byte(g<<2|g>>4)
				}
			case 24:
				rgb = [3]byte{row[x*3+2], row[x*3+1], row[x*3]}
			case 32:
				rgb = [3]byte{row[x*4+2], row[x*4+1], row[x*4]}
				shape.Alpha[i] = row[x*4+3]
				alpha = alpha || shape.Alpha[i] != 0
			}
			copy(shape.XOR[i*3:i*3+3], rgb[:])
			if an != 0 && and[(h-1-y)*andStride+x/8]&(0x80>>uint(x&7)) != 0 {
				shape.AND[i] = 255
			}
		}
	}
	// A 32-bit color bitmap with no alpha samples and an explicit mask is
	// a legacy masked cursor. An absent mask instead preserves all-zero alpha.
	if depth == 32 && !alpha && an != 0 {
		shape.Alpha = nil
	}
	d.cache[index] = shape
	d.state.Kind, d.state.Shape = PointerColor, shape
	if len(shape.Alpha) != 0 {
		d.stats.Alpha++
	}
	return nil
}
