package graphics

import "image"

// Must match the client-only Glyph Cache capability in pdu. The final cache
// permits larger characters while keeping the complete cache below 264 KiB.
var glyphCellBytes = [10]int{4, 4, 8, 8, 16, 32, 64, 128, 256, 2048}

func glyphEntries(id int) int {
	if id == 9 {
		return 64
	}
	return 254
}

type cachedGlyph struct {
	x, y, w, h, stride int
	bits               []byte // Owned, immutable, byte-aligned top-down rows, MSB first.
}
type glyphFragment struct{ data []byte }
type glyphOrder struct {
	cache, accel, advance, redundant byte
	textColor, opaqueColor           [3]byte
	background, opaque               [4]int // Right/bottom exclusive, unlike order bounds.
	brushX, brushY                   int
	style, hatch                     byte
	extra                            [7]byte
	x, y                             int
	data                             *encodedDeltas
}
type positionedGlyph struct {
	glyph    *cachedGlyph
	position image.Point // Top-left bitmap position, including the signed bearing.
	rect     image.Rectangle
}
type glyphPaint struct {
	glyphs                 []positionedGlyph
	textColor, opaqueColor [3]byte
	opaque                 image.Rectangle
}

// MS-RDPEGDI TWO_BYTE_SIGNED_ENCODING uses sign/magnitude, unlike DELTA_PTS.
func (r *orderReader) compactSigned() int {
	b := r.byte()
	v := int(b & 0x3f)
	if b&0x80 != 0 {
		v = v*256 + int(r.byte())
	}
	if b&0x40 != 0 {
		v = -v
	}
	return v
}

func readGlyph(r *orderReader, id int, rev2 bool, decoded *int) (int, *cachedGlyph, error) {
	g := &cachedGlyph{}
	var index int
	if rev2 {
		index = int(r.byte())
		g.x = r.compactSigned()
		g.y = r.compactSigned()
		g.w, g.h = int(r.compactWord()), int(r.compactWord())
	} else {
		index = int(r.word())
		g.x, g.y = int(int16(r.word())), int(int16(r.word()))
		g.w, g.h = int(r.word()), int(r.word())
	}
	if r.err != nil || id < 0 || id >= 10 || index >= glyphEntries(id) || g.w > maxDimension || g.h > maxDimension {
		return 0, nil, ErrInvalid
	}
	g.stride = (g.w + 7) / 8
	size := (g.stride*g.h + 3) &^ 3
	if size > glyphCellBytes[id] {
		return 0, nil, ErrInvalid
	}
	*decoded += max(1, g.w*g.h)
	if *decoded > MaxPixels {
		return 0, nil, ErrInvalid
	}
	b := r.take(size)
	if r.err != nil {
		return 0, nil, ErrInvalid
	}
	g.bits = append([]byte(nil), b[:g.stride*g.h]...)
	return index, g, nil
}

func (d *orderDecoder) readGlyphCache(b []byte, extra uint16, decoded *int) error {
	r := orderReader{b: b}
	rev2 := extra&0x20 != 0
	var id, count int
	var unicode bool
	if rev2 {
		if extra&0xc0 != 0 {
			return ErrInvalid
		}
		id, count = int(extra&15), int(extra>>8)
		unicode = extra&0x10 != 0
	} else {
		// The normative Rev1 table uses 0x100; Microsoft's annotated Rev1
		// packet uses 0x10. Both indicate the same diagnostic-only suffix.
		if extra&^uint16(0x110) != 0 {
			return ErrInvalid
		}
		id, count = int(r.byte()), int(r.byte())
		unicode = extra&0x110 != 0
	}
	if r.err != nil || id >= 10 {
		return ErrInvalid
	}
	for i := 0; i < count; i++ {
		index, g, err := readGlyph(&r, id, rev2, decoded)
		if err != nil {
			return err
		}
		d.glyphs[id][index] = g
	}
	if unicode {
		r.take(count * 2)
	} // Diagnostic-only UTF-16 values, not font data.
	if r.err != nil || len(r.b) != 0 {
		return ErrInvalid
	}
	d.stats.CacheGlyph++
	if rev2 {
		d.stats.CacheGlyphV2++
	}
	d.stats.CachedGlyphs += uint64(count)
	return nil
}

func (d *orderDecoder) readText(r *orderReader, flags byte, present uint32, clip image.Rectangle, decoded *int) (drawOperation, error) {
	op := drawOperation{typ: d.last}
	history := 0
	if d.last == 19 {
		history = 1
	}
	if d.last == 24 {
		history = 2
	}
	o := d.textPrevious[history]
	field := uint32(1)
	has := func() bool { v := present&field != 0; field <<= 1; return v }
	bfield := func(v *byte) {
		if has() {
			*v = r.byte()
		}
	}
	color := func(v *[3]byte) {
		if has() {
			copy(v[:], r.take(3))
		}
	}
	coord := func(v *int) {
		if has() {
			*v = r.coord(*v, d.last != 27 && flags&0x10 != 0)
		}
	}
	bfield(&o.cache)
	if d.last == 27 {
		bfield(&o.accel)
		bfield(&o.advance)
		bfield(&o.redundant)
	} else if has() {
		v := r.word()
		o.accel, o.advance = byte(v>>8), byte(v)
	}
	color(&o.textColor)
	color(&o.opaqueColor)
	for i := range o.background {
		coord(&o.background[i])
	}
	for i := range o.opaque {
		coord(&o.opaque[i])
	}
	if d.last == 27 {
		if has() {
			o.brushX = int(int8(r.byte()))
		}
		if has() {
			o.brushY = int(int8(r.byte()))
		}
		bfield(&o.style)
		bfield(&o.hatch)
		if has() {
			copy(o.extra[:], r.take(7))
		}
		if o.style != 0 || o.hatch != 0 || o.redundant > 1 {
			return op, ErrInvalid
		}
	}
	coord(&o.x)
	coord(&o.y)
	if has() {
		o.data = readDeltas(r, false)
	}
	if r.err != nil || o.cache >= 10 || o.accel&1 == 0 || o.accel&0x80 != 0 || o.accel&6 == 6 {
		return op, ErrInvalid
	}
	bg, opaque := o.background, o.opaque
	if bg[0] > bg[2] || bg[1] > bg[3] {
		return op, ErrInvalid
	}
	x, y := o.x, o.y
	if d.last != 27 {
		if x == -32768 {
			x = bg[0]
		}
		if y == -32768 {
			y = bg[1]
		}
		if opaque[3] == -32768 {
			encoding := opaque[1] & 15
			if encoding != 15 && encoding != 13 {
				return op, ErrInvalid
			}
			opaque[0], opaque[1], opaque[3] = bg[0], bg[1], bg[3]
			if encoding == 15 {
				opaque[2] = bg[2]
			}
		} else {
			if opaque[0] == 0 {
				opaque[0] = bg[0]
			}
			if opaque[2] == 0 {
				opaque[2] = bg[2]
			}
		}
	} else if o.redundant != 0 {
		// The wire requires zeros for a redundant (transparent) opaque rectangle.
		if opaque != [4]int{} {
			return op, ErrInvalid
		}
	}
	p := &glyphPaint{textColor: o.textColor, opaqueColor: o.opaqueColor}
	if o.redundant == 0 {
		if opaque[0] > opaque[2] || opaque[1] > opaque[3] {
			return op, ErrInvalid
		}
		p.opaque = image.Rect(opaque[0], opaque[1], opaque[2], opaque[3]).Intersect(clip)
	}
	op.text, op.rect = p, p.opaque
	op.work = p.opaque.Dx() * p.opaque.Dy()
	data := deltaReader(o.data).b
	position := image.Pt(x, y)
	advance := func(n int) {
		if o.accel&8 != 0 {
			n = -n
		}
		if o.accel&4 != 0 {
			position.Y += n
		} else {
			position.X += n
		}
	}
	appendGlyph := func(index int) error {
		if index < 0 || index >= glyphEntries(int(o.cache)) {
			return ErrInvalid
		}
		g := d.glyphs[o.cache][index]
		if g == nil {
			return ErrInvalid
		}
		at := position.Add(image.Pt(g.x, g.y))
		rect := image.Rect(at.X, at.Y, at.X+g.w, at.Y+g.h).Intersect(clip)
		op.work += max(1, rect.Dx()*rect.Dy())
		if op.work > MaxPixels || len(p.glyphs) >= 65536 {
			return ErrInvalid
		}
		p.glyphs = append(p.glyphs, positionedGlyph{g, at, rect})
		op.rect = op.rect.Union(rect)
		return nil
	}
	if d.last == 24 {
		if len(data) == 0 {
			return op, ErrInvalid
		}
		index := int(data[0])
		if len(data) > 1 {
			gr := orderReader{b: data}
			var g *cachedGlyph
			var err error
			index, g, err = readGlyph(&gr, int(o.cache), true, decoded)
			if err != nil {
				return op, err
			}
			gr.take(2) // Padding/optional diagnostic Unicode character.
			if gr.err != nil || len(gr.b) != 0 {
				return op, ErrInvalid
			}
			d.glyphs[o.cache][index] = g
			d.stats.CachedGlyphs++
		}
		if err := appendGlyph(index); err != nil {
			return op, err
		}
	} else {
		explicit := o.advance == 0 && o.accel&0x20 == 0
		// A fragment contains only glyph indices/deltas, never recursive USE/ADD.
		consumeGlyph := func(gr *orderReader) error {
			index := int(gr.byte())
			if index >= 254 {
				return ErrInvalid
			}
			if explicit {
				advance(gr.glyphDelta())
			}
			if gr.err != nil {
				return ErrInvalid
			}
			if err := appendGlyph(index); err != nil {
				return err
			}
			if o.advance != 0 {
				advance(int(o.advance))
			} else if o.accel&0x20 != 0 {
				g := d.glyphs[o.cache][index]
				if o.accel&4 != 0 {
					advance(g.h)
				} else {
					advance(g.w)
				}
			}
			return nil
		}
		gr := orderReader{b: data}
		runStart := 0
		fragmentOrigin := position
		for len(gr.b) > 0 && gr.err == nil {
			pos := len(data) - len(gr.b)
			switch gr.b[0] {
			case 0xfe:
				gr.byte()
				index := gr.byte()
				fragment := d.fragments[index]
				if fragment == nil {
					return op, ErrInvalid
				}
				if explicit {
					// USE deltas are measured between fragment origins, not from
					// the last glyph of the preceding fragment (MS-RDPEGDI 2.2.2.2.1.1.2.13).
					position = fragmentOrigin
					advance(gr.glyphDelta())
				}
				if gr.err != nil {
					return op, ErrInvalid
				}
				fragmentOrigin = position
				fr := orderReader{b: fragment.data}
				for len(fr.b) > 0 {
					if err := consumeGlyph(&fr); err != nil {
						return op, err
					}
				}
				runStart = len(data) - len(gr.b)
			case 0xff:
				gr.byte()
				index, size := gr.byte(), int(gr.byte())
				if gr.err != nil || size == 0 || size != pos-runStart {
					return op, ErrInvalid
				}
				d.fragments[index] = &glyphFragment{append([]byte(nil), data[runStart:pos]...)}
				runStart = len(data) - len(gr.b)
			default:
				if pos == runStart {
					fragmentOrigin = position
				}
				if err := consumeGlyph(&gr); err != nil {
					return op, err
				}
			}
		}
		if gr.err != nil {
			return op, ErrInvalid
		}
	}
	d.textPrevious[history] = o
	return op, nil
}

func (r *orderReader) glyphDelta() int {
	b := r.byte()
	if b == 0x80 {
		return int(r.word())
	}
	if b > 0x80 {
		r.err = ErrInvalid
	}
	return int(b)
}

func (p *glyphPaint) paint(dst *image.RGBA) {
	fill := drawOperation{typ: 10, order: drawingOrder{fore: p.opaqueColor, rop: 0xf0}, rect: p.opaque}
	fill.paintRect(dst)
	for _, item := range p.glyphs {
		g := item.glyph
		for y := item.rect.Min.Y; y < item.rect.Max.Y; y++ {
			for x := item.rect.Min.X; x < item.rect.Max.X; x++ {
				gx, gy := x-item.position.X, y-item.position.Y
				if g.bits[gy*g.stride+gx/8]&(0x80>>(gx&7)) != 0 {
					i := dst.PixOffset(x, y)
					copy(dst.Pix[i:i+3], p.textColor[:])
					dst.Pix[i+3] = 255
				}
			}
		}
	}
}
