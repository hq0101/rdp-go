package graphics

import (
	"encoding/binary"
	"fmt"
	"image"

	"github.com/hq0101/rdp-go/rail"
)

// The Revision 1 cache profile must match pdu.ConfirmDrawingOrders. Sizes are
// uncompressed wire bytes; decoded RGBA uses at most twice this space (16 bpp).
var cacheEntries = [3]int{120, 120, 256}
var cacheCellBytes = [3]int{1024, 4096, 16384}

type drawingOrder struct {
	x, y, w, h, sx, sy int
	rop                byte
	fore, back         [3]byte // TS_COLOR is RGB, unlike raw bitmap BGR pixels.
	bx, by             int
	style, hatch       byte
	extra              [7]byte
	cache, index       uint16
	backMode           uint16
	penWidth, count    byte
	fillMode           byte
	deltas             *encodedDeltas // Immutable wire list, retained when its field is absent.
}

type orderDecoder struct {
	last           byte
	bounds         [4]int // Inclusive, shared between order types.
	previous       [32]drawingOrder
	textPrevious   [3]glyphOrder // GlyphIndex, FastIndex and FastGlyph histories.
	glyphs         [10][254]*cachedGlyph
	fragments      [256]*glyphFragment
	cache          [3]map[uint16]*image.RGBA
	waiting        [3]*image.RGBA // Revision 2 waiting-list slot, addressed as 32767.
	stats          OrderStats
	brushes        [2][64]*cachedBrush
	palette        *[256][3]byte
	offscreen      [offscreenEntries]*image.RGBA
	offscreenSizes [offscreenEntries]int
	offscreenBytes int
	target         uint16
}

// OrderStats counts successfully applied orders for this connection. Cache-only
// batches count even when no pixels changed; failed batches never increment it.
type OrderStats struct {
	WindowOrder        uint64 `json:"window_order"`
	DstBlt             uint64 `json:"dstblt"`
	PatBlt             uint64 `json:"patblt"`
	ScrBlt             uint64 `json:"scrblt"`
	OpaqueRect         uint64 `json:"opaque_rect"`
	MemBlt             uint64 `json:"memblt"`
	Mem3Blt            uint64 `json:"mem3blt"`
	MultiDstBlt        uint64 `json:"multi_dstblt"`
	MultiPatBlt        uint64 `json:"multi_patblt"`
	MultiScrBlt        uint64 `json:"multi_scrblt"`
	MultiOpaqueRect    uint64 `json:"multi_opaque_rect"`
	LineTo             uint64 `json:"line_to"`
	Polyline           uint64 `json:"polyline"`
	PolygonSC          uint64 `json:"polygon_sc"`
	PolygonCB          uint64 `json:"polygon_cb"`
	EllipseSC          uint64 `json:"ellipse_sc"`
	EllipseCB          uint64 `json:"ellipse_cb"`
	GlyphIndex         uint64 `json:"glyph_index"`
	FastIndex          uint64 `json:"fast_index"`
	FastGlyph          uint64 `json:"fast_glyph"`
	CacheGlyph         uint64 `json:"cache_glyph"`
	CacheGlyphV2       uint64 `json:"cache_glyph_v2"`
	CachedGlyphs       uint64 `json:"cached_glyphs"`
	CacheBitmap        uint64 `json:"cache_bitmap"`
	CacheBitmapV2      uint64 `json:"cache_bitmap_v2"`
	CacheBitmapV3      uint64 `json:"cache_bitmap_v3"`
	CacheBitmapNSCodec uint64 `json:"cache_bitmap_nscodec"`
	CacheBrush         uint64 `json:"cache_brush"`
	CreateOffscreen    uint64 `json:"create_offscreen"`
	SwitchSurface      uint64 `json:"switch_surface"`
}

func (f *Framebuffer) OrderStats() OrderStats {
	if f == nil {
		return OrderStats{}
	}
	return f.orders.stats
}

type orderReader struct {
	b   []byte
	err error
}

func (r *orderReader) take(n int) []byte {
	if n < 0 || n > len(r.b) {
		r.err = ErrInvalid
		return nil
	}
	b := r.b[:n]
	r.b = r.b[n:]
	return b
}
func (r *orderReader) byte() byte {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (r *orderReader) word() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}
func (r *orderReader) coord(old int, delta bool) int {
	var v int
	if delta {
		v = old + int(int8(r.byte()))
	} else {
		v = int(int16(r.word()))
	}
	if v < -32768 || v > 32767 {
		r.err = ErrInvalid
	}
	return v
}

type drawOperation struct {
	typ         byte
	order       drawingOrder
	rect        image.Rectangle
	source      *image.RGBA // nil for ScrBlt: use framebuffer as it exists at execution.
	sourcePoint image.Point
	destination *image.RGBA
	brush       *cachedBrush
	regions     []image.Rectangle // Multi-order clipping regions or ordered shape spans.
	points      []image.Point     // Solid one-pixel line segments; final endpoint excluded.
	text        *glyphPaint
	work        int
}

// Parse and validate the entire batch before painting. Bitmap/brush cache entries
// are immutable; offscreen images are writable only during the commit below.
// Copied maps/arrays and value-type history let malformed batches roll back without
// copying the desktop or offscreen pixels. Operations retain the cache object at
// their position in the stream, even if a later order replaces/deletes that entry.
func (f *Framebuffer) applyOrders(b []byte) ([]image.Rectangle, error) {
	if len(b) < 8 || len(b) > 1<<20 {
		return nil, ErrInvalid
	}
	n := int(binary.LittleEndian.Uint16(b[4:]))
	if n > 4096 || n > len(b)-8 {
		return nil, ErrInvalid
	}
	r := orderReader{b: b[8:]}
	next := f.orders
	var copied [3]bool
	var ops []drawOperation
	var windowOrders [][]byte
	work, decoded, primitives := 0, 0, 0
	for i := 0; i < n; i++ {
		start := r.b
		flags := r.byte()
		if flags&1 == 0 {
			if flags>>2 == 0x0b {
				if f.WindowState == nil {
					return nil, fmt.Errorf("%w: RemoteApp window order", ErrUnsupported)
				}
				if len(r.b) < 2 {
					return nil, ErrInvalid
				}
				size := int(binary.LittleEndian.Uint16(r.b))
				if size < 7 || size > len(start) {
					return nil, ErrInvalid
				}
				r.take(size - 1)
				windowOrders = append(windowOrders, start[:size])
				next.stats.WindowOrder++
				continue
			}
			if !f.AllowOffscreen {
				return nil, fmt.Errorf("%w: alternate secondary order", ErrUnsupported)
			}
			if err := next.readAlternate(&r, flags, f.OffscreenDepth, &decoded); err != nil {
				return nil, err
			}
			continue
		}
		if flags&2 != 0 {
			if err := next.readCache(&r, &copied, &decoded, f.AllowBitmapCacheV3, f.AllowNSCodec, f.AllowBrushCache, f.AllowGlyphCache, f.AllowGlyphCacheV2); err != nil {
				return nil, fmt.Errorf("cache order %d: %w", i, err)
			}
			continue
		}
		dst := f.pixels
		if next.target != primarySurface {
			if !f.AllowOffscreen || next.target >= offscreenEntries || next.offscreen[next.target] == nil {
				return nil, ErrInvalid
			}
			dst = next.offscreen[next.target]
		}
		op, err := next.readPrimary(&r, flags, dst.Bounds(), f.AllowBrushCache, f.AllowOffscreen, f.AllowExtendedOrders, f.AllowGlyphCache, f.AllowShapeOrders, &decoded)
		if err != nil {
			return nil, fmt.Errorf("drawing order %d: %w", i, err)
		}
		switch op.typ {
		case 0:
			next.stats.DstBlt++
		case 1:
			next.stats.PatBlt++
		case 2:
			next.stats.ScrBlt++
		case 10:
			next.stats.OpaqueRect++
		case 13:
			next.stats.MemBlt++
		case 14:
			next.stats.Mem3Blt++
		case 15:
			next.stats.MultiDstBlt++
		case 16:
			next.stats.MultiPatBlt++
		case 17:
			next.stats.MultiScrBlt++
		case 18:
			next.stats.MultiOpaqueRect++
		case 9:
			next.stats.LineTo++
		case 22:
			next.stats.Polyline++
		case 20:
			next.stats.PolygonSC++
		case 21:
			next.stats.PolygonCB++
		case 25:
			next.stats.EllipseSC++
		case 26:
			next.stats.EllipseCB++
		case 27:
			next.stats.GlyphIndex++
		case 19:
			next.stats.FastIndex++
		case 24:
			next.stats.FastGlyph++
		}
		primitives += max(1, len(op.regions)) + len(op.points)
		if op.text != nil {
			primitives += len(op.text.glyphs)
		}
		if primitives > 65536 {
			return nil, fmt.Errorf("%w: drawing primitive limit", ErrInvalid)
		}
		work += op.work
		if work > MaxPixels {
			return nil, fmt.Errorf("%w: drawing work limit", ErrInvalid)
		}
		if !op.rect.Empty() {
			op.destination = dst
			ops = append(ops, op)
		}
	}
	if r.err != nil || len(r.b) != 0 {
		return nil, ErrInvalid
	}
	if len(windowOrders) > 0 {
		if err := f.WindowState.Apply(windowOrders...); err != nil {
			kind := ErrInvalid
			if err == rail.ErrUnsupported {
				kind = ErrUnsupported
			}
			return nil, fmt.Errorf("%w: RemoteApp window state: %w", kind, err)
		}
	}
	dirty := make([]image.Rectangle, 0, len(ops))
	for _, op := range ops {
		op.paint(op.destination)
		if op.destination == f.pixels {
			dirty = append(dirty, op.rect)
		}
	}
	f.orders = next
	return dirty, nil
}

func (d *orderDecoder) readPrimary(r *orderReader, flags byte, screen image.Rectangle, allowBrush, allowOffscreen, allowExtended, allowGlyph, allowShapes bool, decoded *int) (drawOperation, error) {
	var op drawOperation
	if flags&0x20 != 0 && flags&4 == 0 {
		return op, ErrInvalid
	}
	if flags&8 != 0 {
		d.last = r.byte()
	}
	fields := 0
	switch d.last {
	case 0:
		fields = 5
	case 1:
		fields = 12
	case 2, 10:
		fields = 7
	case 13:
		fields = 9
	case 14:
		fields = 16
	case 9:
		fields = 10
	case 15, 20, 22, 25:
		fields = 7
	case 21, 26:
		fields = 13
	case 16:
		fields = 14
	case 17, 18:
		fields = 9
	case 19, 24:
		fields = 15
	case 27:
		fields = 22
	default:
		return op, fmt.Errorf("%w: primary type %d", ErrUnsupported, d.last)
	}
	textOrder := d.last == 19 || d.last == 24 || d.last == 27
	shape := d.last == 20 || d.last == 21 || d.last == 25 || d.last == 26
	if textOrder && !allowGlyph || shape && !allowShapes || !shape && !textOrder && (d.last == 9 || d.last >= 15) && !allowExtended {
		return op, ErrUnsupported
	}
	bytes := (fields+8)/8 - int(flags>>6)
	if bytes < 0 {
		return op, ErrInvalid
	}
	var present uint32
	for i := 0; i < bytes; i++ {
		present |= uint32(r.byte()) << (8 * i)
	}
	if present>>fields != 0 {
		return op, ErrInvalid
	}
	clip := screen
	if flags&4 != 0 {
		if flags&0x20 == 0 {
			encoding := r.byte()
			for i := range d.bounds {
				if encoding&(0x10<<i) != 0 {
					d.bounds[i] = r.coord(d.bounds[i], true)
				} else if encoding&(1<<i) != 0 {
					d.bounds[i] = r.coord(d.bounds[i], false)
				}
			}
		}
		if d.bounds[2] < d.bounds[0] || d.bounds[3] < d.bounds[1] {
			return op, ErrInvalid
		}
		clip = clip.Intersect(image.Rect(d.bounds[0], d.bounds[1], d.bounds[2]+1, d.bounds[3]+1))
	}
	if textOrder {
		return d.readText(r, flags, present, clip, decoded)
	}
	if shape {
		return d.readShape(r, flags, present, clip, allowBrush)
	}
	o := d.previous[d.last]
	field := uint32(1)
	has := func() bool { v := present&field != 0; field <<= 1; return v }
	coord := func(v *int) {
		if has() {
			*v = r.coord(*v, flags&0x10 != 0)
		}
	}
	word := func(v *uint16) {
		if has() {
			*v = r.word()
		}
	}
	byteField := func(v *byte) {
		if has() {
			*v = r.byte()
		}
	}
	color := func(v *[3]byte) {
		if has() {
			copy(v[:], r.take(3))
		}
	}
	if d.last == 9 || d.last == 22 {
		if d.last == 9 {
			word(&o.backMode)
			coord(&o.x)
			coord(&o.y)
			coord(&o.sx)
			coord(&o.sy)
			color(&o.back)
			byteField(&o.rop)
			byteField(&o.style)
			byteField(&o.penWidth)
			color(&o.fore)
			if (o.backMode != 1 && o.backMode != 2) || o.back != [3]byte{} || o.style != 0 || o.penWidth != 1 {
				return op, ErrInvalid
			}
		} else {
			coord(&o.x)
			coord(&o.y)
			byteField(&o.rop)
			word(&o.cache) // Unused BrushCacheEntry, ignored by specification.
			color(&o.fore)
			byteField(&o.count)
			if has() {
				o.deltas = readDeltas(r, false)
			}
		}
		var err error
		op, err = lineOperation(d.last, o, clip)
		if r.err != nil || err != nil {
			return op, ErrInvalid
		}
		d.previous[d.last] = o
		return op, nil
	}
	base := baseOrder(d.last)
	if base == 13 || base == 14 {
		word(&o.cache)
	}
	coord(&o.x)
	coord(&o.y)
	coord(&o.w)
	coord(&o.h)
	if base == 10 {
		for i := range o.fore {
			byteField(&o.fore[i])
		}
		o.rop = 0xf0
	} else {
		byteField(&o.rop)
	}
	if base == 2 || base == 13 || base == 14 {
		coord(&o.sx)
		coord(&o.sy)
	}
	if base == 1 || base == 14 {
		color(&o.back)
		color(&o.fore)
		if has() {
			o.bx = int(int8(r.byte()))
		}
		if has() {
			o.by = int(int8(r.byte()))
		}
		byteField(&o.style)
		byteField(&o.hatch)
		if has() {
			copy(o.extra[:], r.take(7))
		}
		// SOLIDPATTERNBRUSHONLY excludes hatched/hollow brushes. Cached patterns
		// are separately negotiated through the Brush Capability Set.
		if o.style != 0 && o.style != 3 && o.style&0x80 == 0 {
			return op, fmt.Errorf("%w: brush style %d", ErrUnsupported, o.style)
		}
	}
	if base == 13 || base == 14 {
		word(&o.index)
	}
	if d.last >= 15 && d.last <= 18 {
		byteField(&o.count)
		if has() {
			o.deltas = readDeltas(r, true)
		}
	}
	if r.err != nil || o.w < 0 || o.h < 0 {
		return op, ErrInvalid
	}
	if base == 0 && (ropDepends(o.rop, 2) || ropDepends(o.rop, 4)) || (base == 2 || base == 13) && ropDepends(o.rop, 4) || base == 1 && ropDepends(o.rop, 2) {
		return op, ErrInvalid
	}
	d.previous[d.last] = o
	op = drawOperation{typ: d.last, order: o, rect: image.Rect(o.x, o.y, o.x+o.w, o.y+o.h).Intersect(clip)}
	if d.last >= 15 && d.last <= 18 {
		var err error
		op.regions, err = rectangleRegions(o, op.rect)
		if err != nil {
			return op, err
		}
		op.rect = image.Rectangle{}
		for _, rect := range op.regions {
			op.rect = op.rect.Union(rect)
		}
	}
	// Also bounds temporary source storage for overlapping screen copies.
	op.work = op.rect.Dx() * op.rect.Dy()
	if (base == 1 || base == 14) && o.style&0x80 != 0 {
		var err error
		op.brush, err = d.brush(o.style, o.hatch, allowBrush)
		if err != nil {
			return op, err
		}
	}
	if base == 2 || base == 13 || base == 14 {
		sourceBounds := screen
		sy := o.sy
		if base != 2 {
			id := int(o.cache & 255)
			if o.cache>>8 > 5 {
				return op, ErrInvalid
			}
			if id == 255 {
				if !allowOffscreen || o.index >= offscreenEntries {
					return op, ErrInvalid
				}
				op.source = d.offscreen[o.index]
			} else {
				if id >= 3 || (o.index != 32767 && int(o.index) >= cacheEntries[id]) {
					return op, ErrInvalid
				}
				op.source = d.cache[id][o.index]
				if o.index == 32767 {
					op.source = d.waiting[id]
				}
			}
			if op.source == nil {
				return op, fmt.Errorf("%w: missing bitmap cache %d/%d", ErrInvalid, id, o.index)
			}
			sourceBounds = op.source.Bounds()
			// Cached bitmap source y is measured up from its bottom edge.
			sy = sourceBounds.Dy() - o.h - o.sy
		}
		op.sourcePoint = image.Pt(o.sx+op.rect.Min.X-o.x, sy+op.rect.Min.Y-o.y)
		if !op.rect.Empty() && ropDepends(o.rop, 2) && !image.Rect(op.sourcePoint.X, op.sourcePoint.Y, op.sourcePoint.X+op.rect.Dx(), op.sourcePoint.Y+op.rect.Dy()).In(sourceBounds) {
			return op, ErrInvalid
		}
	}
	return op, nil
}

func (d *orderDecoder) readCache(r *orderReader, copied *[3]bool, decoded *int, allowV3, allowNS, allowBrush, allowGlyph, allowGlyphV2 bool) (err error) {
	// Signed orderLength excludes the six-byte header and seven historical bytes.
	// Very small Revision 2 RLE cells can have a negative encoded length.
	length := int(int16(r.word())) + 7
	extra, typ := r.word(), r.byte()
	b := r.take(length)
	if r.err != nil {
		return r.err
	}
	if typ == 3 {
		if !allowGlyph || extra&0x20 != 0 && !allowGlyphV2 {
			return ErrUnsupported
		}
		return d.readGlyphCache(b, extra, decoded)
	}
	if typ == 7 {
		if !allowBrush {
			return ErrUnsupported
		}
		return d.readBrush(b)
	}
	defer func() {
		if err == nil {
			d.stats.CacheBitmap++
		}
	}()
	if typ == 4 || typ == 5 {
		return d.readCacheV2(b, extra, typ == 5, copied, decoded)
	}
	if typ == 8 && allowV3 {
		return d.readCacheV3(b, extra, copied, decoded, allowNS)
	}
	if typ != 0 && typ != 2 {
		return fmt.Errorf("%w: secondary type %d", ErrUnsupported, typ)
	}
	if len(b) < 9 || extra & ^uint16(0x400) != 0 {
		return ErrInvalid
	}
	id, w, h, depth := int(b[0]), int(b[2]), int(b[3]), int(b[4])
	size, index := int(binary.LittleEndian.Uint16(b[5:])), binary.LittleEndian.Uint16(b[7:])
	if id >= 3 || int(index) >= cacheEntries[id] || w == 0 || h == 0 || size != len(b)-9 {
		return ErrInvalid
	}
	if depth != 16 && depth != 24 && depth != 32 {
		return ErrUnsupported
	}
	stride := (w*((depth+7)/8) + 3) &^ 3
	if stride*h > cacheCellBytes[id] {
		return ErrInvalid
	}
	*decoded += w * h
	if *decoded > MaxPixels {
		return ErrInvalid
	}
	// Cache and screen bitmaps share the wire pixel format. Reuse the validated
	// bitmap pipeline (including optional compression headers and Planar decoding).
	payload := make([]byte, 22, len(b)+13)
	binary.LittleEndian.PutUint16(payload, 1)
	binary.LittleEndian.PutUint16(payload[2:], 1)
	for off, value := range map[int]int{8: w - 1, 10: h - 1, 12: w, 14: h, 16: depth, 20: size} {
		binary.LittleEndian.PutUint16(payload[off:], uint16(value))
	}
	if typ == 2 {
		binary.LittleEndian.PutUint16(payload[18:], 1|extra)
	}
	bitmaps, err := DecodeBitmapUpdate(append(payload, b[9:]...))
	if err != nil {
		return err
	}
	if !copied[id] {
		m := make(map[uint16]*image.RGBA, len(d.cache[id])+1)
		for key, img := range d.cache[id] {
			m[key] = img
		}
		d.cache[id] = m
		copied[id] = true
	}
	d.cache[id][index] = bitmaps[0].Image
	return nil
}

func ropDepends(rop byte, input int) bool {
	for i := 0; i < 8; i++ {
		if (rop>>i)&1 != (rop>>(i^input))&1 {
			return true
		}
	}
	return false
}

// Each ROP3 bit is the truth table entry indexed by pattern:source:destination.
func rop3(rop byte, p, s, d byte) byte {
	switch rop {
	case 0:
		return 0
	case 0xff:
		return 255
	case 0xcc:
		return s
	case 0xf0:
		return p
	case 0xaa:
		return d
	case 0x55:
		return ^d
	case 0x66:
		return s ^ d
	}
	var out byte
	for i := 0; i < 8; i++ {
		if rop&(1<<i) == 0 {
			continue
		}
		a, b, c := p, s, d
		if i&4 == 0 {
			a = ^a
		}
		if i&2 == 0 {
			b = ^b
		}
		if i&1 == 0 {
			c = ^c
		}
		out |= a & b & c
	}
	return out
}

func (op drawOperation) paint(dst *image.RGBA) {
	if op.typ == 20 || op.typ == 21 || op.typ == 25 || op.typ == 26 {
		op.paintShape(dst)
		return
	}
	if op.text != nil {
		op.text.paint(dst)
		return
	}
	if op.typ == 9 || op.typ == 22 {
		op.paintLines(dst)
		return
	}
	if op.typ >= 15 && op.typ <= 18 {
		op.paintMulti(dst)
		return
	}
	op.paintRect(dst)
}

func (op drawOperation) paintRect(dst *image.RGBA) {
	src, point, o := op.source, op.sourcePoint, op.order
	needsSource := (op.typ == 2 || op.typ == 13 || op.typ == 14) && ropDepends(o.rop, 2)
	if needsSource && (src == nil || src == dst) {
		// A temporary copy gives BitBlt overlap semantics in every direction and
		// for every ROP, including operations that depend on destination pixels.
		src = image.NewRGBA(image.Rect(0, 0, op.rect.Dx(), op.rect.Dy()))
		for y := 0; y < src.Rect.Dy(); y++ {
			from := dst.PixOffset(point.X, point.Y+y)
			copy(src.Pix[y*src.Stride:(y+1)*src.Stride], dst.Pix[from:from+src.Stride])
		}
		point = image.Point{}
	}
	for y := op.rect.Min.Y; y < op.rect.Max.Y; y++ {
		for x := op.rect.Min.X; x < op.rect.Max.X; x++ {
			p := o.fore
			if op.brush != nil {
				row, col := (y-o.by)&7, (x-o.bx)&7
				if op.brush.format == 1 {
					if op.brush.mono[row]&(0x80>>col) != 0 {
						p = o.back
					}
				} else {
					p = op.brush.colors[row*8+col]
				}
			} else if o.style == 3 && (op.typ == 1 || op.typ == 14) {
				row := (y - o.by) & 7
				bits := o.hatch
				if row < 7 {
					bits = o.extra[6-row]
				}
				// Monochrome DIB brush: zero selects text/foreground; one background.
				if bits&(0x80>>((x-o.bx)&7)) != 0 {
					p = o.back
				}
			}
			i := dst.PixOffset(x, y)
			var s [3]byte
			if needsSource {
				j := src.PixOffset(point.X+x-op.rect.Min.X, point.Y+y-op.rect.Min.Y)
				copy(s[:], src.Pix[j:j+3])
			}
			for k := 0; k < 3; k++ {
				dst.Pix[i+k] = rop3(o.rop, p[k], s[k], dst.Pix[i+k])
			}
			dst.Pix[i+3] = 255
		}
	}
}
