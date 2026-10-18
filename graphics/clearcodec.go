package graphics

import (
	"image"
	"math/bits"
)

const maxClearInput = 64 << 20
const maxClearWork = 64 << 20

// Cache pages and their pixel slices are immutable after a successful Decode.
// Updating a slot copies just its page, so copying a decoder is a cheap fork,
// including when an enclosing graphics message must roll back several bitmaps.
type clearPage [256][]byte

// ClearDecoder decodes MS-RDPEGFX ClearCodec, including residual runs, bands,
// glyphs, raw/NSCodec/RLEX subcodecs and the session-wide sequence number.
// The zero value starts a new session. Keep one decoder across surfaces and
// graphics resets. Calls on a single value must be serialized. A value copy is
// an independent fork; input and returned images never alias cached pixels.
// Dimensions are limited to 8192 per axis and MaxPixels. Unwritten pixels in
// optional layers are initialized to opaque black.
type ClearDecoder struct {
	seq                  byte
	vCursor, shortCursor int
	vbars                [128]*clearPage // 32768 columns, at most 52 pixels each
	short                [64]*clearPage  // 16384 columns
	glyphs               [16]*clearPage  // first 4000 slots, at most 1024 pixels each
}

// Reset discards session history. CACHE_RESET on the wire only rewinds the two
// column insertion cursors; it does not discard glyphs, columns, or sequencing.
func (d *ClearDecoder) Reset() { *d = ClearDecoder{} }

func (d *ClearDecoder) Decode(src []byte, width, height int) (*image.NRGBA, error) {
	img, _, err := d.DecodeWithBudget(src, width, height, maxClearWork)
	return img, err
}

// DecodeWithBudget also bounds pixel work across overlapping layers, cache
// insertions and subcodec expansion. It returns consumed work on success. A
// caller processing multiple bitmaps can share a budget. The budget must be in
// [0, 64 Mi]; errors return no image/work and leave all decoder state unchanged.
func (d *ClearDecoder) DecodeWithBudget(src []byte, width, height, budget int) (*image.NRGBA, int, error) {
	if !codecDimensions(width, height) || len(src) < 2 || len(src) > maxClearInput || budget < 0 || budget > maxClearWork {
		return nil, 0, ErrInvalid
	}
	t := clearTransaction{next: *d, remaining: budget}
	img, err := t.decode(src, width, height)
	if err != nil {
		return nil, 0, err
	}
	*d = t.next
	return img, budget - t.remaining, nil
}

type clearTransaction struct {
	next      ClearDecoder
	dirty     [3][128]bool
	remaining int
}

func (t *clearTransaction) spend(n int) bool {
	if n < 0 || n > t.remaining {
		return false
	}
	t.remaining -= n
	return true
}

func (d *ClearDecoder) pages(kind int) []*clearPage {
	switch kind {
	case 0:
		return d.vbars[:]
	case 1:
		return d.short[:]
	default:
		return d.glyphs[:]
	}
}

func (d *ClearDecoder) cached(kind, slot int) []byte {
	p := d.pages(kind)[slot/256]
	if p == nil {
		return nil
	}
	return p[slot%256]
}

// pixels must be newly allocated and must not be returned to a caller.
func (t *clearTransaction) store(kind, slot int, pixels []byte) {
	pages := t.next.pages(kind)
	i := slot / 256
	if !t.dirty[kind][i] {
		p := new(clearPage)
		if pages[i] != nil {
			*p = *pages[i]
		}
		pages[i] = p
		t.dirty[kind][i] = true
	}
	pages[i][slot%256] = pixels
}

func (t *clearTransaction) decode(src []byte, w, h int) (*image.NRGBA, error) {
	r := clearReader{data: src}
	flags, seq := r.u8(), r.u8()
	if flags & ^byte(7) != 0 || flags&2 != 0 && flags&1 == 0 || seq != t.next.seq {
		return nil, ErrInvalid
	}
	t.next.seq++
	if flags&4 != 0 {
		t.next.vCursor, t.next.shortCursor = 0, 0
	}
	n := w * h
	if !t.spend(n) {
		return nil, ErrInvalid
	}
	slot := -1
	if flags&1 != 0 {
		slot = int(r.u16())
		if r.bad || slot >= 4000 || n > 1024 {
			return nil, ErrInvalid
		}
	}
	if flags&2 != 0 {
		pixels := t.next.cached(2, slot)
		if len(r.data) != 0 || len(pixels) != n*4 {
			return nil, ErrInvalid
		}
		// Glyph storage contains a linear pixel sequence, not fixed dimensions.
		img := image.NewNRGBA(image.Rect(0, 0, w, h))
		copy(img.Pix, pixels)
		return img, nil
	}
	residualLen, bandsLen, subLen := r.u32(), r.u32(), r.u32()
	if r.bad || uint64(residualLen)+uint64(bandsLen)+uint64(subLen) != uint64(len(r.data)) {
		return nil, ErrInvalid
	}
	residual, bands, sub := r.take(int(residualLen)), r.take(int(bandsLen)), r.take(int(subLen))
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	if !t.residual(residual, img.Pix) || !t.bands(bands, img) || !t.subcodecs(sub, img) {
		return nil, ErrInvalid
	}
	if slot >= 0 {
		if !t.spend(n) {
			return nil, ErrInvalid
		}
		t.store(2, slot, append([]byte(nil), img.Pix...))
	}
	return img, nil
}

func (t *clearTransaction) residual(src, dst []byte) bool {
	r := clearReader{data: src}
	pos := 0
	for len(r.data) != 0 && !r.bad {
		b, g, red := r.u8(), r.u8(), r.u8()
		n := r.run((len(dst) - pos) / 4)
		// A zero-length segment still consumes work, preventing free parser loops.
		if r.bad || !t.spend(n+1) {
			return false
		}
		for end := pos + n*4; pos < end; pos += 4 {
			dst[pos], dst[pos+1], dst[pos+2] = red, g, b
		}
	}
	return !r.bad
}

func (t *clearTransaction) bands(src []byte, img *image.NRGBA) bool {
	r := clearReader{data: src}
	for len(r.data) != 0 && !r.bad {
		x0, x1, y0, y1 := int(r.u16()), int(r.u16()), int(r.u16()), int(r.u16())
		b, g, red := r.u8(), r.u8(), r.u8()
		height := y1 - y0 + 1
		if r.bad || x1 < x0 || y1 < y0 || x1 >= img.Rect.Dx() || y1 >= img.Rect.Dy() || height > 52 || !t.spend((x1-x0+1)*height) {
			return false
		}
		for x := x0; x <= x1; x++ {
			head := r.u16()
			if r.bad {
				return false
			}
			var column []byte
			if head&0x8000 != 0 {
				column = t.next.cached(0, int(head&0x7fff))
				if len(column) != height*4 {
					return false
				}
			} else {
				var short []byte
				var start int
				if head&0x4000 != 0 {
					start = int(r.u8())
					short = t.next.cached(1, int(head&0x3fff))
					if r.bad || short == nil || start+len(short)/4 > height {
						return false
					}
				} else {
					start = int(head & 255)
					end := int(head >> 8)
					if end < start || end > height || t.next.shortCursor >= 16384 || !t.spend(end-start) {
						return false
					}
					pixels := r.take((end - start) * 3)
					if r.bad {
						return false
					}
					short = make([]byte, (end-start)*4)
					for i := 0; i < end-start; i++ {
						short[i*4], short[i*4+1], short[i*4+2], short[i*4+3] = pixels[i*3+2], pixels[i*3+1], pixels[i*3], 255
					}
					t.store(1, t.next.shortCursor, short)
					t.next.shortCursor++
				}
				if !t.spend(height) {
					return false
				}
				column = make([]byte, height*4)
				for y := 0; y < height; y++ {
					column[y*4], column[y*4+1], column[y*4+2], column[y*4+3] = red, g, b, 255
				}
				copy(column[start*4:], short)
				t.store(0, t.next.vCursor, column)
				t.next.vCursor = (t.next.vCursor + 1) & 32767
			}
			for y := 0; y < height; y++ {
				i := img.PixOffset(x, y0+y)
				copy(img.Pix[i:i+4], column[y*4:y*4+4])
			}
		}
	}
	return !r.bad
}

func (t *clearTransaction) subcodecs(src []byte, img *image.NRGBA) bool {
	r := clearReader{data: src}
	for len(r.data) != 0 && !r.bad {
		x, y, w, h := int(r.u16()), int(r.u16()), int(r.u16()), int(r.u16())
		size, kind := r.u32(), r.u8()
		if r.bad || w < 1 || h < 1 || x+w > img.Rect.Dx() || y+h > img.Rect.Dy() || uint64(size) > uint64(w*h*3) || uint64(size) > uint64(len(r.data)) || !t.spend(w*h) {
			return false
		}
		data := r.take(int(size))
		switch kind {
		case 0:
			if len(data) != w*h*3 {
				return false
			}
			for yy := 0; yy < h; yy++ {
				for xx := 0; xx < w; xx++ {
					i, j := img.PixOffset(x+xx, y+yy), (yy*w+xx)*3
					img.Pix[i], img.Pix[i+1], img.Pix[i+2] = data[j+2], data[j+1], data[j]
				}
			}
		case 1:
			// NSCodec's four planes and chroma padding need additional work.
			if !t.spend(w * h * 8) {
				return false
			}
			decoded, err := decodeNSCodec(data, w, h, true)
			if err != nil {
				return false
			}
			for yy := 0; yy < h; yy++ {
				for xx := 0; xx < w; xx++ {
					i, j := img.PixOffset(x+xx, y+yy), decoded.PixOffset(xx, yy)
					// NSCodec's inverse transform already returns RGB. Unlike the
					// raw subcodec's BGR bytes, it requires no channel swap.
					img.Pix[i], img.Pix[i+1], img.Pix[i+2] = decoded.Pix[j], decoded.Pix[j+1], decoded.Pix[j+2]
				}
			}
		case 2:
			if !t.rlex(data, img, image.Rect(x, y, x+w, y+h)) {
				return false
			}
		default:
			return false
		}
	}
	return !r.bad
}

func (t *clearTransaction) rlex(src []byte, img *image.NRGBA, rect image.Rectangle) bool {
	r := clearReader{data: src}
	count := int(r.u8())
	if r.bad || count == 0 || count > 127 {
		return false
	}
	palette := r.take(count * 3)
	if r.bad {
		return false
	}
	indexBits := bits.Len(uint(count - 1))
	mask := (1 << indexBits) - 1
	pos, n := 0, rect.Dx()*rect.Dy()
	put := func(index int) {
		i := img.PixOffset(rect.Min.X+pos%rect.Dx(), rect.Min.Y+pos/rect.Dx())
		img.Pix[i], img.Pix[i+1], img.Pix[i+2] = palette[index*3+2], palette[index*3+1], palette[index*3]
		pos++
	}
	for len(r.data) != 0 && !r.bad {
		head := int(r.u8())
		stop, depth := head&mask, head>>indexBits
		start := stop - depth
		run := r.run(n - pos)
		if r.bad || start < 0 || stop >= count || depth+1 > n-pos-run || !t.spend(run+depth+1) {
			return false
		}
		for i := 0; i < run; i++ {
			put(start)
		}
		// The suite includes BOTH endpoints, even when depth is zero.
		for i := start; i <= stop; i++ {
			put(i)
		}
	}
	return !r.bad && pos == n
}
