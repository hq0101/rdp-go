package graphics

import (
	"image"
	"sort"
)

// MS-RDPEGDI 2.2.2.2.1.1.1.4/.5. Retain owned encoded data so a changed
// count or polyline base point can be applied when CodedDeltaList is omitted.
type encodedDeltas struct{ data []byte }

func readDeltas(r *orderReader, wide bool) *encodedDeltas {
	var n int
	if wide {
		n = int(r.word())
	} else {
		n = int(r.byte())
	}
	if n > 32767 {
		r.err = ErrInvalid
		return nil
	}
	return &encodedDeltas{append([]byte(nil), r.take(n)...)}
}

func deltaReader(d *encodedDeltas) orderReader {
	if d == nil {
		return orderReader{}
	}
	return orderReader{b: d.data}
}

// Packed signed 7/15-bit integer, high-order byte first in the long form.
func (r *orderReader) packedDelta() int {
	b := r.byte()
	v := int(b & 0x3f)
	if b&0x40 != 0 {
		v -= 64
	}
	if b&0x80 != 0 {
		v = v*256 + int(r.byte())
	}
	return v
}

func signedCoord(v int) bool { return v >= -32768 && v <= 32767 }

func baseOrder(typ byte) byte {
	switch typ {
	case 15, 16, 17:
		return typ - 15
	case 18:
		return 10
	}
	return typ
}

func rectangleRegions(o drawingOrder, clip image.Rectangle) ([]image.Rectangle, error) {
	if o.count > 45 {
		return nil, ErrInvalid
	}
	r := deltaReader(o.deltas)
	zeros := r.take((int(o.count) + 1) / 2)
	if r.err != nil {
		return nil, ErrInvalid
	}
	var rects []image.Rectangle
	v := [4]int{}
	for i := 0; i < int(o.count); i++ {
		bits := zeros[i/2] << ((i & 1) * 4)
		for j := range v {
			if bits&(0x80>>j) == 0 {
				delta := r.packedDelta()
				if j < 2 {
					v[j] += delta
				} else {
					v[j] = delta // Width/height are absolute; absent means retained.
				}
			}
		}
		if r.err != nil || !signedCoord(v[0]) || !signedCoord(v[1]) || v[2] < 0 || v[3] < 0 {
			return nil, ErrInvalid
		}
		rect := image.Rect(v[0], v[1], v[0]+v[2], v[1]+v[3]).Intersect(clip)
		if !rect.Empty() {
			rects = append(rects, rect)
		}
	}
	if r.err != nil || len(r.b) != 0 {
		return nil, ErrInvalid
	}
	return unionRegions(rects), nil
}

// Clip rectangles describe one operation, so overlap must not apply an XOR (or
// another destination-dependent ROP) twice. At most 45 rectangles/90 y edges.
func unionRegions(rects []image.Rectangle) []image.Rectangle {
	ys := make([]int, 0, len(rects)*2)
	for _, r := range rects {
		ys = append(ys, r.Min.Y, r.Max.Y)
	}
	sort.Ints(ys)
	var out []image.Rectangle
	for i := 1; i < len(ys); i++ {
		y0, y1 := ys[i-1], ys[i]
		if y0 == y1 {
			continue
		}
		var band []image.Rectangle
		for _, r := range rects {
			if r.Min.Y <= y0 && r.Max.Y >= y1 {
				band = append(band, image.Rect(r.Min.X, y0, r.Max.X, y1))
			}
		}
		sort.Slice(band, func(i, j int) bool { return band[i].Min.X < band[j].Min.X })
		for j := 0; j < len(band); {
			r := band[j]
			j++
			for j < len(band) && band[j].Min.X <= r.Max.X {
				r.Max.X = max(r.Max.X, band[j].Max.X)
				j++
			}
			out = append(out, r)
		}
	}
	return out
}

func (op drawOperation) paintMulti(dst *image.RGBA) {
	base := baseOrder(op.typ)
	if base == 2 && ropDepends(op.order.rop, 2) {
		// All clipping rectangles refer to the screen before this one order.
		// Snapshot once so a preceding rectangle cannot overwrite a later source.
		op.source = image.NewRGBA(image.Rect(0, 0, op.rect.Dx(), op.rect.Dy()))
		for y := 0; y < op.rect.Dy(); y++ {
			from := dst.PixOffset(op.sourcePoint.X, op.sourcePoint.Y+y)
			copy(op.source.Pix[y*op.source.Stride:(y+1)*op.source.Stride], dst.Pix[from:from+op.source.Stride])
		}
		op.sourcePoint = image.Point{}
	}
	for _, rect := range op.regions {
		part := op
		part.typ, part.rect = base, rect
		part.sourcePoint = op.sourcePoint.Add(rect.Min.Sub(op.rect.Min))
		part.paintRect(dst)
	}
}

func lineOperation(typ byte, o drawingOrder, clip image.Rectangle) (drawOperation, error) {
	op := drawOperation{typ: typ, order: o, points: []image.Point{image.Pt(o.x, o.y)}}
	if o.rop < 1 || o.rop > 16 {
		return op, ErrInvalid
	}
	if typ == 9 {
		op.points = append(op.points, image.Pt(o.sx, o.sy))
	} else {
		var err error
		op.points, err = deltaPoints(o)
		if err != nil {
			return op, err
		}
	}
	for i := 1; i < len(op.points); i++ {
		a, b := op.points[i-1], op.points[i]
		op.work += max(absInt(b.X-a.X), absInt(b.Y-a.Y))
		if a != b {
			op.rect = op.rect.Union(image.Rect(min(a.X, b.X), min(a.Y, b.Y), max(a.X, b.X)+1, max(a.Y, b.Y)+1).Intersect(clip))
		}
	}
	return op, nil
}

func deltaPoints(o drawingOrder) ([]image.Point, error) {
	r := deltaReader(o.deltas)
	zeros := r.take((int(o.count) + 3) / 4)
	if r.err != nil {
		return nil, ErrInvalid
	}
	p := image.Pt(o.x, o.y)
	points := []image.Point{p}
	for i := 0; i < int(o.count); i++ {
		bits := zeros[i/4] << ((i & 3) * 2)
		if bits&0x80 == 0 {
			p.X += r.packedDelta()
		}
		if bits&0x40 == 0 {
			p.Y += r.packedDelta()
		}
		if r.err != nil || !signedCoord(p.X) || !signedCoord(p.Y) {
			return nil, ErrInvalid
		}
		points = append(points, p)
	}
	if len(r.b) != 0 {
		return nil, ErrInvalid
	}
	return points, nil
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// ROP2 values 1..16 encode the four-bit pen:destination truth table plus one.
func rop2(rop, pen, dst byte) byte {
	table := rop - 1
	var out byte
	for i := 0; i < 4; i++ {
		if table&(1<<i) != 0 {
			p, d := pen, dst
			if i&2 == 0 {
				p = ^p
			}
			if i&1 == 0 {
				d = ^d
			}
			out |= p & d
		}
	}
	return out
}

func (op drawOperation) paintLines(dst *image.RGBA) {
	for i := 1; i < len(op.points); i++ {
		a, b := op.points[i-1], op.points[i]
		dx, dy := absInt(b.X-a.X), absInt(b.Y-a.Y)
		sx, sy := 1, 1
		if b.X < a.X {
			sx = -1
		}
		if b.Y < a.Y {
			sy = -1
		}
		major, minor, step, shift := dx, dy, image.Pt(sx, 0), image.Pt(0, sy)
		if dy > dx {
			major, minor, step, shift = dy, dx, image.Pt(0, sy), image.Pt(sx, 0)
		}
		// Cosmetic GDI lines choose the top/left pixel at exact half-pixel ties.
		err := (major - 1) / 2
		if shift.X < 0 || shift.Y < 0 {
			err = major / 2
		}
		for n := 0; n < major; n++ {
			if a.In(op.rect) {
				at := dst.PixOffset(a.X, a.Y)
				for c := 0; c < 3; c++ {
					dst.Pix[at+c] = rop2(op.order.rop, op.order.fore[c], dst.Pix[at+c])
				}
				dst.Pix[at+3] = 255
			}
			a = a.Add(step)
			err += minor
			if err >= major {
				a = a.Add(shift)
				err -= major
			}
		}
	}
}
