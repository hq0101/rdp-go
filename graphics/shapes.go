package graphics

import (
	"image"
	"math"
	"sort"
)

func (d *orderDecoder) readShape(r *orderReader, flags byte, present uint32, clip image.Rectangle, allowBrush bool) (drawOperation, error) {
	typ := d.last
	o := d.previous[typ]
	field := uint32(1)
	has := func() bool { v := present&field != 0; field <<= 1; return v }
	coord := func(v *int) {
		if has() {
			*v = r.coord(*v, flags&0x10 != 0)
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
	coord(&o.x)
	coord(&o.y)
	polygon := typ == 20 || typ == 21
	colored := typ == 21 || typ == 26
	if !polygon {
		coord(&o.sx)
		coord(&o.sy)
	} // Inclusive right/bottom, not size.
	byteField(&o.rop)
	byteField(&o.fillMode)
	if colored {
		color(&o.back)
	}
	color(&o.fore)
	if colored {
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
	}
	if polygon {
		byteField(&o.count)
		if has() {
			o.deltas = readDeltas(r, false)
		}
	}
	op := drawOperation{typ: typ, order: o}
	mask := byte(0x1f)
	if colored {
		mask = 0x9f
	}
	if r.err != nil || o.rop&^mask != 0 || o.rop&31 < 1 || o.rop&31 > 16 || o.fillMode > 2 || polygon && o.fillMode == 0 || typ == 26 && o.fillMode == 0 {
		return op, ErrInvalid
	}
	if colored {
		if o.style != 0 && o.style != 3 && o.style&0x80 == 0 {
			return op, ErrUnsupported
		}
		if o.style&0x80 != 0 {
			var err error
			op.brush, err = d.brush(o.style, o.hatch, allowBrush)
			if err != nil {
				return op, err
			}
		}
	}
	var err error
	if polygon {
		op.points, err = deltaPoints(o)
		if err != nil || len(op.points) < 2 {
			return op, ErrInvalid
		}
		err = op.polygonSpans(clip)
	} else {
		if o.sx < o.x || o.sy < o.y {
			return op, ErrInvalid
		}
		err = op.ellipseSpans(clip)
	}
	if err != nil {
		return op, err
	}
	d.previous[typ] = o
	return op, nil
}

type shapeCrossing struct {
	num, den  int64
	direction int
}

func ceilRatio(num, den int64) int {
	q := num / den
	if num%den > 0 {
		q++
	}
	return int(q)
}
func (op *drawOperation) addSpan(left, right, y int, clip image.Rectangle) error {
	left = max(left, clip.Min.X)
	right = min(right, clip.Max.X)
	if left >= right || y < clip.Min.Y || y >= clip.Max.Y {
		return nil
	}
	op.work += right - left
	if op.work > MaxPixels || len(op.regions) >= 65536 {
		return ErrInvalid
	}
	span := image.Rect(left, y, right, y+1)
	op.regions = append(op.regions, span)
	op.rect = op.rect.Union(span)
	return nil
}

// Integer scan conversion, with top/left included and bottom/right excluded.
// Rational crossings avoid float rounding at large/signed coordinates. Equal
// crossings are processed together, so self-intersections apply a ROP only once.
func (op *drawOperation) polygonSpans(clip image.Rectangle) error {
	points := op.points
	top, bottom := points[0].Y, points[0].Y
	for _, p := range points {
		top = min(top, p.Y)
		bottom = max(bottom, p.Y)
	}
	top = max(top, clip.Min.Y)
	bottom = min(bottom, clip.Max.Y)
	if bottom <= top || clip.Empty() {
		return nil
	}
	op.work += (bottom - top) * len(points)
	if op.work > MaxPixels {
		return ErrInvalid
	}
	crossings := make([]shapeCrossing, 0, len(points))
	for y := top; y < bottom; y++ {
		crossings = crossings[:0]
		for i, a := range points {
			b := points[(i+1)%len(points)]
			direction := 1
			if a.Y > b.Y {
				a, b = b, a
				direction = -1
			}
			if y < a.Y || y >= b.Y {
				continue
			}
			dy, dx := int64(b.Y-a.Y), int64(b.X-a.X)
			crossings = append(crossings, shapeCrossing{int64(a.X)*dy + int64(y-a.Y)*dx, dy, direction})
		}
		sort.Slice(crossings, func(i, j int) bool { return crossings[i].num*crossings[j].den < crossings[j].num*crossings[i].den })
		winding := 0
		for i := 0; i < len(crossings); {
			c := crossings[i]
			j := i
			for j < len(crossings) && c.num*crossings[j].den == crossings[j].num*c.den {
				winding += crossings[j].direction
				j++
			}
			inside := winding != 0
			if op.order.fillMode == 1 {
				inside = winding&1 != 0
			}
			if inside && j < len(crossings) {
				if err := op.addSpan(ceilRatio(c.num, c.den), ceilRatio(crossings[j].num, crossings[j].den), y, clip); err != nil {
					return err
				}
			}
			i = j
		}
	}
	return nil
}

// Cubic ellipse path in 28.4 device coordinates. The four quarter curves
// use the standard circular cubic coefficient; asymmetric fixed-point rounding
// and half-pixel flattening preserve the cosmetic GDI raster convention.
func ellipsePath(o drawingOrder) []image.Point {
	l, t, r, b := float64(o.x*16), float64(o.y*16), float64(o.sx*16), float64(o.sy*16)
	cx, cy := (l+r)/2, (t+b)/2
	const corner = 0.44771525016920655 // 1 - 4*(sqrt(2)-1)/3.
	xInset := math.Floor((r - l) / 2 * corner)
	yInset := math.Ceil((b - t) / 2 * corner)
	controls := [][2]float64{{r, cy}, {r, t + yInset}, {r - xInset, t}, {cx, t}, {l + xInset, t}, {l, t + yInset}, {l, cy}, {l, b - yInset}, {l + xInset, b}, {cx, b}, {r - xInset, b}, {r, b - yInset}, {r, cy}}
	path := []image.Point{image.Pt(int(r), int(cy))}
	var flatten func([4][2]float64)
	flatten = func(p [4][2]float64) {
		flat := true
		for j := 0; j < 2; j++ {
			for k := 0; k < 2; k++ {
				if math.Abs(p[j][k]-2*p[j+1][k]+p[j+2][k]) > 32.0/3.0 {
					flat = false
				}
			}
		}
		if flat {
			path = append(path, image.Pt(int(math.Floor(p[3][0]+.5)), int(math.Floor(p[3][1]+.5))))
			return
		}
		mid := func(a, b [2]float64) [2]float64 { return [2]float64{(a[0] + b[0]) / 2, (a[1] + b[1]) / 2} }
		a, b, c := mid(p[0], p[1]), mid(p[1], p[2]), mid(p[2], p[3])
		d, e := mid(a, b), mid(b, c)
		f := mid(d, e)
		flatten([4][2]float64{p[0], a, d, f})
		flatten([4][2]float64{f, e, c, p[3]})
	}
	for i := 0; i < 12; i += 3 {
		flatten([4][2]float64{controls[i], controls[i+1], controls[i+2], controls[i+3]})
	}
	return path
}

func floorRatio(n, d int64) int {
	q := n / d
	if n%d < 0 {
		q--
	}
	return int(q)
}

// Quantize the endpoint's half-pixel diamond to the major-axis grid. Exact
// corners use GIQ's top/left preference, with separate 45-degree tie rules.
func fixedEndpoint(major, minor int, diagonal bool, minorDelta, direction int) int {
	base := floorRatio(int64(major), 16)
	fraction := major - base*16
	nearest := floorRatio(int64(minor+7), 16)
	offset := absInt(minor - nearest*16)
	sum := fraction + offset
	roundEqual := offset > 0 && offset < 8 || offset == 0 && direction < 0
	if diagonal {
		roundEqual = offset < 8 && (minorDelta > 0 || minor-nearest*16 < 0)
	}
	if sum > 8 || sum == 8 && roundEqual {
		base++
	}
	return base
}

func fixedLine(a, b image.Point, mark func(int, int)) int {
	if a == b {
		return 0
	}
	vertical := absInt(b.Y-a.Y) > absInt(b.X-a.X)
	p, q := a, b
	if vertical {
		p = image.Pt(a.Y, a.X)
		q = image.Pt(b.Y, b.X)
	}
	direction := 1
	if p.X > q.X {
		direction = -1
		p.X = -p.X
		q.X = -q.X
	}
	start, end := fixedEndpoint(p.X, p.Y, absInt(q.Y-p.Y) == q.X-p.X, q.Y-p.Y, direction), fixedEndpoint(q.X, q.Y, absInt(q.Y-p.Y) == q.X-p.X, q.Y-p.Y, direction)

	den := int64(q.X - p.X)
	for major := start; major < end; major++ {
		num := int64(p.Y)*den + int64(major*16-p.X)*int64(q.Y-p.Y)
		minor := floorRatio(num+8*den-1, 16*den)
		x, y := major*direction, minor
		if vertical {
			x, y = y, x
		}
		mark(x, y)
	}
	return max(0, end-start)
}

func (op *drawOperation) ellipseSpans(clip image.Rectangle) error {
	o := op.order
	if o.sx == o.x && o.sy == o.y || clip.Empty() {
		return nil
	}
	top, bottom := max(o.y, clip.Min.Y), min(o.sy+1, clip.Max.Y)
	if bottom <= top {
		return nil
	}
	// Each half of a convex ellipse has one contiguous boundary run per row.
	rows := make([][4]int, bottom-top)
	for i := range rows {
		rows[i] = [4]int{o.sx + 1, o.x - 1, o.sx + 1, o.x - 1}
	}
	mark := func(x, y int) {
		if y < top || y >= bottom || x < o.x || x > o.sx {
			return
		}
		side := 0
		if x*2 > o.x+o.sx {
			side = 2
		}
		row := &rows[y-top]
		row[side] = min(row[side], x)
		row[side+1] = max(row[side+1], x)
	}
	path := ellipsePath(o)
	for i := 1; i < len(path); i++ {
		a, b := path[i-1], path[i]
		if a == b {
			continue
		}
		op.work += fixedLine(a, b, mark)
		if op.work > MaxPixels {
			return ErrInvalid
		}
	}
	if o.fillMode != 0 {
		op.work += (bottom - top) * len(path)
		if op.work > MaxPixels {
			return ErrInvalid
		}
		for y := top; y < bottom; y++ {
			left, right := o.sx+1, o.x
			for i := 1; i < len(path); i++ {
				a, b := path[i-1], path[i]
				if a.Y > b.Y {
					a, b = b, a
				}
				yy := y * 16
				if yy < a.Y || yy >= b.Y {
					continue
				}
				den := int64(b.Y - a.Y)
				num := int64(a.X)*den + int64(yy-a.Y)*int64(b.X-a.X)
				x := ceilRatio(num, den*16)
				left = min(left, x)
				right = max(right, x)
			}
			if err := op.addSpan(left, right, y, clip); err != nil {
				return err
			}
		}
	}
	for i, row := range rows {
		y := top + i
		// GDI fills the path and then strokes it. Keep the two passes separate:
		// destination-dependent ROP2 operations must be applied twice at their overlap.
		if row[1]+1 >= row[2] {
			if err := op.addSpan(min(row[0], row[2]), max(row[1], row[3])+1, y, clip); err != nil {
				return err
			}
		} else {
			if err := op.addSpan(row[0], row[1]+1, y, clip); err != nil {
				return err
			}
			if err := op.addSpan(row[2], row[3]+1, y, clip); err != nil {
				return err
			}
		}
	}
	return nil
}

func (op drawOperation) paintShape(dst *image.RGBA) {
	o := op.order
	for _, span := range op.regions {
		for y := span.Min.Y; y < span.Max.Y; y++ {
			for x := span.Min.X; x < span.Max.X; x++ {
				p := o.fore
				background := false
				row, col := (y-o.by)&7, (x-o.bx)&7
				if op.brush != nil {
					if op.brush.format == 1 {
						background = op.brush.mono[row]&(0x80>>col) != 0
					} else {
						p = op.brush.colors[row*8+col]
					}
				} else if o.style == 3 {
					bits := o.hatch
					if row < 7 {
						bits = o.extra[6-row]
					}
					background = bits&(0x80>>col) != 0
				}
				if background {
					if o.rop&0x80 != 0 {
						continue
					}
					p = o.back
				}
				at := dst.PixOffset(x, y)
				for c := 0; c < 3; c++ {
					dst.Pix[at+c] = rop2(o.rop&31, p[c], dst.Pix[at+c])
				}
				dst.Pix[at+3] = 255
			}
		}
	}
}
