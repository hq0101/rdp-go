package nativeview

import (
	"github.com/hq0101/rdp-go/ime"
	"runtime"
	"unsafe"
)

// Each analysis owns a pinned UTF-16 copy until ScriptStringFree has returned.
// It lives only for the borrowed HDC's lifetime, never across a paint/DC release.
type shapedLine struct {
	analysis      uintptr
	text          []uint16
	pin           runtime.Pinner
	width, height int32
	units         [][2]int32
	carets        []int32
}

func shapeLine(dc uintptr, text []uint16) (line *shapedLine, err error) {
	if dc == 0 || len(text) > ime.MaxCommitUnits {
		return nil, ErrInvalid
	}
	line = &shapedLine{text: append([]uint16(nil), text...), carets: make([]int32, len(text)+1), units: make([][2]int32, len(text))}
	defer func() {
		if err != nil {
			line.close()
			line = nil
		}
	}()
	if len(text) == 0 {
		m := uint16('M')
		var size winSize
		ok, _, e := getTextExtent.Call(dc, uintptr(unsafe.Pointer(&m)), 1, uintptr(unsafe.Pointer(&size)))
		if ok == 0 {
			return line, nativeError("GetTextExtentPoint32", e)
		}
		if size.CY < 1 || size.CY > 4096 {
			return line, ErrInvalid
		}
		line.height = size.CY
		return line, nil
	}
	line.pin.Pin(&line.text[0])
	hr, _, _ := scriptAnalyse.Call(dc, uintptr(unsafe.Pointer(&line.text[0])), uintptr(len(text)), uintptr(len(text)*3/2+16), ^uintptr(0), 0x10a0, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&line.analysis)))
	if err = hrError("ScriptStringAnalyse", hr); err != nil {
		return line, err
	}
	if line.analysis == 0 {
		return line, ErrInvalid
	}
	p, _, _ := scriptSize.Call(line.analysis)
	if p == 0 {
		return line, ErrInvalid
	}
	var size winSize
	copyNative.Call(uintptr(unsafe.Pointer(&size)), p, unsafe.Sizeof(size))
	if size.CX < 0 || size.CX > 1<<20 || size.CY < 1 || size.CY > 4096 {
		return line, ErrInvalid
	}
	line.width, line.height = size.CX, size.CY
	for j := range text {
		var lead, trail int32
		hr, _, _ = scriptCPtoX.Call(line.analysis, uintptr(j), 0, uintptr(unsafe.Pointer(&lead)))
		if err = hrError("ScriptStringCPtoX leading", hr); err != nil {
			return line, err
		}
		hr, _, _ = scriptCPtoX.Call(line.analysis, uintptr(j), 1, uintptr(unsafe.Pointer(&trail)))
		if err = hrError("ScriptStringCPtoX trailing", hr); err != nil {
			return line, err
		}
		if lead < 0 || trail < 0 || lead > 1<<20 || trail > 1<<20 {
			return line, ErrInvalid
		}
		line.carets[j] = lead
		line.units[j] = [2]int32{min(lead, trail), max(lead, trail)}
		if j == len(text)-1 {
			line.carets[j+1] = trail
		}
	}
	return line, nil
}
func (l *shapedLine) close() {
	if l == nil {
		return
	}
	if l.analysis != 0 {
		scriptFree.Call(uintptr(unsafe.Pointer(&l.analysis)))
		l.analysis = 0
	}
	l.pin.Unpin()
	l.text = nil
}
func addCoord(a, b int32) (int32, error) {
	n := int64(a) + int64(b)
	if n < -(1<<31) || n > 1<<31-1 {
		return 0, ErrInvalid
	}
	return int32(n), nil
}
func (l *shapedLine) layout(origin winPoint, screen winRect) (ime.TextLayout, error) {
	out := ime.TextLayout{Screen: ime.TextRect{Left: screen.Left, Top: screen.Top, Right: screen.Right, Bottom: screen.Bottom}, Units: make([]ime.TextRect, len(l.units)), Carets: make([]ime.TextRect, len(l.carets))}
	bottom, err := addCoord(origin.Y, l.height)
	if err != nil {
		return ime.TextLayout{}, err
	}
	for j, u := range l.units {
		x1, e1 := addCoord(origin.X, u[0])
		x2, e2 := addCoord(origin.X, u[1])
		if e1 != nil || e2 != nil {
			return ime.TextLayout{}, ErrInvalid
		}
		out.Units[j] = ime.TextRect{Left: x1, Top: origin.Y, Right: x2, Bottom: bottom}
		if x1 < screen.Left || x2 > screen.Right || origin.Y < screen.Top || bottom > screen.Bottom {
			out.Clipped = true
		}
	}
	for j, x := range l.carets {
		left, e1 := addCoord(origin.X, x)
		right, e2 := addCoord(left, 1)
		if e1 != nil || e2 != nil {
			return ime.TextLayout{}, ErrInvalid
		}
		out.Carets[j] = ime.TextRect{Left: left, Top: origin.Y, Right: right, Bottom: bottom}
	}
	return out, nil
}
func displayColor(c ime.DisplayColor, fallback uint32) uint32 {
	switch c.Kind {
	case ime.DisplayColorRGB:
		return rgb(c.Value)
	case ime.DisplayColorSystem:
		v, _, _ := getSysColor.Call(uintptr(c.Value))
		return uint32(v)
	default:
		return rgb(fallback)
	}
}
func (l *shapedLine) draw(dc uintptr, x, y int32, clip winRect, minSel, maxSel int32) error {
	if l.analysis == 0 {
		return nil
	}
	hr, _, _ := scriptOut.Call(l.analysis, signed(x), signed(y), 4, uintptr(unsafe.Pointer(&clip)), signed(minSel), signed(maxSel), 0)
	return hrError("ScriptStringOut", hr)
}
func (l *shapedLine) rangeRects(r ime.TextRange, x, y int32) []winRect {
	var result []winRect
	for j := max(0, int(r.Start)); j < min(len(l.units), int(r.End)); j++ {
		u := l.units[j]
		if u[0] == u[1] {
			continue
		}
		result = append(result, winRect{x + u[0], y, x + u[1], y + l.height})
	}
	return result
}
func clipRect(a, b winRect) winRect {
	return winRect{max(a.Left, b.Left), max(a.Top, b.Top), min(a.Right, b.Right), min(a.Bottom, b.Bottom)}
}
func validRect(r winRect) bool { return r.Right > r.Left && r.Bottom > r.Top }

// Painting clips whole shaped text by code-unit extents. It never reshapes each
// styled run separately, preserving fallback fonts, ligatures and bidi order.
func paintPreedit(dc, font uintptr, p ime.TextPresentation, x, y int32, clip winRect, caret bool) error {
	state, _, e := saveDC.Call(dc)
	if state == 0 {
		return nativeError("SaveDC", e)
	}
	defer restoreDC.Call(dc, state)
	intersectClip.Call(dc, signed(clip.Left), signed(clip.Top), signed(clip.Right), signed(clip.Bottom))
	selectObject.Call(dc, font)
	setBkMode.Call(dc, 1)
	setTextAlign.Call(dc, 0)
	line, err := shapeLine(dc, p.Snapshot.Text)
	if err != nil {
		return err
	}
	defer line.close()
	setTextColor.Call(dc, uintptr(rgb(0x202124)))
	if err = line.draw(dc, x, y, clip, 0, 0); err != nil {
		return err
	}
	for _, run := range p.Runs {
		for _, box := range line.rangeRects(run.Range, x, y) {
			box = clipRect(box, clip)
			if !validRect(box) {
				continue
			}
			if run.Style.Background.Kind != ime.DisplayColorDefault {
				if err = brushRect(dc, box, displayColor(run.Style.Background, 0xffffff)); err != nil {
					return err
				}
			}
			setTextColor.Call(dc, uintptr(displayColor(run.Style.Foreground, 0x202124)))
			if err = line.draw(dc, x, y, box, 0, 0); err != nil {
				return err
			}
		}
	}
	// Default underlines cover only units without an explicit attribute. A run
	// with LineNone suppresses the default too; don't paint two line styles.
	for _, composition := range p.Snapshot.Compositions {
		for unit := composition.Start; unit < composition.End; unit++ {
			covered := false
			for _, run := range p.Runs {
				if unit >= run.Range.Start && unit < run.Range.End {
					covered = true
					break
				}
			}
			if covered {
				continue
			}
			for _, box := range line.rangeRects(ime.TextRange{Start: unit, End: unit + 1}, x, y) {
				if err = drawUnderline(dc, box, clip, ime.DisplayLineSolid, false, rgb(0x5f6368)); err != nil {
					return err
				}
			}
		}
	}
	for _, run := range p.Runs {
		for _, box := range line.rangeRects(run.Range, x, y) {
			if run.Style.Line != ime.DisplayLineNone {
				if err = drawUnderline(dc, box, clip, run.Style.Line, run.Style.BoldLine, displayColor(run.Style.Underline, 0x202124)); err != nil {
					return err
				}
			}
		}
	}
	selection := p.Snapshot.Selection
	if selection.Start < selection.End {
		for _, box := range line.rangeRects(ime.TextRange{Start: selection.Start, End: selection.End}, x, y) {
			box = clipRect(box, clip)
			if validRect(box) {
				if err = line.draw(dc, x, y, box, selection.Start, selection.End); err != nil {
					return err
				}
			}
		}
	}
	if caret && selection.Start == selection.End {
		index := int(selection.End)
		if index < 0 || index >= len(line.carets) {
			return ErrInvalid
		}
		box := clipRect(winRect{x + line.carets[index], y, x + line.carets[index] + 1, y + line.height}, clip)
		if validRect(box) {
			return brushRect(dc, box, rgb(0x202124))
		}
	}
	return nil
}
func drawUnderline(dc uintptr, box, clip winRect, style ime.DisplayLine, bold bool, color uint32) error {
	left, right := max(box.Left, clip.Left), min(box.Right, clip.Right)
	y := box.Bottom + 1
	if left >= right || y < clip.Top || y >= clip.Bottom {
		return nil
	}
	width := int32(1)
	if bold {
		width = 2
	}
	// CreatePen silently makes a wide dotted/dashed pen solid. Draw bounded
	// segments instead so bold TSF attributes preserve their requested style.
	if style == ime.DisplayLineDot || style == ime.DisplayLineDash {
		length := width
		if style == ime.DisplayLineDash {
			length *= 4
		}
		for x := box.Left; x < right; x += length + 2*width {
			r := clipRect(winRect{x, y, min(x+length, right), y + width}, clip)
			if validRect(r) {
				if err := brushRect(dc, r, color); err != nil {
					return err
				}
			}
		}
		return nil
	}
	penStyle := uintptr(0)
	if style == ime.DisplayLineDot {
		penStyle = 2
	}
	if style == ime.DisplayLineDash {
		penStyle = 1
	}
	pen, _, e := createPen.Call(penStyle, signed(width), uintptr(color))
	if pen == 0 {
		return nativeError("CreatePen", e)
	}
	old, _, _ := selectObject.Call(dc, pen)
	defer func() { selectObject.Call(dc, old); deleteObject.Call(pen) }()
	points := []winPoint{{left, y}, {right, y}}
	if style == ime.DisplayLineSquiggle {
		points = nil
		for x := left; x <= right; x += 2 {
			yy := y + (x-left)/2%2*2
			if yy >= clip.Bottom {
				yy = clip.Bottom - 1
			}
			points = append(points, winPoint{x, yy})
		}
		if len(points) < 2 {
			return nil
		}
	}
	ok, _, e := polyline.Call(dc, uintptr(unsafe.Pointer(&points[0])), uintptr(len(points)))
	if ok == 0 {
		return nativeError("Polyline", e)
	}
	return nil
}
