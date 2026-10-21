package nativeview

import (
	"fmt"
	"image"
	"unicode/utf16"
	"unsafe"

	rdp "github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/graphics"
	"github.com/hq0101/rdp-go/ime"
)

type candidateButton struct {
	rect   image.Rectangle
	token  ime.CandidateToken
	action ime.CandidateAction
}

func (w *desktopWindow) geometry() error {
	var r winRect
	if ok, _, e := getClientRect.Call(w.hwnd, uintptr(unsafe.Pointer(&r))); ok == 0 {
		return nativeError("GetClientRect", e)
	}
	if r.Right < 0 || r.Bottom < 0 || r.Right > 32768 || r.Bottom > 32768 {
		return ErrInvalid
	}
	w.client = image.Rect(0, 0, int(r.Right), int(r.Bottom))
	dpi, _, _ := getWindowDPI.Call(w.hwnd)
	if dpi == 0 || dpi > 960 {
		return ErrInvalid
	}
	if w.font == 0 || w.fontDPI != uint32(dpi) {
		face, _ := wstr("Segoe UI")
		font, _, e := createFont.Call(signed(-int32(16*dpi/96)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(&face[0])))
		if font == 0 {
			return nativeError("CreateFont", e)
		}
		if w.font != 0 {
			deleteObject.Call(w.font)
		}
		w.font, w.fontDPI = font, uint32(dpi)
	}
	w.rowHeight = max(24, int32(30*dpi/96))
	rows := 0
	if len(w.candidates) > 0 {
		first, last := candidatePage(w.candidates[0])
		rows = min(9, last-first) + 1
	}
	panel := int(w.rowHeight) * (rows + 2)
	w.textY = int32(max(0, w.client.Dy()-panel))
	return nil
}

func candidatePage(c ime.CandidateList) (int, int) {
	if len(c.Strings) == 0 {
		return 0, 0
	}
	if len(c.PageStarts) == 0 || int(c.CurrentPage) >= len(c.PageStarts) {
		return 0, 0
	}
	first := int(c.PageStarts[c.CurrentPage])
	last := len(c.Strings)
	if int(c.CurrentPage)+1 < len(c.PageStarts) {
		last = int(c.PageStarts[c.CurrentPage+1])
	}
	if first < 0 || first > last || last > len(c.Strings) {
		return 0, 0
	}
	return first, last
}

func (w *desktopWindow) sampleText() error {
	p, err := w.input.Presentation(w.focus)
	if err != nil {
		return err
	}
	w.presentation = p
	w.buttons = nil
	w.nativeUI = nil
	initialLists, err := w.input.Candidates(w.focus)
	if err != nil {
		return err
	}
	w.candidates = initialLists
	// SetLayout needs the actual shaped coordinates, not fixed-width guesses.
	// Sample candidates AFTER layout, which can invalidate their native tokens.
	if err = w.geometry(); err != nil {
		return err
	}
	textY := w.textY
	dc, _, e := getDC.Call(w.hwnd)
	if dc == 0 {
		return nativeError("GetDC", e)
	}
	defer releaseDC.Call(w.hwnd, dc)
	old, _, _ := selectObject.Call(dc, w.font)
	defer selectObject.Call(dc, old)
	line, err := shapeLine(dc, p.Snapshot.Text)
	if err != nil {
		return err
	}
	defer line.close()
	origin := winPoint{8, w.textY + 4}
	if ok, _, e := clientToScreen.Call(w.hwnd, uintptr(unsafe.Pointer(&origin))); ok == 0 {
		return nativeError("ClientToScreen", e)
	}
	screenStart, screenEnd := winPoint{}, winPoint{int32(w.client.Max.X), int32(w.client.Max.Y)}
	clientToScreen.Call(w.hwnd, uintptr(unsafe.Pointer(&screenStart)))
	clientToScreen.Call(w.hwnd, uintptr(unsafe.Pointer(&screenEnd)))
	layout, err := line.layout(origin, winRect{screenStart.X, screenStart.Y, screenEnd.X, screenEnd.Y})
	if err != nil {
		return err
	}
	if err = w.input.SetLayout(w.focus, p.Snapshot.Revision, layout); err != nil {
		return err
	}
	lists, err := w.input.Candidates(w.focus)
	if err != nil {
		return err
	}
	w.candidates = lists
	if err = w.geometry(); err != nil {
		return err
	}
	if textY != w.textY {
		return ime.ErrChanged
	}
	return nil
}

// shortLabel limits only display text, never committed text or candidate data.
func shortLabel(s string) []uint16 {
	u := utf16.Encode([]rune(s))
	for j, c := range u {
		if c == 0 {
			u[j] = 0x2400
		}
		if c == '\r' || c == '\n' || c == '\t' {
			u[j] = ' '
		}
	}
	if len(u) > ime.MaxCommitUnits {
		u = u[:ime.MaxCommitUnits-1]
		if len(u) > 0 && u[len(u)-1] >= 0xd800 && u[len(u)-1] <= 0xdbff {
			u = u[:len(u)-1]
		}
		u = append(u, 0x2026)
	}
	return u
}
func paintLabel(dc uintptr, text string, x, y int32, clip winRect) error {
	line, err := shapeLine(dc, shortLabel(text))
	if err != nil {
		return err
	}
	defer line.close()
	return line.draw(dc, x, y, clip, 0, 0)
}

func labelFits(dc uintptr, text string, width, height int32) (bool, error) {
	if len(utf16.Encode([]rune(text))) > ime.MaxCommitUnits {
		return false, nil
	}
	line, err := shapeLine(dc, shortLabel(text))
	if err != nil {
		return false, err
	}
	defer line.close()
	return line.width <= width && line.height <= height, nil
}

func (w *desktopWindow) desktopViewport() image.Rectangle {
	if w.desktop == nil {
		return image.Rectangle{}
	}
	return viewport(image.Rect(0, 0, w.client.Dx(), int(w.textY)), int(w.desktop.info.Width), int(w.desktop.info.Height))
}

func desktopPixels(u *desktopUpdate, point image.Point) ([]byte, error) {
	if u == nil || u.image == nil {
		return nil, nil
	}
	source := u.image
	copyImage := image.NewRGBA(source.Bounds())
	copy(copyImage.Pix, source.Pix)
	if u.pointer.Kind == graphics.PointerColor && u.pointer.Shape != nil {
		if err := u.pointer.Shape.Composite(copyImage, point); err != nil {
			return nil, err
		}
	}
	// GDI BI_RGB uses little-endian BGRA. The framebuffer remains immutable.
	for j := 0; j < len(copyImage.Pix); j += 4 {
		copyImage.Pix[j], copyImage.Pix[j+2] = copyImage.Pix[j+2], copyImage.Pix[j]
	}
	return copyImage.Pix, nil
}

func (w *desktopWindow) paint(dc uintptr) error {
	w.nativeUI = nil
	if w.font == 0 {
		return nil
	}
	saved, _, e := saveDC.Call(dc)
	if saved == 0 {
		return nativeError("SaveDC", e)
	}
	defer restoreDC.Call(dc, saved)
	selectObject.Call(dc, w.font)
	setBkMode.Call(dc, 1)
	setTextAlign.Call(dc, 0)
	all := winRect{0, 0, int32(w.client.Dx()), int32(w.client.Dy())}
	if err := brushRect(dc, all, rgb(0x18202b)); err != nil {
		return err
	}
	v := w.desktopViewport()
	if !v.Empty() && w.desktop.ready && w.desktop.image != nil {
		if w.rasterSource != w.desktop || w.rasterPoint != w.lastPointer {
			pixels, err := desktopPixels(w.desktop, w.lastPointer)
			if err != nil {
				return err
			}
			w.rasterPixels, w.rasterSource, w.rasterPoint = pixels, w.desktop, w.lastPointer
		}
		pixels := w.rasterPixels
		header := bitmapHeader{Size: 40, Width: int32(w.desktop.image.Rect.Dx()), Height: -int32(w.desktop.image.Rect.Dy()), Planes: 1, Bits: 32}
		result, _, e := stretchDIBits.Call(dc, uintptr(v.Min.X), uintptr(v.Min.Y), uintptr(v.Dx()), uintptr(v.Dy()), 0, 0, uintptr(header.Width), uintptr(-header.Height), uintptr(unsafe.Pointer(&pixels[0])), uintptr(unsafe.Pointer(&header)), 0, 0x00cc0020)
		if int32(result) == -1 {
			return nativeError("StretchDIBits", e)
		}
	} else {
		w.rasterSource, w.rasterPixels = nil, nil
	}
	panel := winRect{0, w.textY, all.Right, all.Bottom}
	if err := brushRect(dc, panel, rgb(0xf4f6f8)); err != nil {
		return err
	}
	setTextColor.Call(dc, uintptr(rgb(0x202124)))
	if err := paintPreedit(dc, w.font, w.presentation, 8, w.textY+4, panel, w.loop != nil); err != nil {
		return err
	}
	w.buttons = nil
	y := w.textY + w.rowHeight
	if len(w.candidates) > 0 {
		c := w.candidates[0]
		first, last := candidatePage(c)
		// A page longer than the panel can display keeps its native UI visible.
		// Do not hide an incomplete replacement or unsupported behavior provider.
		complete := last-first <= 9 && last > first && c.SupportsBehavior
		for index := first; index < min(last, first+9); index++ {
			box := winRect{4, y, all.Right - 4, min(all.Bottom, y+w.rowHeight)}
			if !validRect(box) || box.Bottom-box.Top < w.rowHeight {
				complete = false
				if !validRect(box) {
					break
				}
			}
			label := fmt.Sprintf("%d  %s", index-first+1, c.Strings[index])
			fits, err := labelFits(dc, label, box.Right-10, box.Bottom-box.Top-2)
			if err != nil {
				return err
			}
			complete = complete && fits
			if index == c.Selection {
				if err := brushRect(dc, box, rgb(0xd6e8ff)); err != nil {
					return err
				}
			}
			if err := paintLabel(dc, label, 10, y+2, box); err != nil {
				return err
			}
			if c.SupportsBehavior {
				w.buttons = append(w.buttons, candidateButton{image.Rect(int(box.Left), int(box.Top), int(box.Right), int(box.Bottom)), c.Token, ime.CandidateAction{Kind: ime.CandidateSelect, Index: uint32(index)}})
			}
			y += w.rowHeight
		}
		if c.SupportsBehavior {
			type actionLabel struct {
				label   string
				action  ime.CandidateAction
				enabled bool
			}
			actions := []actionLabel{{"Previous", ime.CandidateAction{Kind: ime.CandidateSelectPage, Index: c.CurrentPage - 1}, c.CurrentPage > 0}, {"Next", ime.CandidateAction{Kind: ime.CandidateSelectPage, Index: c.CurrentPage + 1}, int(c.CurrentPage)+1 < len(c.PageStarts)}, {"Confirm", ime.CandidateAction{Kind: ime.CandidateFinalize}, c.Selection >= 0}, {"Cancel", ime.CandidateAction{Kind: ime.CandidateAbort}, true}}
			width := max(int32(1), (all.Right-8)/4)
			for j, a := range actions {
				box := winRect{4 + int32(j)*width, y, 4 + int32(j+1)*width, min(all.Bottom, y+w.rowHeight)}
				if !validRect(box) || box.Bottom-box.Top < w.rowHeight {
					complete = false
					if !validRect(box) {
						break
					}
				}
				if a.enabled {
					fits, err := labelFits(dc, a.label, box.Right-box.Left-4, box.Bottom-box.Top-2)
					if err != nil {
						return err
					}
					complete = complete && fits
					if err := paintLabel(dc, a.label, box.Left+4, y+2, box); err != nil {
						return err
					}
					w.buttons = append(w.buttons, candidateButton{image.Rect(int(box.Left), int(box.Top), int(box.Right), int(box.Bottom)), c.Token, a.action})
				}
			}
			y += w.rowHeight
		}
		if complete == c.NativeShown {
			w.nativeUI = &candidateInput{c.Token, ime.CandidateAction{Kind: ime.CandidateShow, Visible: !complete}}
		}
		// Previously hosted lists may move behind a new first list. Restore
		// those native windows too, one fresh token at a time outside painting.
		for _, other := range w.candidates[1:] {
			if !other.NativeShown {
				w.nativeUI = &candidateInput{other.Token, ime.CandidateAction{Kind: ime.CandidateShow, Visible: true}}
				break
			}
		}
	}
	label := w.status
	if w.loop != nil {
		label = "Connected — local input method enabled"
	} else if w.desktop != nil && w.desktop.ready {
		label = "Click the desktop to type"
	}
	return paintLabel(dc, label, 8, y+3, winRect{0, y, all.Right, all.Bottom})
}

func (w *desktopWindow) mouse(message uint32, wp, lp uintptr) {
	if w.loop == nil || w.closing || w.blurRequested {
		return
	}
	p := image.Pt(int(int16(lp)), int(int16(lp>>16)))
	if message == 0x200 && w.warpedClient != nil {
		warped := *w.warpedClient
		w.warpedClient = nil
		if p == warped {
			return
		} // the server's own position update is not new local input
	}
	if message == 0x20a {
		point := winPoint{int32(p.X), int32(p.Y)}
		if ok, _, _ := screenToClient.Call(w.hwnd, uintptr(unsafe.Pointer(&point))); ok == 0 {
			return
		}
		p = image.Pt(int(point.X), int(point.Y))
	}
	var button rdp.MouseButton
	down := false
	switch message {
	case 0x201:
		button, down = rdp.MouseLeft, true
	case 0x202:
		button = rdp.MouseLeft
	case 0x204:
		button, down = rdp.MouseRight, true
	case 0x205:
		button = rdp.MouseRight
	case 0x207:
		button, down = rdp.MouseMiddle, true
	case 0x208:
		button = rdp.MouseMiddle
	}
	if button == rdp.MouseLeft && down && !w.pressed[0] {
		for _, b := range w.buttons {
			if p.In(b.rect) {
				w.enqueue(inputItem{candidate: &candidateInput{b.token, b.action}})
				return
			}
		}
	}
	v := w.desktopViewport()
	x, y, inside := remotePoint(p, v, int(w.desktop.info.Width), int(w.desktop.info.Height))
	held := w.pressed[0] || w.pressed[1] || w.pressed[2]
	if !inside {
		if !held {
			return
		}
		if v.Empty() {
			w.blurRequested = true
			return
		}
		p.X = min(max(p.X, v.Min.X), v.Max.X-1)
		p.Y = min(max(p.Y, v.Min.Y), v.Max.Y-1)
		x, y, _ = remotePoint(p, v, int(w.desktop.info.Width), int(w.desktop.info.Height))
	}
	w.lastPointer = image.Pt(int(x), int(y))
	if message == 0x200 {
		w.enqueue(inputItem{mouse: mouseAction{kind: mouseMove, x: x, y: y}})
		return
	}
	if message == 0x20a {
		if delta := int16(wp >> 16); delta != 0 {
			w.enqueue(inputItem{mouse: mouseAction{kind: mouseWheel, wheel: delta}})
		}
		return
	}
	if button == 0 {
		return
	}
	index := int(button) - 1
	if !down && !w.pressed[index] {
		return
	}
	w.pressed[index] = down
	if down {
		w.captured = true
		setCapture.Call(w.hwnd)
	}
	w.enqueue(inputItem{mouse: mouseAction{kind: mouseButton, button: button, down: down, x: x, y: y}})
	if !w.pressed[0] && !w.pressed[1] && !w.pressed[2] {
		w.captured = false
		releaseCapture.Call()
	}
}

// Only move the OS cursor while the foreground viewer owns its desktop area.
// A server update must not pull the pointer out of local IME controls or another
// application. A request ignored here is never replayed on later focus changes.
func (w *desktopWindow) positionCursor(p image.Point) error {
	v := w.desktopViewport()
	local, valid := localPoint(p, v, int(w.desktop.info.Width), int(w.desktop.info.Height))
	if !valid {
		return nil
	}
	var current winPoint
	if ok, _, e := getCursorPos.Call(uintptr(unsafe.Pointer(&current))); ok == 0 {
		return nativeError("GetCursorPos", e)
	}
	if ok, _, e := screenToClient.Call(w.hwnd, uintptr(unsafe.Pointer(&current))); ok == 0 {
		return nativeError("ScreenToClient", e)
	}
	if !image.Pt(int(current.X), int(current.Y)).In(v) && !w.captured {
		return nil
	}
	screen := winPoint{int32(local.X), int32(local.Y)}
	if ok, _, e := clientToScreen.Call(w.hwnd, uintptr(unsafe.Pointer(&screen))); ok == 0 {
		return nativeError("ClientToScreen", e)
	}
	if ok, _, e := setCursorPos.Call(signed(screen.X), signed(screen.Y)); ok == 0 {
		return nativeError("SetCursorPos", e)
	}
	w.warpedClient = &local
	return nil
}
