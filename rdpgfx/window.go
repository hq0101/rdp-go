package rdpgfx

import (
	"image"
	"sort"
)

// WindowMapping retains the wire's 64-bit window identity and all geometries.
// Surface is the entire offscreen allocation; Mapped is its top-left region.
// Target is the size of the entire scaled surface (MS-RDPEGFX 3.3.5.23).
// Ordinary mappings have Target == Surface. IDs are remote identifiers, never
// OS handles. Do not truncate WindowID when joining it to a 32-bit RAIL order.
// The application associates RAIL and GFX streams; a mapping may arrive before
// its window metadata, and several surfaces may identify the same window.
type WindowMapping struct {
	// Local serials within one pipeline/channel generation. Generation changes
	// on every Map; Revision changes when a completed frame is published. Neither
	// uses the server frame ID, which may wrap or be reused.
	Generation, Revision    uint64
	SurfaceID               uint16
	WindowID                uint64
	Surface, Mapped, Target image.Point
	Scaled                  bool
}

type windowFrame struct {
	mapping WindowMapping
	frameID uint32
	pixels  *image.NRGBA // immutable; subsequent writes use copy-on-write
}

// WindowFrame is an owned, immutable snapshot of one completed window surface.
// Methods are safe for concurrent readers. Source/Image allocate caller-owned
// images; the application must bound retained snapshots and rendered images.
// A snapshot remains valid after remap, deletion, reset or channel close.
type WindowFrame struct{ frame windowFrame }

func (f *WindowFrame) Mapping() WindowMapping { return f.frame.mapping }
func (f *WindowFrame) FrameID() uint32        { return f.frame.frameID }
func (f *WindowFrame) Source() *image.NRGBA {
	if f.frame.pixels == nil {
		return nil
	}
	return cloneImage(f.frame.pixels)
}

// Image renders the mapped top-left region. For a scaled mapping, it samples
// relative to the entire surface/target, then clips to the scaled mapped extent
// (right/bottom rounded up). This is an explicit interpretation of 3.3.5.23;
// padded real Windows mappings still require interoperability validation.
// Pixel-center bilinear filtering interpolates premultiplied colors and alpha
// and returns straight-alpha NRGBA, avoiding color fringes at transparency.
// The protocol specifies no filtering kernel or fractional-edge rounding.
func (f *WindowFrame) Image() *image.NRGBA {
	if f.frame.pixels == nil {
		return nil
	}
	m := f.frame.mapping
	w := (m.Mapped.X*m.Target.X + m.Surface.X - 1) / m.Surface.X
	h := (m.Mapped.Y*m.Target.Y + m.Surface.Y - 1) / m.Surface.Y
	dst := image.NewNRGBA(image.Rect(0, 0, w, h))
	if m.Target == m.Surface {
		copyPixels(dst, image.Point{}, f.frame.pixels, dst.Rect, false)
		return dst
	}
	copyScaledWindow(dst, f.frame.pixels, m.Target)
	return dst
}

// WindowMappings returns completed mappings sorted by SurfaceID. Pending frame
// changes are invisible until END_FRAME. RESET only changes desktop geometry;
// window mappings persist. DELETE_SURFACE outside a frame removes its snapshot
// immediately; deletion inside a frame becomes visible at END_FRAME.
func (p *Pipeline) WindowMappings() []WindowMapping {
	var out []WindowMapping
	for _, f := range p.windowFrames {
		out = append(out, f.mapping)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SurfaceID < out[j].SurfaceID })
	return out
}

// WindowSnapshot returns nil if this surface has no completed window frame.
// It copies the full source, preserving padding and mapping metadata for an
// application-specific renderer. Each source is bounded by 16 Mi pixels; all
// live sources and all completed sources separately share that bound. Calls
// must be serialized with Apply, as with Snapshot.
func (p *Pipeline) WindowSnapshot(surfaceID uint16) *WindowFrame {
	f, ok := p.windowFrames[surfaceID]
	if !ok {
		return nil
	}
	f.pixels = cloneImage(f.pixels)
	return &WindowFrame{frame: f}
}
func (r *Receiver) WindowMappings() []WindowMapping       { return r.pipeline.WindowMappings() }
func (r *Receiver) WindowSnapshot(id uint16) *WindowFrame { return r.pipeline.WindowSnapshot(id) }
func (c *Client) WindowMappings() []WindowMapping         { return c.receiver.WindowMappings() }
func (c *Client) WindowSnapshot(id uint16) *WindowFrame   { return c.receiver.WindowSnapshot(id) }

func (t *transaction) mapWindow(c Command) error {
	p := t.p
	if !p.WindowMapping {
		return ErrUnsupported
	}
	if c.ID == MapSurfaceToScaledWindow && !scaledOutputAllowed(p.confirmedVersion, p.confirmedFlags) {
		return ErrUnsupported
	}
	s, ok := p.surfaces[c.SurfaceID]
	if !ok || c.MappedWidth > s.image.Rect.Dx() || c.MappedHeight > s.image.Rect.Dy() {
		return ErrInvalid
	}
	m := WindowMapping{SurfaceID: c.SurfaceID, WindowID: c.WindowID, Surface: s.image.Rect.Size(), Mapped: image.Pt(c.MappedWidth, c.MappedHeight), Target: s.image.Rect.Size(), Scaled: c.ID == MapSurfaceToScaledWindow}
	if m.Scaled {
		m.Target = image.Pt(c.Width, c.Height)
	}
	if !validSize(m.Target.X, m.Target.Y) {
		return ErrInvalid
	}
	old := 0
	if s.windowMapped {
		old = s.window.Target.X * s.window.Target.Y
	}
	pixels := m.Target.X * m.Target.Y
	if pixels > maxPixels-p.windowPixels+old {
		return ErrInvalid
	}
	if p.windowGeneration == ^uint64(0) {
		return ErrInvalid
	}
	p.windowGeneration++
	m.Generation = p.windowGeneration
	p.windowPixels += pixels - old
	s.window, s.windowMapped, s.dirty = m, true, true
	p.surfaces[c.SurfaceID] = s
	p.stats.WindowMappings++
	if m.Scaled {
		p.stats.ScaledWindowMappings++
	}
	return nil
}

func (t *transaction) presentWindows() (bool, error) {
	p := t.p
	changed := false
	for id := range p.windowFrames {
		if s, ok := p.surfaces[id]; !ok || !s.windowMapped {
			delete(p.windowFrames, id)
			changed = true
		}
	}
	for id, s := range p.surfaces {
		if !s.windowMapped || !s.dirty {
			continue
		}
		if p.windowFrames == nil {
			p.windowFrames = make(map[uint16]windowFrame)
		}
		if p.windowRevision == ^uint64(0) {
			return false, ErrInvalid
		}
		p.windowRevision++
		m := s.window
		m.Revision = p.windowRevision
		p.windowFrames[id] = windowFrame{m, p.frameID, s.image}
		// A later frame in this same Apply must not mutate the published image.
		t.copied[id] = false
		// Desktop mappings are independent and still need presentation below.
		s.dirty = s.mapped
		p.surfaces[id] = s
		p.stats.WindowFrames++
		changed = true
	}
	return changed, nil
}

func copyScaledWindow(dst, src *image.NRGBA, target image.Point) {
	for y := 0; y < dst.Rect.Dy(); y++ {
		sy := scaleCoordinate(y, src.Rect.Dy(), target.Y)
		for x := 0; x < dst.Rect.Dx(); x++ {
			sx := scaleCoordinate(x, src.Rect.Dx(), target.X)
			positions := [4]int{src.PixOffset(sx.lo, sy.lo), src.PixOffset(sx.hi, sy.lo), src.PixOffset(sx.lo, sy.hi), src.PixOffset(sx.hi, sy.hi)}
			weights := [4]int64{(65536 - sx.weight) * (65536 - sy.weight), sx.weight * (65536 - sy.weight), (65536 - sx.weight) * sy.weight, sx.weight * sy.weight}
			var alpha int64
			var rgb [3]int64
			for i, off := range positions {
				a := int64(src.Pix[off+3]) * weights[i]
				alpha += a
				for k := range rgb {
					rgb[k] += int64(src.Pix[off+k]) * a
				}
			}
			off := dst.PixOffset(x, y)
			dst.Pix[off+3] = byte((alpha + (1 << 31)) >> 32)
			if dst.Pix[off+3] != 0 {
				for k := range rgb {
					dst.Pix[off+k] = byte((rgb[k] + alpha/2) / alpha)
				}
			}
		}
	}
}
