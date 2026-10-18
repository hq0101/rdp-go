package remoteapp

import (
	"image"
	"image/draw"

	"github.com/hq0101/rdp-go/rdpgfx"
)

// RenderBase extracts currently visible window pixels from a zero-origin,
// completed desktop framebuffer. Obscured/unavailable pixels stay transparent;
// this function does not invent or cache contents hidden on the server. The
// returned NRGBA is caller-owned and includes the whole visible-body geometry.
// Each render is bounded by 16 Mi pixels plus a one-byte mask per pixel. Bound
// aggregate retained outputs in the application; View owns no render cache.
func (v *View) RenderBase(desktop *image.RGBA) (*image.NRGBA, error) {
	if v.mode != BasePresentation {
		return nil, ErrMode
	}
	if !v.shown {
		return nil, ErrHidden
	}
	if desktop == nil || desktop.Rect != image.Rect(0, 0, v.desktop.Dx(), v.desktop.Dy()) {
		return nil, ErrGeometry
	}
	row := 4 * desktop.Rect.Dx()
	h := desktop.Rect.Dy()
	if desktop.Stride < row || len(desktop.Pix) < row || h > 1 && desktop.Stride > (len(desktop.Pix)-row)/(h-1) {
		return nil, ErrGeometry
	}
	out := image.NewNRGBA(image.Rectangle{Max: v.bounds.Size()})
	visible := v.bounds.Intersect(v.desktop)
	if !visible.Empty() {
		draw.Draw(out, visible.Sub(v.bounds.Min), desktop, visible.Min.Sub(v.desktop.Min), draw.Src)
	}
	v.mask(out)
	return out, nil
}

// RenderEnhanced renders an immutable completed Scene frame associated with this
// exact window lifetime. It applies shape, preserving GFX alpha and disregarding
// server occlusion visibility. Geometry updates and frames are separate streams:
// if dimensions disagree, wait for matching data or make an explicit application
// rendering decision; this API never silently stretches/crops to stale geometry.
func (v *View) RenderEnhanced(binding Binding, frame *rdpgfx.WindowFrame) (*image.NRGBA, error) {
	if v.mode != EnhancedPresentation {
		return nil, ErrMode
	}
	if !v.shown {
		return nil, ErrHidden
	}
	if frame == nil || binding.Window != v.Identity() || binding.Mapping != frame.Mapping() || binding.FrameID != frame.FrameID() || binding.Mapping.WindowID != uint64(v.window.ID) {
		return nil, ErrStale
	}
	m := binding.Mapping
	if m.Surface.X <= 0 || m.Surface.Y <= 0 {
		return nil, ErrGeometry
	}
	size := image.Pt((m.Mapped.X*m.Target.X+m.Surface.X-1)/m.Surface.X, (m.Mapped.Y*m.Target.Y+m.Surface.Y-1)/m.Surface.Y)
	if size != v.bounds.Size() {
		return nil, ErrGeometry
	}
	out := frame.Image()
	if out == nil {
		return nil, ErrGeometry
	}
	v.mask(out)
	return out, nil
}

func (v *View) mask(out *image.NRGBA) {
	w, h := out.Rect.Dx(), out.Rect.Dy()
	mask := make([]byte, w*h)
	mark := func(rects []image.Rectangle, bit byte) {
		for _, r := range rects {
			for y := r.Min.Y; y < r.Max.Y; y++ {
				for x := r.Min.X; x < r.Max.X; x++ {
					mask[y*w+x] |= bit
				}
			}
		}
	}
	mark(v.shape, 1)
	want := byte(1)
	if v.mode == BasePresentation {
		mark(v.visibility, 2)
		want = 3
	}
	for i, b := range mask {
		if b != want {
			clear(out.Pix[i*4 : i*4+4])
		}
	}
}
