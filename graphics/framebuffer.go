package graphics

import (
	"encoding/binary"
	"image"
	"image/draw"

	"github.com/hq0101/rdp-go/rail"
)

// Framebuffer accumulates bitmap and negotiated drawing-order updates. It is not safe for concurrent access.
// Snapshot returns a copy that can be passed to another goroutine or PNG encoder.
type Framebuffer struct {
	// WindowState explicitly accepts RemoteApp windowing drawing orders. Create
	// it with the effective negotiated capabilities and retain it for this
	// connection. Nil rejects window orders. Successful mixed drawing batches
	// commit metadata and pixels together; use Revision/Snapshot to observe it.
	// Metadata commits with each Orders Update, including inside marked Surface
	// frames whose pixels are presented later. This does not enable RemoteApp
	// capability negotiation, decode icon pixels or create native windows.
	WindowState *rail.WindowState
	// AllowNSCodec must match SessionInfo.NSCodec. False accepts only raw
	// Surface and Revision 3 bitmaps. Like the rest of Framebuffer it requires serial access.
	AllowNSCodec bool
	// AllowBitmapCacheV3 must match SessionInfo.BitmapCacheV3.
	AllowBitmapCacheV3 bool
	// Match the effective session capabilities after each activation.
	AllowBrushCache, AllowOffscreen bool
	// AllowExtendedOrders must match SessionInfo.ExtendedOrders.
	AllowExtendedOrders bool
	// AllowShapeOrders must match SessionInfo.ShapeOrders.
	AllowShapeOrders bool
	// Match SessionInfo.GlyphCache and GlyphCacheV2 after every activation.
	AllowGlyphCache, AllowGlyphCacheV2 bool
	// OffscreenDepth is the negotiated session depth for wire cache accounting.
	// Supported values are 24 and 32; zero defaults to 32.
	OffscreenDepth uint16
	pixels         *image.RGBA
	orders         orderDecoder
	surface        surfaceState
}

func NewFramebuffer(width, height int) (*Framebuffer, error) {
	if width < 1 || height < 1 || width > maxDimension || height > maxDimension || width*height > MaxPixels {
		return nil, ErrInvalid
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	return &Framebuffer{pixels: img, orders: orderDecoder{last: 1, target: primarySurface}}, nil
}

// Resize starts a reactivated desktop. It clears pixels and primary-order history,
// retaining this connection's volatile bitmap, brush, glyph and fragment caches.
// Use a new Framebuffer for a new connection. An invalid size leaves all state unchanged.
func (f *Framebuffer) Resize(width, height int) error {
	if f == nil || f.pixels == nil {
		return ErrInvalid
	}
	next, err := NewFramebuffer(width, height)
	if err != nil {
		return err
	}
	next.orders.cache = f.orders.cache
	next.orders.waiting = f.orders.waiting
	next.orders.stats = f.orders.stats
	next.orders.brushes, next.orders.palette = f.orders.brushes, f.orders.palette
	next.orders.glyphs, next.orders.fragments = f.orders.glyphs, f.orders.fragments
	next.orders.offscreen, next.orders.offscreenSizes, next.orders.offscreenBytes = f.orders.offscreen, f.orders.offscreenSizes, f.orders.offscreenBytes
	next.surface.stats = f.surface.stats
	next.AllowNSCodec = f.AllowNSCodec
	next.WindowState = f.WindowState
	next.AllowBitmapCacheV3 = f.AllowBitmapCacheV3
	next.AllowExtendedOrders = f.AllowExtendedOrders
	next.AllowShapeOrders = f.AllowShapeOrders
	next.AllowGlyphCache, next.AllowGlyphCacheV2 = f.AllowGlyphCache, f.AllowGlyphCacheV2
	next.AllowBrushCache, next.AllowOffscreen, next.OffscreenDepth = f.AllowBrushCache, f.AllowOffscreen, f.OffscreenDepth
	*f = *next
	return nil
}

// PresentGraphicsFrame copies a complete opaque RDPGFX output snapshot into the
// primary framebuffer, preserving legacy caches and order history. Geometry
// must match the current framebuffer (resize first if necessary). It rejects
// an incomplete legacy Surface Commands frame. The source remains caller-owned.
// As with Apply, calls must be serialized; errors leave pixels unchanged.
func (f *Framebuffer) PresentGraphicsFrame(src *image.NRGBA) error {
	if f == nil || f.pixels == nil || src == nil || src.Rect != f.pixels.Rect || f.surface.open || src.Stride < src.Rect.Dx()*4 {
		return ErrInvalid
	}
	w, h := src.Rect.Dx(), src.Rect.Dy()
	if h <= 0 || len(src.Pix) < w*4 || h-1 > (len(src.Pix)-w*4)/src.Stride {
		return ErrInvalid
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if src.Pix[y*src.Stride+x*4+3] != 255 {
				return ErrInvalid
			}
		}
	}
	for y := 0; y < h; y++ {
		copy(f.pixels.Pix[y*f.pixels.Stride:y*f.pixels.Stride+w*4], src.Pix[y*src.Stride:y*src.Stride+w*4])
	}
	return nil
}

// Apply processes a bitmap or Orders Update and returns conservative dirty bounds.
// Lines, text, shapes and multi-rectangle orders can leave pixels within bounds untouched.
// Synchronize Updates are accepted without changes. An error leaves the frame
// and decoding/cache state unchanged. Call only for events with DataType pdu.Update.
func (f *Framebuffer) Apply(payload []byte) ([]image.Rectangle, error) {
	if f == nil || f.pixels == nil || len(payload) < 2 {
		return nil, ErrInvalid
	}
	if f.surface.open {
		// A server may interleave ordinary updates inside a marked frame. Keep
		// screen-copy sources and visible presentation on the same staged image.
		next := *f
		next.pixels = f.surface.pending
		dirty, err := next.apply(payload)
		if err != nil {
			return nil, err
		}
		f.orders = next.orders
		for _, r := range dirty {
			f.surface.dirty = f.surface.dirty.Union(r)
		}
		return nil, nil
	}
	return f.apply(payload)
}

func (f *Framebuffer) apply(payload []byte) ([]image.Rectangle, error) {
	if binary.LittleEndian.Uint16(payload) == 3 {
		if len(payload) != 4 {
			return nil, ErrInvalid
		}
		return nil, nil
	}
	if binary.LittleEndian.Uint16(payload) == 0 {
		return f.applyOrders(payload)
	}
	if binary.LittleEndian.Uint16(payload) == 2 {
		return nil, f.applyPalette(payload)
	}
	if binary.LittleEndian.Uint16(payload) != 1 {
		return nil, ErrUnsupported
	}
	bitmaps, err := DecodeBitmapUpdate(payload)
	if err != nil {
		return nil, err
	}
	for _, b := range bitmaps {
		if !b.Bounds.In(f.pixels.Bounds()) {
			return nil, ErrInvalid
		}
	}
	dirty := make([]image.Rectangle, 0, len(bitmaps))
	for _, b := range bitmaps {
		draw.Draw(f.pixels, b.Bounds, b.Image, image.Point{}, draw.Src)
		dirty = append(dirty, b.Bounds)
	}
	return dirty, nil
}
func (f *Framebuffer) Snapshot() *image.RGBA {
	if f == nil || f.pixels == nil {
		return nil
	}
	img := image.NewRGBA(f.pixels.Bounds())
	copy(img.Pix, f.pixels.Pix)
	return img
}
