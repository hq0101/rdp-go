package rail

import (
	"errors"
	"image"
)

// MaxIconDimension is the RAIL high-DPI icon bound. WindowState separately
// enforces the negotiated 32- or 96-pixel limit before caching an icon.
const MaxIconDimension = 96

// ErrIconBackground means a standalone transparent image cannot represent an
// icon's XOR pixels, or Composite was given a non-opaque destination region.
var ErrIconBackground = errors.New("rail: icon requires an opaque background")

// IconImage is an immutable, decoded icon. It retains AND/XOR operations which
// cannot always be represented by a transparent PNG. Methods can be called
// concurrently, with independently synchronized destinations. The zero value is
// an empty image. It owns its pixels and never aliases Icon or WindowState.
type IconImage struct {
	width, height int
	rgb, mask     []byte
	alpha         []byte
	background    bool
}

// Decode converts TS_ICON_INFO bitmap planes using the Windows DIB layout:
// bottom-up rows padded to four bytes, MSB-first packed indices, BGR0 palette,
// little-endian RGB555 at 16 bpp, BGR at 24 bpp and straight BGRA at 32 bpp.
// This layout is an explicit interoperability profile: MS-RDPERP describes the
// plane fields but does not fully specify their pixel layout. Real RemoteApp
// server coverage is still required; no format is guessed from malformed sizes.
//
// At 32 bpp any nonzero alpha selects alpha blending for the entire image;
// otherwise AND/XOR applies. A missing mask is treated as all zeroes. Indexed
// color requires a BGR0 table, except 1 bpp can omit the black/white table.
// A monochrome icon can also use one double-height mask DIB with no color/table:
// its bottom-up XOR rows precede its bottom-up AND rows. Other absent color
// planes return ErrUnsupported. A 0x0 icon with empty planes returns an empty
// image. Cache metadata is not involved; call this on a window/notification
// snapshot's Icon, including icons obtained through a cached reference.
func (i *Icon) Decode() (*IconImage, error) {
	if i == nil || i.Width > MaxIconDimension || i.Height > MaxIconDimension || (i.Width == 0) != (i.Height == 0) {
		return nil, ErrInvalid
	}
	switch i.BPP {
	case 1, 4, 8, 16, 24, 32:
	default:
		return nil, ErrUnsupported
	}
	w, h := int(i.Width), int(i.Height)
	if w == 0 {
		if len(i.Mask) != 0 || len(i.Palette) != 0 || len(i.Color) != 0 {
			return nil, ErrInvalid
		}
		return &IconImage{}, nil
	}
	maskStride := ((w + 31) / 32) * 4
	colorStride := ((w*int(i.BPP) + 31) / 32) * 4
	mask, pixels := i.Mask, i.Color
	if len(pixels) == 0 {
		if i.BPP != 1 || len(i.Palette) != 0 || len(mask) != 2*maskStride*h {
			return nil, ErrUnsupported
		}
		pixels, mask = mask[:maskStride*h], mask[maskStride*h:]
	}
	if len(pixels) != colorStride*h || len(mask) != 0 && len(mask) != maskStride*h {
		return nil, ErrInvalid
	}
	palette := i.Palette
	if i.BPP <= 8 {
		if i.BPP == 1 && len(palette) == 0 {
			palette = []byte{0, 0, 0, 0, 255, 255, 255, 0}
		}
		if len(palette) == 0 || len(palette)%4 != 0 || len(palette)/4 > 1<<i.BPP {
			return nil, ErrInvalid
		}
	} else if len(palette) != 0 {
		return nil, ErrInvalid
	}
	n := w * h
	out := &IconImage{width: w, height: h, rgb: make([]byte, 3*n), mask: make([]byte, n)}
	if i.BPP == 32 {
		for off := 3; off < len(pixels); off += 4 {
			if pixels[off] != 0 {
				out.alpha = make([]byte, n)
				break
			}
		}
	}
	for y := 0; y < h; y++ {
		row := pixels[(h-1-y)*colorStride:]
		for x := 0; x < w; x++ {
			p := y*w + x
			if len(mask) != 0 && mask[(h-1-y)*maskStride+x/8]&(0x80>>uint(x%8)) != 0 {
				out.mask[p] = 255
			}
			var r, g, b byte
			switch i.BPP {
			case 1, 4, 8:
				shift := 8 - int(i.BPP) - x*int(i.BPP)%8
				index := int(row[x*int(i.BPP)/8]>>uint(shift)) & ((1 << i.BPP) - 1)
				if index >= len(palette)/4 {
					return nil, ErrInvalid
				}
				b, g, r = palette[4*index], palette[4*index+1], palette[4*index+2]
			case 16:
				v := le.Uint16(row[2*x:])
				r, g, b = byte(v>>10)&31, byte(v>>5)&31, byte(v)&31
				r, g, b = r<<3|r>>2, g<<3|g>>2, b<<3|b>>2
			case 24:
				b, g, r = row[3*x], row[3*x+1], row[3*x+2]
			case 32:
				b, g, r = row[4*x], row[4*x+1], row[4*x+2]
				if out.alpha != nil {
					out.alpha[p] = row[4*x+3]
				}
			}
			out.rgb[3*p], out.rgb[3*p+1], out.rgb[3*p+2] = r, g, b
			if out.alpha == nil && out.mask[p] != 0 && r|g|b != 0 {
				out.background = true
			}
		}
	}
	return out, nil
}

// Bounds returns zero-based, top-down image bounds. A nil image has empty bounds.
func (i *IconImage) Bounds() image.Rectangle {
	if i == nil {
		return image.Rectangle{}
	}
	return image.Rect(0, 0, i.width, i.height)
}

// HasAlpha reports whether the source selected 32-bit alpha composition.
func (i *IconImage) HasAlpha() bool { return i != nil && i.alpha != nil }

// RequiresBackground reports whether any XOR operation depends on the destination.
func (i *IconImage) RequiresBackground() bool { return i != nil && i.background }

// Image returns an independent straight-alpha image suitable for PNG encoding.
// It fails with ErrIconBackground if arbitrary destination colors are needed;
// Composite preserves those pixels' AND/XOR behavior instead.
func (i *IconImage) Image() (*image.NRGBA, error) {
	if i == nil {
		return nil, ErrInvalid
	}
	if i.background {
		return nil, ErrIconBackground
	}
	out := image.NewNRGBA(i.Bounds())
	for p := 0; p < i.width*i.height; p++ {
		a := byte(255)
		if i.alpha != nil {
			a = i.alpha[p]
		} else if i.mask[p] != 0 {
			a = 0
		}
		copy(out.Pix[4*p:4*p+3], i.rgb[3*p:3*p+3])
		out.Pix[4*p+3] = a
	}
	return out, nil
}

// Composite draws at the top-left position, clipped to dst. The affected region
// must be opaque RGBA; a non-opaque pixel returns ErrIconBackground before any
// write. Invalid image storage or overflowing coordinates return ErrInvalid.
// It does not scale. Alpha composition matches DrawIconEx's source quantization
// and destination rounding; legacy pixels use (destination AND mask) XOR color.
// Draw on a display copy if the underlying framebuffer must remain unchanged.
func (i *IconImage) Composite(dst *image.RGBA, at image.Point) error {
	if i == nil || !validIconDestination(dst) {
		return ErrInvalid
	}
	maxInt := int(^uint(0) >> 1)
	if at.X > maxInt-i.width || at.Y > maxInt-i.height {
		return ErrInvalid
	}
	r := image.Rectangle{Min: at, Max: image.Pt(at.X+i.width, at.Y+i.height)}.Intersect(dst.Rect)
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			if dst.Pix[dst.PixOffset(x, y)+3] != 255 {
				return ErrIconBackground
			}
		}
	}
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			p := (y-at.Y)*i.width + (x - at.X)
			off := dst.PixOffset(x, y)
			for c := 0; c < 3; c++ {
				if i.alpha != nil {
					a := int(i.alpha[p])
					dst.Pix[off+c] = byte(int(i.rgb[3*p+c])*a/255 + (int(dst.Pix[off+c])*(255-a)+127)/255)
				} else {
					dst.Pix[off+c] = dst.Pix[off+c]&i.mask[p] ^ i.rgb[3*p+c]
				}
			}
		}
	}
	return nil
}

func validIconDestination(dst *image.RGBA) bool {
	if dst == nil || dst.Stride < 0 || dst.Rect.Max.X < dst.Rect.Min.X || dst.Rect.Max.Y < dst.Rect.Min.Y {
		return false
	}
	w := uint(dst.Rect.Max.X) - uint(dst.Rect.Min.X)
	h := uint(dst.Rect.Max.Y) - uint(dst.Rect.Min.Y)
	maxInt := ^uint(0) >> 1
	if w > maxInt/4 || h > maxInt {
		return false
	}
	if w == 0 || h == 0 {
		return true
	}
	row := int(w) * 4
	return dst.Stride >= row && len(dst.Pix) >= row && int(h)-1 <= (len(dst.Pix)-row)/dst.Stride
}
