// Package graphics decodes RDP bitmaps and basic GDI drawing orders without a GUI
// or native dependencies. It also provides Planar, NSCodec, Alpha and ClearCodec
// decoders, and RemoteFX/Progressive tile decoding. AVC is not integrated.
package graphics

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
)

var ErrInvalid = errors.New("rdp graphics: invalid graphics update")
var ErrUnsupported = errors.New("rdp graphics: unsupported pixel format or update")

// MaxPixels bounds decoded allocations per update and per framebuffer.
const MaxPixels = 16 << 20
const maxDimension = 8192

// Bitmap contains owned top-down RGBA pixels and their desktop destination.
// Image can be wider than Bounds because RDP permits padded/cropped rectangles.
type Bitmap struct {
	Bounds image.Rectangle
	Image  *image.RGBA
}

// DecodeBitmapUpdate accepts a TS_UPDATE_BITMAP_DATA payload from either output path. It handles
// 15/16/24-bit raw and interleaved RLE data, plus raw and RDP 6.0 planar 32-bit
// bitmaps. Desktop updates are opaque; DecodePlanar separately preserves alpha.
// Palette-indexed pixels are not implemented.
// No decoded rectangles are returned if any rectangle is malformed.
func DecodeBitmapUpdate(b []byte) ([]Bitmap, error) {
	if len(b) < 4 || binary.LittleEndian.Uint16(b) != 1 {
		return nil, ErrInvalid
	}
	n := int(binary.LittleEndian.Uint16(b[2:]))
	b = b[4:]
	if n == 0 || n > 4096 || n > len(b)/18 {
		return nil, ErrInvalid
	}
	var out []Bitmap
	total := 0
	for i := 0; i < n; i++ {
		if len(b) < 18 {
			return nil, ErrInvalid
		}
		var h [9]int
		for j := range h {
			h[j] = int(binary.LittleEndian.Uint16(b[j*2:]))
		}
		b = b[18:]
		left, top, right, bottom, w, height, depth, flags, size := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
		if w < 1 || height < 1 || w > maxDimension || height > maxDimension || right < left || bottom < top || right >= maxDimension || bottom >= maxDimension || right-left+1 > w || bottom-top+1 > height || size > len(b) || flags & ^0x401 != 0 || flags == 0x400 {
			return nil, ErrInvalid
		}
		total += w * height
		if total > MaxPixels {
			return nil, ErrInvalid
		}
		if depth != 15 && depth != 16 && depth != 24 && depth != 32 {
			return nil, fmt.Errorf("%w: %d bpp", ErrUnsupported, depth)
		}
		data := b[:size]
		b = b[size:]
		pixelSize := (depth + 7) / 8
		var pixels []uint32
		var planar *image.NRGBA
		if flags&1 != 0 {
			if flags&0x400 == 0 {
				if len(data) < 8 || binary.LittleEndian.Uint16(data) != 0 || int(binary.LittleEndian.Uint16(data[2:])) != len(data)-8 {
					return nil, ErrInvalid
				}
				// Width/size fields are redundant; bounds come from TS_BITMAP_DATA.
				data = data[8:]
			}
			var err error
			if depth == 32 {
				planar, err = DecodePlanar(data, w, height)
			} else {
				pixels, err = interleaved(data, w, height, depth)
			}
			if err != nil {
				return nil, err
			}
		} else {
			stride := (w*pixelSize + 3) &^ 3
			if len(data) != stride*height {
				return nil, ErrInvalid
			}
			pixels = make([]uint32, w*height)
			for y := 0; y < height; y++ {
				for x := 0; x < w; x++ {
					off := y*stride + x*pixelSize
					var v uint32
					for k := 0; k < pixelSize; k++ {
						v |= uint32(data[off+k]) << uint(8*k)
					}
					pixels[y*w+x] = v
				}
			}
		}
		if planar != nil {
			// TS_BITMAP_DATA replaces opaque desktop pixels; consume and validate
			// alpha but do not blend the update with the previous screen.
			for off := 3; off < len(planar.Pix); off += 4 {
				planar.Pix[off] = 255
			}
			img := &image.RGBA{Pix: planar.Pix, Stride: planar.Stride, Rect: planar.Rect}
			out = append(out, Bitmap{Bounds: image.Rect(left, top, right+1, bottom+1), Image: img})
			continue
		}
		img := image.NewRGBA(image.Rect(0, 0, w, height))
		for y := 0; y < height; y++ {
			for x := 0; x < w; x++ {
				v := pixels[(height-1-y)*w+x]
				off := y*img.Stride + x*4
				r, g, blue := byte(v>>16), byte(v>>8), byte(v)
				if depth == 15 {
					r = expand5(v >> 10)
					g = expand5(v >> 5)
					blue = expand5(v)
				} else if depth == 16 {
					r = expand5(v >> 11)
					u := (v >> 5) & 63
					g = byte(u<<2 | u>>4)
					blue = expand5(v)
				}
				img.Pix[off], img.Pix[off+1], img.Pix[off+2], img.Pix[off+3] = r, g, blue, 255
			}
		}
		out = append(out, Bitmap{Bounds: image.Rect(left, top, right+1, bottom+1), Image: img})
	}
	if len(b) != 0 {
		return nil, ErrInvalid
	}
	return out, nil
}
func expand5(v uint32) byte { v &= 31; return byte(v<<3 | v>>2) }
