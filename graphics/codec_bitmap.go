package graphics

import (
	"fmt"
	"image"
)

// Extended bitmap pixels are shared by Surface Commands and Revision 3 caches.
// Both consumers replace opaque desktop pixels; they do not alpha-blend them.
func decodeCodecBitmap(b []byte, w, h int, depth, codec byte, allowNS bool) (*image.RGBA, error) {
	if w < 1 || h < 1 || w > maxDimension || h > maxDimension || w*h > MaxPixels {
		return nil, ErrInvalid
	}
	if codec == 1 && allowNS && (depth == 24 || depth == 32) {
		decoded, err := DecodeNSCodec(b, w, h)
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(decoded.Pix); i += 4 {
			decoded.Pix[i+3] = 255
			if depth == 24 {
				decoded.Pix[i], decoded.Pix[i+2] = decoded.Pix[i+2], decoded.Pix[i]
			}
		}
		return &image.RGBA{Pix: decoded.Pix, Stride: decoded.Stride, Rect: decoded.Rect}, nil
	}
	if codec != 0 || (depth != 16 && depth != 24 && depth != 32) {
		return nil, fmt.Errorf("%w: bitmap codec %d/%d bpp", ErrUnsupported, codec, depth)
	}
	bytesPerPixel := int(depth) / 8
	stride := (w*bytesPerPixel + 3) &^ 3
	if len(b) != stride*h {
		return nil, ErrInvalid
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			src, dst := ((h-1-y)*stride + x*bytesPerPixel), (y*w+x)*4
			if depth == 16 {
				v := uint32(b[src]) | uint32(b[src+1])<<8
				g := (v >> 5) & 63
				img.Pix[dst], img.Pix[dst+1], img.Pix[dst+2] = expand5(v>>11), byte(g<<2|g>>4), expand5(v)
			} else {
				img.Pix[dst], img.Pix[dst+1], img.Pix[dst+2] = b[src+2], b[src+1], b[src]
			}
			img.Pix[dst+3] = 255
		}
	}
	return img, nil
}
