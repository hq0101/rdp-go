package graphics

import "image"

// DecodePlanar decodes an MS-RDPEGDI RDP6_BITMAP_STREAM (without the optional
// TS_CD_HEADER) into owned, top-down, straight-alpha pixels. It supports raw or
// RLE planes, omitted alpha, color loss levels 1..7 and chroma subsampling.
// For YCoCg without alpha it applies the Windows 24-bit red/blue correction.
// Desktop bitmap updates use these colors as opaque screen pixels instead.
func DecodePlanar(src []byte, width, height int) (*image.NRGBA, error) {
	if width < 1 || height < 1 || width > maxDimension || height > maxDimension || width*height > MaxPixels || len(src) < 1 {
		return nil, ErrInvalid
	}
	flags := src[0]
	src = src[1:]
	cll, subsampled, rle, noAlpha := flags&7, flags&8 != 0, flags&16 != 0, flags&32 != 0
	if flags&0xc0 != 0 || (subsampled && cll == 0) {
		return nil, ErrInvalid
	}
	// Plane order is A,R,G,B or A,Y,Co,Cg; absent alpha is fully opaque.
	components := []int{3, 0, 1, 2}
	if noAlpha {
		components = components[1:]
	}
	chromaWidth, chromaHeight := width, height
	if subsampled {
		chromaWidth, chromaHeight = (width+1)/2, (height+1)/2
	}
	minimum := 0
	for _, component := range components {
		w, h := width, height
		if subsampled && (component == 1 || component == 2) {
			w, h = chromaWidth, chromaHeight
		}
		if rle {
			minimum += ((w + 46) / 47) * h
		} else {
			minimum += w * h
		}
	}
	// Reject impossible sizes before allocating an image or plane scratch space.
	if len(src) < minimum || (!rle && len(src) > minimum+1) {
		return nil, ErrInvalid
	}
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	if noAlpha {
		for i := 3; i < len(img.Pix); i += 4 {
			img.Pix[i] = 255
		}
	}
	var scratch []byte
	if rle {
		scratch = make([]byte, width*height)
	}
	for _, component := range components {
		w, h, scale := width, height, 1
		if subsampled && (component == 1 || component == 2) {
			w, h, scale = chromaWidth, chromaHeight, 2
		}
		var plane []byte
		if rle {
			plane = scratch[:w*h]
			var err error
			src, err = decodePlaneRLE(src, plane, w, h)
			if err != nil {
				return nil, err
			}
		} else {
			plane, src = src[:w*h], src[w*h:]
		}
		for y := 0; y < height; y++ {
			row := (height - 1 - y) * img.Stride
			for x := 0; x < width; x++ {
				img.Pix[row+x*4+component] = plane[(y/scale)*w+x/scale]
			}
		}
	}
	if (rle && len(src) != 0) || (!rle && len(src) > 1) {
		return nil, ErrInvalid
	}
	if cll != 0 {
		for i := 0; i < len(img.Pix); i += 4 {
			y := int(img.Pix[i])
			// Chroma starts as a signed 9-bit value. Restore its sign after
			// undoing the logical reduction shift, then take the half terms.
			co := signedChroma(img.Pix[i+1], cll) >> 1
			cg := signedChroma(img.Pix[i+2], cll) >> 1
			r, g, b := clampColor(y+co-cg), clampColor(y+cg), clampColor(y-co-cg)
			if noAlpha {
				r, b = b, r
			}
			img.Pix[i], img.Pix[i+1], img.Pix[i+2] = r, g, b
		}
	}
	return img, nil
}

func signedChroma(v byte, shift byte) int {
	n := (int(v) << shift) & 511
	if n&256 != 0 {
		n -= 512
	}
	return n
}
func clampColor(v int) byte { return byte(max(0, min(255, v))) }

// decodePlaneRLE consumes exactly width*height samples and returns the next
// plane's bytes. A subsegment cannot cross scanlines. The last RAW value is
// carried between subsegments, and starts at zero on each new scanline.
func decodePlaneRLE(src, dst []byte, width, height int) ([]byte, error) {
	for y := 0; y < height; y++ {
		var last byte
		for x := 0; x < width; {
			if len(src) == 0 || src[0] == 0 {
				return nil, ErrInvalid
			}
			control := src[0]
			src = src[1:]
			raw, run := int(control>>4), int(control&15)
			if run == 1 {
				raw, run = 0, raw+16
			} else if run == 2 {
				raw, run = 0, raw+32
			}
			if raw+run > width-x || raw > len(src) {
				return nil, ErrInvalid
			}
			for i := 0; i < raw+run; i++ {
				if i < raw {
					last, src = src[0], src[1:]
				}
				value := last
				pos := y*width + x
				if y != 0 {
					delta := last >> 1
					if last&1 != 0 {
						delta = ^delta
					}
					value = dst[pos-width] + delta // intentional 8-bit wrap
				}
				dst[pos] = value
				x++
			}
		}
	}
	return src, nil
}
