package graphics

import (
	"encoding/binary"
	"image"
)

// DecodeNSCodec decodes an MS-RDPNSC NSCODEC_BITMAP_STREAM into owned top-down
// straight-alpha pixels. It handles independently raw/RLE planes, ColorLossLevel
// 1..7, optional alpha and padded chroma subsampling. It uses the AYCoCg inverse
// transform; a caller decoding a Windows 24-bpp source must swap red/blue afterward.
func DecodeNSCodec(src []byte, width, height int) (*image.NRGBA, error) {
	return decodeNSCodec(src, width, height, false)
}

// ClearCodec embeds top-down NSCodec RGB; legacy surface/cache NSCodec uses
// bottom-up scanlines. Scanline orientation is supplied by the outer protocol.
func decodeNSCodec(src []byte, width, height int, topDown bool) (*image.NRGBA, error) {
	if width < 1 || height < 1 || width > maxDimension || height > maxDimension || width*height > MaxPixels || len(src) < 20 {
		return nil, ErrInvalid
	}
	cll, subsampled := src[16], src[17]
	if cll < 1 || cll > 7 || subsampled > 1 {
		return nil, ErrInvalid
	}
	// The two reserved bytes are ignored (MS-RDPNSC section 4).
	lumaWidth, chromaWidth, chromaHeight := width, width, height
	if subsampled != 0 {
		lumaWidth = (width + 7) &^ 7
		chromaWidth, chromaHeight = lumaWidth/2, (height+1)/2
	}
	expected := [4]int{lumaWidth * height, chromaWidth * chromaHeight, chromaWidth * chromaHeight, width * height}
	var sizes [4]int
	total := uint64(20)
	for i := range sizes {
		n := binary.LittleEndian.Uint32(src[i*4:])
		if n == 0 && i != 3 || uint64(n) > uint64(expected[i]) {
			return nil, ErrInvalid
		}
		if n > 0 && int(n) < expected[i] && n < 7 {
			return nil, ErrInvalid
		}
		sizes[i] = int(n)
		total += uint64(n)
	}
	if total != uint64(len(src)) {
		return nil, ErrInvalid
	}
	// One image and one reusable plane scratch area, even when subsampling pads
	// a very narrow source to eight columns. Raw planes alias only this input call.
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	var scratch []byte
	src = src[20:]
	for component, n := range sizes {
		if component == 3 && n == 0 {
			for i := 3; i < len(img.Pix); i += 4 {
				img.Pix[i] = 255
			}
			continue
		}
		plane := src[:n]
		src = src[n:]
		if n < expected[component] {
			if cap(scratch) < expected[component] {
				scratch = make([]byte, expected[component])
			}
			decoded := scratch[:expected[component]]
			if err := decodeNSPlaneRLE(plane, decoded); err != nil {
				return nil, err
			}
			plane = decoded
		}
		stride, scale := width, 1
		if component == 0 {
			stride = lumaWidth
		}
		if subsampled != 0 && (component == 1 || component == 2) {
			stride, scale = chromaWidth, 2
		}
		for y := 0; y < height; y++ {
			row := (height - 1 - y) * img.Stride
			if topDown {
				row = y * img.Stride
			}
			for x := 0; x < width; x++ {
				img.Pix[row+x*4+component] = plane[(y/scale)*stride+x/scale]
			}
		}
	}
	for i := 0; i < len(img.Pix); i += 4 {
		y := int(img.Pix[i])
		co, cg := signedChroma(img.Pix[i+1], cll)>>1, signedChroma(img.Pix[i+2], cll)>>1
		img.Pix[i], img.Pix[i+1], img.Pix[i+2] = clampColor(y+co-cg), clampColor(y+cg), clampColor(y-co-cg)
	}
	return img, nil
}

// RLE is applied to an entire plane, not per scanline. The last four source
// bytes are raw EndData, including equal adjacent bytes; never parse them as runs.
func decodeNSPlaneRLE(src, dst []byte) error {
	if len(src) < 4 || len(dst) < 4 {
		return ErrInvalid
	}
	tail := src[len(src)-4:]
	src = src[:len(src)-4]
	end, pos := len(dst)-4, 0
	for len(src) != 0 {
		v := src[0]
		run, consumed := uint64(1), 1
		if len(src) >= 2 && src[1] == v {
			if len(src) < 3 {
				return ErrInvalid
			}
			run, consumed = uint64(src[2])+2, 3
			if src[2] == 255 {
				if len(src) < 7 {
					return ErrInvalid
				}
				run, consumed = uint64(binary.LittleEndian.Uint32(src[3:])), 7
				if run < 2 {
					return ErrInvalid
				}
			}
		}
		if run > uint64(end-pos) {
			return ErrInvalid
		}
		for i := 0; i < int(run); i++ {
			dst[pos+i] = v
		}
		pos += int(run)
		src = src[consumed:]
	}
	if pos != end {
		return ErrInvalid
	}
	copy(dst[end:], tail)
	return nil
}
