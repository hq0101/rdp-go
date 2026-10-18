package cliprdr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/png"
	"math/bits"
)

const MaxImagePixels = 16 << 20
const MaxImageDimension = 16384

var ErrImage = errors.New("cliprdr: invalid, unsupported or oversized clipboard image")

func imageSize(w, h int) bool {
	return w > 0 && h > 0 && w <= MaxImageDimension && h <= MaxImageDimension && int64(w)*int64(h) <= MaxImagePixels
}

// DecodeDIB reads a packed clipboard DIB, without a BMP file header. Supports
// CORE/INFO/V4/V5, 1/4/8-bit palettes, 16/24/32-bit RGB and RGB(A) bitfields.
// RLE/JPEG/PNG-in-DIB and color-managed profiles are rejected explicitly; no
// profile file path is ever opened. Use DecodePNG for registered PNG data.
func DecodeDIB(b []byte) (*image.NRGBA, error) {
	if len(b) < 12 || len(b) > MaxDataBytes {
		return nil, ErrImage
	}
	u16 := func(i int) uint16 { return binary.LittleEndian.Uint16(b[i:]) }
	u32 := func(i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }
	head := int(u32(0))
	if head != 12 && head != 40 && head != 108 && head != 124 || head > len(b) {
		return nil, ErrImage
	}
	var w, h, depth, palette int
	var compression, sizeImage uint32
	bottom := true
	entry := 4
	var masks [4]uint32
	if head == 12 {
		w = int(u16(4))
		h = int(u16(6))
		depth = int(u16(10))
		if u16(8) != 1 || (depth != 1 && depth != 4 && depth != 8 && depth != 24) {
			return nil, ErrImage
		}
		entry = 3
	} else {
		w = int(int32(u32(4)))
		signedH := int64(int32(u32(8)))
		if signedH < 0 {
			bottom = false
			signedH = -signedH
		}
		if signedH > MaxImageDimension {
			return nil, ErrImage
		}
		h = int(signedH)
		depth = int(u16(14))
		if u16(12) != 1 {
			return nil, ErrImage
		}
		compression = u32(16)
		sizeImage = u32(20)
		palette = int(u32(32))
	}
	if !imageSize(w, h) || (depth != 1 && depth != 4 && depth != 8 && depth != 16 && depth != 24 && depth != 32) || palette < 0 || palette > 256 {
		return nil, ErrImage
	}
	if compression != 0 && compression != 3 {
		return nil, ErrImage
	}
	if compression == 3 && depth != 16 && depth != 32 {
		return nil, ErrImage
	}
	offset := head
	if head >= 108 {
		// Calibrated RGB with all-zero endpoints/gamma is a common untagged bitmap.
		// Non-default profiles need a real color conversion rather than silent sRGB.
		cs := u32(56)
		if cs != 0 && cs != 0x73524742 && cs != 0x57696e20 {
			return nil, ErrImage
		}
		if cs == 0 {
			for _, v := range b[60:108] {
				if v != 0 {
					return nil, ErrImage
				}
			}
		}
		if head == 124 && (u32(112) != 0 || u32(116) != 0) {
			return nil, ErrImage
		}
	}
	if compression == 3 {
		if head == 40 {
			if len(b) < 52 {
				return nil, ErrImage
			}
			offset = 52
		}
		for i := 0; i < 3; i++ {
			masks[i] = u32(40 + i*4)
		}
		if head >= 108 {
			masks[3] = u32(52)
		}
	} else if depth == 16 {
		masks = [4]uint32{0x7c00, 0x3e0, 0x1f, 0}
	} else if depth == 32 {
		masks = [4]uint32{0xff0000, 0xff00, 0xff, 0}
	}
	if depth == 16 || depth == 32 {
		var used uint32
		for i, m := range masks {
			if m == 0 {
				if i < 3 {
					return nil, ErrImage
				}
				continue
			}
			shift := bits.TrailingZeros32(m)
			n := m >> shift
			if n&(n+1) != 0 || m&used != 0 || depth == 16 && m > 0xffff {
				return nil, ErrImage
			}
			used |= m
		}
	}
	if depth <= 8 {
		if palette == 0 {
			palette = 1 << depth
		}
		if palette > 1<<depth {
			return nil, ErrImage
		}
	}
	if offset+palette*entry > len(b) {
		return nil, ErrImage
	}
	table := b[offset : offset+palette*entry]
	offset += palette * entry
	stride := (w*depth + 31) / 32 * 4
	need := stride * h
	if need > len(b)-offset || sizeImage != 0 && (uint64(sizeImage) < uint64(need) || uint64(sizeImage) > uint64(len(b)-offset)) {
		return nil, ErrImage
	}
	out := image.NewNRGBA(image.Rect(0, 0, w, h))
	pixels := b[offset : offset+need]
	component := func(v, m uint32, alpha bool) uint8 {
		if m == 0 {
			if alpha {
				return 255
			}
			return 0
		}
		n := m >> bits.TrailingZeros32(m)
		x := (v & m) >> bits.TrailingZeros32(m)
		return uint8((uint64(x)*255 + uint64(n)/2) / uint64(n))
	}
	for y := 0; y < h; y++ {
		row := y
		if bottom {
			row = h - 1 - y
		}
		src := pixels[row*stride:]
		dst := out.Pix[y*out.Stride:]
		for x := 0; x < w; x++ {
			var r, g, bl, a byte
			a = 255
			switch depth {
			case 1, 4, 8:
				shift := 8 - depth - (x * depth % 8)
				index := int(src[x*depth/8]>>shift) & ((1 << depth) - 1)
				if index >= palette {
					return nil, ErrImage
				}
				q := table[index*entry:]
				bl, g, r = q[0], q[1], q[2]
			case 24:
				q := src[x*3:]
				bl, g, r = q[0], q[1], q[2]
			case 16, 32:
				var v uint32
				if depth == 16 {
					v = uint32(binary.LittleEndian.Uint16(src[x*2:]))
				} else {
					v = binary.LittleEndian.Uint32(src[x*4:])
				}
				r = component(v, masks[0], false)
				g = component(v, masks[1], false)
				bl = component(v, masks[2], false)
				a = component(v, masks[3], true)
			}
			i := x * 4
			dst[i], dst[i+1], dst[i+2], dst[i+3] = r, g, bl, a
		}
	}
	return out, nil
}

// EncodeDIBV5 produces top-down, non-premultiplied BGRA with explicit masks and
// sRGB color space. Windows can synthesize CF_DIB/CF_BITMAP from this format.
func EncodeDIBV5(img image.Image) ([]byte, error) {
	if img == nil {
		return nil, ErrImage
	}
	r := img.Bounds()
	w, h := r.Dx(), r.Dy()
	if !imageSize(w, h) || int64(w)*int64(h)*4+124 > MaxDataBytes {
		return nil, ErrImage
	}
	b := make([]byte, 124+w*h*4)
	put := func(i int, v uint32) { binary.LittleEndian.PutUint32(b[i:], v) }
	put(0, 124)
	put(4, uint32(w))
	put(8, uint32(-int32(h)))
	binary.LittleEndian.PutUint16(b[12:], 1)
	binary.LittleEndian.PutUint16(b[14:], 32)
	put(16, 3)
	put(20, uint32(w*h*4))
	put(40, 0xff0000)
	put(44, 0xff00)
	put(48, 0xff)
	put(52, 0xff000000)
	put(56, 0x73524742)
	put(108, 4)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.NRGBAModel.Convert(img.At(r.Min.X+x, r.Min.Y+y)).(color.NRGBA)
			i := 124 + (y*w+x)*4
			b[i], b[i+1], b[i+2], b[i+3] = c.B, c.G, c.R, c.A
		}
	}
	return b, nil
}

func DecodePNG(b []byte) (image.Image, error) {
	if len(b) > MaxDataBytes {
		return nil, ErrImage
	}
	c, e := png.DecodeConfig(bytes.NewReader(b))
	if e != nil || !imageSize(c.Width, c.Height) {
		return nil, ErrImage
	}
	img, e := png.Decode(bytes.NewReader(b))
	if e != nil {
		return nil, ErrImage
	}
	return img, nil
}

type imageWriter struct{ bytes.Buffer }

func (w *imageWriter) Write(b []byte) (int, error) {
	if len(b) > MaxDataBytes-w.Len() {
		return 0, ErrImage
	}
	return w.Buffer.Write(b)
}
func EncodePNG(img image.Image) ([]byte, error) {
	if img == nil || !imageSize(img.Bounds().Dx(), img.Bounds().Dy()) {
		return nil, ErrImage
	}
	w := new(imageWriter)
	if e := png.Encode(w, img); e != nil {
		return nil, e
	}
	return w.Bytes(), nil
}
func (c *Client) PublishImage(img image.Image) ([]byte, error) {
	d, e := EncodeDIBV5(img)
	if e != nil {
		return nil, e
	}
	p, e := EncodePNG(img)
	if e != nil {
		return nil, e
	}
	return c.Publish([]Data{{Format{ID: 0xc002, Name: PNGName}, p}, {Format{ID: DIBV5}, d}})
}
