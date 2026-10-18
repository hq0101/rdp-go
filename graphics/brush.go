package graphics

import "encoding/binary"

// The protocol has independent 64-entry mono and color brush caches. Entries
// are immutable so a replacement cannot change an earlier operation in a batch.
type cachedBrush struct {
	format  byte
	mono    [8]byte // top-down, MSB is the leftmost pixel
	colors  [64][3]byte
	indices [64]byte
}

func (d *orderDecoder) readBrush(b []byte) error {
	if len(b) < 6 || b[0] >= 64 || b[2] != 8 || b[3] != 8 {
		return ErrInvalid
	}
	index, format := b[0], b[1]
	size := int(b[5])
	data := b[6:]
	// A raw 32-bpp 8x8 brush has 256 bytes. The one-byte iBytes wraps to zero;
	// accept that case only when the secondary order boundary proves the size.
	if format == 6 && size == 0 {
		size = 256
	}
	if size != len(data) {
		return ErrInvalid
	}
	brush := &cachedBrush{format: format}
	if format == 1 {
		if size != 8 {
			return ErrInvalid
		}
		for y := 0; y < 8; y++ {
			brush.mono[y] = data[7-y]
		}
		d.brushes[0][index] = brush
	} else {
		bytesPerPixel := int(format) - 2
		if format < 3 || format > 6 {
			return ErrUnsupported
		}
		compressed := size == 16+4*bytesPerPixel
		if !compressed && size != 64*bytesPerPixel {
			return ErrInvalid
		}
		for y := 0; y < 8; y++ {
			for x := 0; x < 8; x++ {
				pos := (7-y)*8 + x
				pixel := data
				if compressed {
					index := (data[pos/4] >> uint(6-2*(pos%4))) & 3
					pixel = data[16+int(index)*bytesPerPixel:]
				} else {
					pixel = data[pos*bytesPerPixel:]
				}
				i := y*8 + x
				switch format {
				case 3:
					brush.indices[i] = pixel[0]
				case 4:
					v := uint32(binary.LittleEndian.Uint16(pixel))
					g := (v >> 5) & 63
					brush.colors[i] = [3]byte{expand5(v >> 11), byte(g<<2 | g>>4), expand5(v)}
				default:
					brush.colors[i] = [3]byte{pixel[2], pixel[1], pixel[0]}
				}
			}
		}
		d.brushes[1][index] = brush
	}
	d.stats.CacheBrush++
	return nil
}

func (d *orderDecoder) brush(style, index byte, allowed bool) (*cachedBrush, error) {
	if !allowed {
		return nil, ErrUnsupported
	}
	format := style & 15
	if style != 0x80|format || index >= 64 {
		return nil, ErrInvalid
	}
	cache := 1
	if format == 1 {
		cache = 0
	}
	b := d.brushes[cache][index]
	if b == nil || b.format != format {
		return nil, ErrInvalid
	}
	if format == 3 {
		if d.palette == nil {
			return nil, ErrInvalid
		}
		resolved := *b
		for i, v := range b.indices {
			resolved.colors[i] = d.palette[v]
		}
		b = &resolved
	}
	return b, nil
}

// Palette updates supply the current palette used by indexed color brushes.
// This does not enable 8-bpp Bitmap Updates or palette-indexed primary colors.
func (f *Framebuffer) applyPalette(b []byte) error {
	palette, err := parsePalette(b)
	if err != nil {
		return err
	}
	f.orders.palette = palette
	return nil
}

func parsePalette(b []byte) (*[256][3]byte, error) {
	if len(b) != 8+256*3 || binary.LittleEndian.Uint16(b) != 2 || binary.LittleEndian.Uint32(b[4:]) != 256 {
		return nil, ErrInvalid
	}
	palette := new([256][3]byte)
	for i := range palette {
		copy(palette[i][:], b[8+3*i:11+3*i])
	}
	return palette, nil
}
