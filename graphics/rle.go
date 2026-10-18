package graphics

import "encoding/binary"

// interleaved decodes MS-RDPBCGR interleaved RLE to bottom-up native pixels.
// Every order must consume input and fit the advertised output area.
func interleaved(src []byte, width, height, depth int) ([]uint32, error) {
	if width < 1 || height < 1 || width > maxDimension || height > maxDimension || width*height > MaxPixels {
		return nil, ErrInvalid
	}
	if depth != 15 && depth != 16 && depth != 24 {
		return nil, ErrUnsupported
	}
	bytesPerPixel := (depth + 7) / 8
	white := uint32(1)<<depth - 1
	fg := white
	out := make([]uint32, width*height)
	pos, cursor := 0, 0
	previousBG, firstLine := false, true
	readPixel := func() (uint32, bool) {
		if len(src)-cursor < bytesPerPixel {
			return 0, false
		}
		var v uint32
		for j := 0; j < bytesPerPixel; j++ {
			v |= uint32(src[cursor+j]) << uint(8*j)
		}
		cursor += bytesPerPixel
		return v, true
	}
	background := func() uint32 {
		if pos < width {
			return 0
		}
		return out[pos-width]
	}
	for cursor < len(src) {
		if firstLine && pos >= width {
			firstLine = false
			previousBG = false
		}
		h := src[cursor]
		cursor++
		code, n := int(h>>5), int(h&31)
		if h >= 0xc0 {
			code, n = int(h>>4), int(h&15)
		}
		if h >= 0xf0 {
			code = int(h)
			n = 0
		}
		fgbg := code == 2 || code == 13
		switch {
		case code == 0xf9 || code == 0xfa:
			n = 8
		case code == 0xfd || code == 0xfe:
			n = 1
		case code >= 0xf0:
			if code != 0xf0 && code != 0xf1 && code != 0xf2 && code != 0xf3 && code != 0xf4 && code != 0xf6 && code != 0xf7 && code != 0xf8 {
				return nil, ErrInvalid
			}
			if len(src)-cursor < 2 {
				return nil, ErrInvalid
			}
			n = int(binary.LittleEndian.Uint16(src[cursor:]))
			cursor += 2
		case code <= 4 || code == 12 || code == 13 || code == 14:
			if n == 0 {
				if cursor == len(src) {
					return nil, ErrInvalid
				}
				n = int(src[cursor])
				cursor++
				if fgbg {
					n++
				} else if h >= 0xc0 {
					n += 16
				} else {
					n += 32
				}
			} else if fgbg {
				n *= 8
			}
		default:
			return nil, ErrInvalid
		}
		if code == 14 || code == 0xf8 {
			n *= 2
		}
		if n == 0 || n > len(out)-pos {
			return nil, ErrInvalid
		}
		if code == 12 || code == 13 || code == 0xf6 || code == 0xf7 {
			v, ok := readPixel()
			if !ok {
				return nil, ErrInvalid
			}
			fg = v
		}
		bg := code == 0 || code == 0xf0
		switch code {
		case 0, 0xf0:
			if previousBG {
				out[pos] = background() ^ fg
				pos++
				n--
			}
			for ; n > 0; n-- {
				out[pos] = background()
				pos++
			}
		case 1, 12, 0xf1, 0xf6:
			for ; n > 0; n-- {
				out[pos] = background() ^ fg
				pos++
			}
		case 3, 0xf3:
			v, ok := readPixel()
			if !ok {
				return nil, ErrInvalid
			}
			for ; n > 0; n-- {
				out[pos] = v
				pos++
			}
		case 4, 0xf4:
			if n > (len(src)-cursor)/bytesPerPixel {
				return nil, ErrInvalid
			}
			for ; n > 0; n-- {
				v, _ := readPixel()
				out[pos] = v
				pos++
			}
		case 14, 0xf8:
			a, ok := readPixel()
			if !ok {
				return nil, ErrInvalid
			}
			b, ok := readPixel()
			if !ok {
				return nil, ErrInvalid
			}
			for ; n > 0; n -= 2 {
				out[pos], out[pos+1] = a, b
				pos += 2
			}
		case 2, 13, 0xf2, 0xf7, 0xf9, 0xfa:
			for n > 0 {
				var mask byte
				if code == 0xf9 {
					mask = 3
				} else if code == 0xfa {
					mask = 5
				} else {
					if cursor == len(src) {
						return nil, ErrInvalid
					}
					mask = src[cursor]
					cursor++
				}
				count := min(n, 8)
				for j := 0; j < count; j++ {
					v := background()
					if mask&(1<<uint(j)) != 0 {
						v ^= fg
					}
					out[pos] = v
					pos++
				}
				n -= count
			}
		case 0xfd:
			out[pos] = white
			pos++
		case 0xfe:
			out[pos] = 0
			pos++
		}
		previousBG = bg
	}
	if pos != len(out) {
		return nil, ErrInvalid
	}
	return out, nil
}
