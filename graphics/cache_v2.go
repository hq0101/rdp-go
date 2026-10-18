package graphics

import (
	"encoding/binary"
	"image"
)

// MS-RDPEGDI 2.2.2.2.1.2.7: high bits encode the number of following bytes;
// the value is big-endian, unlike fixed-width RDP fields.
func (r *orderReader) compactWord() uint16 {
	a := r.byte()
	if a&128 == 0 {
		return uint16(a)
	}
	return uint16(a&127)<<8 | uint16(r.byte())
}
func (r *orderReader) compactDword() uint32 {
	a := r.byte()
	v := uint32(a & 63)
	for i := byte(0); i < a>>6; i++ {
		v = v<<8 | uint32(r.byte())
	}
	return v
}

func (d *orderDecoder) readCacheV2(b []byte, extra uint16, compressed bool, copied *[3]bool, decoded *int) error {
	id, depthID, flags := int(extra&7), (extra>>3)&15, extra>>7
	// Only volatile caches are negotiated. Persistent keys must not be supplied.
	if id >= 3 || flags & ^uint16(1|8|16) != 0 {
		return ErrInvalid
	}
	depth := 0
	switch depthID {
	case 4:
		depth = 16
	case 5:
		depth = 24
	case 6:
		depth = 32
	default:
		return ErrUnsupported
	}
	r := orderReader{b: b}
	w := int(r.compactWord())
	h := w
	if flags&1 == 0 {
		h = int(r.compactWord())
	}
	size := r.compactDword()
	index := r.compactWord()
	if r.err != nil || uint64(size) != uint64(len(r.b)) || w == 0 || h == 0 || w > maxDimension || h > maxDimension || w*h > (256<<(2*id)) {
		return ErrInvalid
	}
	waiting := flags&16 != 0
	if waiting && index != 32767 || !waiting && int(index) >= cacheEntries[id] {
		return ErrInvalid
	}
	*decoded += w * h
	if *decoded > MaxPixels {
		return ErrInvalid
	}
	// The advertised cells cannot exceed 4096 pixels. Even raw 32-bpp cells,
	// including scanline padding, fit the bitmap decoder's uint16 length field.
	if size > 65535 {
		return ErrInvalid
	}
	payload := make([]byte, 22, 22+len(r.b))
	binary.LittleEndian.PutUint16(payload, 1)
	binary.LittleEndian.PutUint16(payload[2:], 1)
	for off, v := range map[int]int{8: w - 1, 10: h - 1, 12: w, 14: h, 16: depth, 20: int(size)} {
		binary.LittleEndian.PutUint16(payload[off:], uint16(v))
	}
	if compressed {
		v := uint16(1)
		if flags&8 != 0 {
			v |= 0x400
		}
		binary.LittleEndian.PutUint16(payload[18:], v)
	}
	bitmaps, err := DecodeBitmapUpdate(append(payload, r.b...))
	if err != nil {
		return err
	}
	if waiting {
		d.waiting[id] = bitmaps[0].Image
	} else {
		if !copied[id] {
			m := make(map[uint16]*image.RGBA, len(d.cache[id])+1)
			for key, img := range d.cache[id] {
				m[key] = img
			}
			d.cache[id], copied[id] = m, true
		}
		d.cache[id][index] = bitmaps[0].Image
	}
	d.stats.CacheBitmapV2++
	return nil
}
