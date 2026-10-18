package graphics

import (
	"encoding/binary"
	"image"
)

func (d *orderDecoder) readCacheV3(b []byte, extra uint16, copied *[3]bool, decoded *int, allowNS bool) error {
	if len(b) < 22 {
		return ErrInvalid
	}
	id, depthID, flags := int(extra&7), (extra>>3)&15, extra>>7
	if id >= 3 || flags & ^uint16(8|16) != 0 {
		return ErrInvalid
	}
	depth := map[uint16]byte{4: 16, 5: 24, 6: 32}[depthID]
	if depth == 0 || b[10] != depth {
		return ErrUnsupported
	}
	index := binary.LittleEndian.Uint16(b)
	waiting := flags&16 != 0
	if waiting && index != 32767 || !waiting && int(index) >= cacheEntries[id] {
		return ErrInvalid
	}
	// The two persistent key fields are always present, but never saved to disk.
	exFlags, codec := b[11], b[13]
	w, h := int(binary.LittleEndian.Uint16(b[14:])), int(binary.LittleEndian.Uint16(b[16:]))
	if exFlags&^byte(1) != 0 || b[12] != 0 || w == 0 || h == 0 || w > maxDimension || h > maxDimension || w*h > (256<<(2*id)) {
		return ErrInvalid
	}
	offset := 22
	if exFlags&1 != 0 {
		offset += 24
	}
	size := uint64(binary.LittleEndian.Uint32(b[18:]))
	if offset > len(b) || size != uint64(len(b)-offset) {
		return ErrInvalid
	}
	*decoded += w * h
	if *decoded > MaxPixels {
		return ErrInvalid
	}
	img, err := decodeCodecBitmap(b[offset:], w, h, depth, codec, allowNS)
	if err != nil {
		return err
	}
	if waiting {
		d.waiting[id] = img
	} else {
		if !copied[id] {
			m := make(map[uint16]*image.RGBA, len(d.cache[id])+1)
			for key, entry := range d.cache[id] {
				m[key] = entry
			}
			d.cache[id], copied[id] = m, true
		}
		d.cache[id][index] = img
	}
	d.stats.CacheBitmapV3++
	if codec == 1 {
		d.stats.CacheBitmapNSCodec++
	}
	return nil
}
