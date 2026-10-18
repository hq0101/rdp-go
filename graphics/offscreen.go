package graphics

import "image"

// Must match the optional offscreen capability in pdu.ConfirmGraphics.
const offscreenEntries = 100
const offscreenCacheBytes = 7680 * 1024
const primarySurface = 0xffff

func (d *orderDecoder) readAlternate(r *orderReader, flags byte, depth uint16, decoded *int) error {
	if flags&3 != 2 {
		return ErrInvalid
	}
	switch flags >> 2 {
	case 0:
		id := r.word()
		if r.err != nil || id != primarySurface && (id >= offscreenEntries || d.offscreen[id] == nil) {
			return ErrInvalid
		}
		d.target = id
		d.stats.SwitchSurface++
	case 1:
		encoded := r.word()
		id := encoded & 0x7fff
		w, h := int(r.word()), int(r.word())
		if depth == 0 {
			depth = 32
		}
		if r.err != nil || (depth != 24 && depth != 32) || id >= offscreenEntries || w < 1 || h < 1 || w > maxDimension || h > maxDimension {
			return ErrInvalid
		}
		if encoded&0x8000 != 0 {
			count := int(r.word())
			if count > offscreenEntries {
				return ErrInvalid
			}
			for i := 0; i < count; i++ {
				index := r.word()
				if r.err != nil || index >= offscreenEntries {
					return ErrInvalid
				}
				d.offscreenBytes -= d.offscreenSizes[index]
				d.offscreen[index], d.offscreenSizes[index] = nil, 0
			}
		}
		size := ((w*int(depth/8) + 3) &^ 3) * h
		nextBytes := d.offscreenBytes - d.offscreenSizes[id] + size
		*decoded += w * h
		if nextBytes > offscreenCacheBytes || *decoded > MaxPixels {
			return ErrInvalid
		}
		img := image.NewRGBA(image.Rect(0, 0, w, h))
		for i := 3; i < len(img.Pix); i += 4 {
			img.Pix[i] = 255
		}
		d.offscreen[id], d.offscreenSizes[id], d.offscreenBytes = img, size, nextBytes
		d.stats.CreateOffscreen++
	default:
		return ErrUnsupported
	}
	return nil
}
