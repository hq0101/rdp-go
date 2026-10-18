package graphics

import (
	"encoding/binary"
	"fmt"
	"image"
	"image/draw"
)

// SurfaceResult reports pixels committed to the visible framebuffer and frames
// finished in this call. Send acknowledgements only after successful application.
type SurfaceResult struct {
	Dirty           []image.Rectangle
	CompletedFrames []uint32
}

type SurfaceStats struct {
	SetBits    uint64 `json:"set_bits"`
	StreamBits uint64 `json:"stream_bits"`
	Frames     uint64 `json:"frames"`
	NSCodec    uint64 `json:"nscodec"`
}

type surfaceState struct {
	open    bool
	id      uint32
	pending *image.RGBA
	dirty   image.Rectangle
	stats   SurfaceStats
}

func (f *Framebuffer) SurfaceStats() SurfaceStats {
	if f == nil {
		return SurfaceStats{}
	}
	return f.surface.stats
}

type surfaceOperation struct {
	typ     uint16
	bitmap  Bitmap
	action  uint16
	id      uint32
	nscodec bool
}

// ApplySurfaceCommands applies fast-path code 4, with raw codec 0 at 32 bpp,
// and NSCodec (codec 1, 24/32 bpp) when AllowNSCodec is true.
// Marked frames remain private until END, even across multiple updates. Resize
// discards an incomplete frame. Validation is atomic per call: neither pixels,
// frame state nor counters change on error.
func (f *Framebuffer) ApplySurfaceCommands(b []byte) (SurfaceResult, error) {
	var result SurfaceResult
	if f == nil || f.pixels == nil || len(b) < 2 || len(b) > 1<<20 {
		return result, ErrInvalid
	}
	var ops []surfaceOperation
	open, id := f.surface.open, f.surface.id
	total := 0
	work := 0
	for len(b) > 0 {
		if len(b) < 2 || len(ops) >= 4096 {
			return result, ErrInvalid
		}
		typ := binary.LittleEndian.Uint16(b)
		switch typ {
		case 1, 6:
			if len(b) < 22 {
				return result, ErrInvalid
			}
			left, top := int(binary.LittleEndian.Uint16(b[2:])), int(binary.LittleEndian.Uint16(b[4:]))
			right, bottom := int(binary.LittleEndian.Uint16(b[6:])), int(binary.LittleEndian.Uint16(b[8:]))
			depth, flags, reserved, codec := b[10], b[11], b[12], b[13]
			w, h := int(binary.LittleEndian.Uint16(b[14:])), int(binary.LittleEndian.Uint16(b[16:]))
			size := uint64(binary.LittleEndian.Uint32(b[18:]))
			nscodec := codec == 1 && f.AllowNSCodec
			if codec != 0 && !nscodec || depth != 32 && !(nscodec && depth == 24) {
				return result, fmt.Errorf("%w: surface codec %d/%d bpp", ErrUnsupported, codec, depth)
			}
			if flags&^byte(1) != 0 || reserved != 0 || w == 0 || h == 0 || w > maxDimension || h > maxDimension {
				return result, ErrInvalid
			}
			total += w * h
			work += w * h
			if total > MaxPixels || work > 4*MaxPixels {
				return result, ErrInvalid
			}
			offset := 22
			if flags&1 != 0 {
				offset += 24
			} // Nonessential ID and timestamp, not pixel bytes.
			if offset > len(b) || !nscodec && size != uint64(w)*uint64(h)*4 || size > uint64(len(b)-offset) {
				return result, ErrInvalid
			}
			bounds := image.Rect(left, top, left+w, top+h)
			if typ == 6 {
				if right <= left || bottom <= top || right-left > w || bottom-top > h {
					return result, ErrInvalid
				}
				bounds = image.Rect(left, top, right, bottom)
			}
			if !bounds.In(f.pixels.Bounds()) {
				return result, ErrInvalid
			}
			pixels := b[offset : offset+int(size)]
			img, err := decodeCodecBitmap(pixels, w, h, depth, codec, f.AllowNSCodec)
			if err != nil {
				return result, err
			}
			ops = append(ops, surfaceOperation{typ: typ, bitmap: Bitmap{Bounds: bounds, Image: img}, nscodec: nscodec})
			b = b[offset+int(size):]
		case 4:
			if len(b) < 8 {
				return result, ErrInvalid
			}
			action, frameID := binary.LittleEndian.Uint16(b[2:]), binary.LittleEndian.Uint32(b[4:])
			if action == 0 {
				work += f.pixels.Bounds().Dx() * f.pixels.Bounds().Dy()
				if work > 4*MaxPixels {
					return result, ErrInvalid
				}
				if open {
					return result, ErrInvalid
				}
				open, id = true, frameID
			} else if action == 1 {
				if !open || frameID != id {
					return result, ErrInvalid
				}
				open = false
			} else {
				return result, ErrInvalid
			}
			ops = append(ops, surfaceOperation{typ: typ, action: action, id: frameID})
			b = b[8:]
		default:
			return result, fmt.Errorf("%w: surface command %d", ErrUnsupported, typ)
		}
	}
	// Everything that can fail has been checked. At most one desktop-sized
	// staging image is retained between calls; repeated BEGIN cannot grow a queue.
	for _, op := range ops {
		if op.typ == 4 {
			if op.action == 0 {
				f.surface.open, f.surface.id = true, op.id
				f.surface.pending, f.surface.dirty = f.Snapshot(), image.Rectangle{}
			} else {
				f.pixels, f.surface.pending = f.surface.pending, nil
				f.surface.open = false
				if !f.surface.dirty.Empty() {
					result.Dirty = append(result.Dirty, f.surface.dirty)
				}
				f.surface.dirty = image.Rectangle{}
				result.CompletedFrames = append(result.CompletedFrames, op.id)
				f.surface.stats.Frames++
			}
			continue
		}
		dst := f.pixels
		if f.surface.open {
			dst = f.surface.pending
		}
		draw.Draw(dst, op.bitmap.Bounds, op.bitmap.Image, image.Point{}, draw.Src)
		if f.surface.open {
			f.surface.dirty = f.surface.dirty.Union(op.bitmap.Bounds)
		} else {
			result.Dirty = append(result.Dirty, op.bitmap.Bounds)
		}
		if op.typ == 1 {
			f.surface.stats.SetBits++
		} else {
			f.surface.stats.StreamBits++
		}
		if op.nscodec {
			f.surface.stats.NSCodec++
		}
	}
	return result, nil
}
