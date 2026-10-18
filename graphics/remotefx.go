package graphics

import (
	"encoding/binary"
	"image"
)

// RemoteFXTile owns a decoded 64x64 opaque tile. Its origin and the frame's
// rectangles are relative to the destination bitmap, not the desktop.
type RemoteFXTile struct {
	Origin image.Point
	Image  *image.NRGBA
}

// RemoteFXFrame contains only changed tiles. Each tile must be clipped to both
// Rectangles and the destination bounds before copying. Pixels outside those
// intersections retain their previous values; filling them with black is wrong.
type RemoteFXFrame struct {
	ID         uint32
	Rectangles []image.Rectangle
	Tiles      []RemoteFXTile
}

// RemoteFXDecoder decodes the MS-RDPRFX 1.0 stream and 64x64 RLGR1/RLGR3 tiles.
// The zero value is ready. Headers survive calls in video mode. Image mode
// requires fresh headers before each frame. Each call contains complete blocks
// and frames; header-only calls are allowed. Calls must be serialized. Value
// copies are independent, and failed calls leave header state unchanged.
// It has no network/capability negotiation, Progressive, or H.264 support.
type RemoteFXDecoder struct {
	headers       byte
	fresh         byte
	width, height int
	imageMode     bool
}

func (d *RemoteFXDecoder) Reset() { *d = RemoteFXDecoder{} }

func (d *RemoteFXDecoder) Decode(data []byte, width, height int) ([]RemoteFXFrame, error) {
	frames, _, err := d.DecodeWithBudget(data, width, height, maxClearWork)
	return frames, err
}

// DecodeWithBudget bounds aggregate plane/tile work; each tile costs 4*4096
// units (three component planes plus RGB). Additional output clipping/copies are
// the caller's responsibility. At most 4096 blocks, rectangles and tiles each
// may be decoded per call, with at most 64 MiB of encoded data and work units.
func (d *RemoteFXDecoder) DecodeWithBudget(data []byte, width, height, budget int) ([]RemoteFXFrame, int, error) {
	if !codecDimensions(width, height) || len(data) == 0 || len(data) > 64<<20 || budget < 0 || budget > maxClearWork {
		return nil, 0, ErrInvalid
	}
	next := *d
	var frames []RemoteFXFrame
	var frame RemoteFXFrame
	phase, blocks, rectCount, tileCount, work := 0, 0, 0, 0, 0
	// Reuse coefficient planes and transform workspace for every tile. Only
	// returned RGB images survive this call; intermediate planes are not cached.
	var coefficients [3][rfxTilePixels]int64
	var transformScratch [rfxTilePixels]int64
	for len(data) > 0 {
		blocks++
		if blocks > 4096 || len(data) < 6 {
			return nil, 0, ErrInvalid
		}
		kind := binary.LittleEndian.Uint16(data)
		size := binary.LittleEndian.Uint32(data[2:])
		if size < 6 || uint64(size) > uint64(len(data)) {
			return nil, 0, ErrInvalid
		}
		r := clearReader{data: data[6:size]}
		data = data[size:]
		if kind != 0xccc0 && next.headers&1 == 0 {
			return nil, 0, ErrInvalid
		}
		if kind >= 0xccc0 && kind <= 0xccc3 && phase != 0 {
			return nil, 0, ErrInvalid
		}
		if kind >= 0xccc3 && kind <= 0xccc7 {
			codec, channel := r.u8(), r.u8()
			wantChannel := byte(0)
			if kind == 0xccc3 {
				wantChannel = 255
			}
			if codec != 1 || channel != wantChannel || r.bad {
				return nil, 0, ErrInvalid
			}
		}
		switch kind {
		case 0xccc0: // SYNC
			if r.u32() != 0xcaccacca || r.u16() != 0x0100 {
				return nil, 0, ErrUnsupported
			}
			// Repeated SYNC starts a new header group without discarding the
			// other valid video-mode headers (the spec allows repeats of any).
			next.headers |= 1
			next.fresh |= 1
		case 0xccc1: // CODEC_VERSIONS
			if r.u8() != 1 || r.u8() != 1 || r.u16() != 0x0100 {
				return nil, 0, ErrUnsupported
			}
			next.headers |= 2
			next.fresh |= 2
		case 0xccc2: // CHANNELS: one channel as required by 3.1.8.3.1
			if r.u8() != 1 || r.u8() != 0 {
				return nil, 0, ErrUnsupported
			}
			w, h := int(r.u16()), int(r.u16())
			if !codecDimensions(w, h) {
				return nil, 0, ErrInvalid
			}
			// The channel describes desktop geometry, not the enclosing GFX
			// update rectangle. A partial update can use different dimensions.
			next.width, next.height = w, h
			next.headers |= 4
			next.fresh |= 4
		case 0xccc3: // CONTEXT
			r.u8() // ctxId SHOULD be ignored
			if r.u16() != 64 {
				return nil, 0, ErrUnsupported
			}
			properties := r.u16()
			if properties&7 & ^uint16(2) != 0 || properties>>3&3 != 1 || properties>>5&15 != 1 || properties>>13&3 != 1 {
				return nil, 0, ErrUnsupported
			}
			// The tile set's entropy identifier, not the context's hint, is used.
			next.imageMode = properties&2 != 0
			next.headers |= 8
			next.fresh |= 8
		case 0xccc4: // FRAME_BEGIN
			if phase != 0 || next.headers != 15 || next.imageMode && next.fresh != 15 {
				return nil, 0, ErrInvalid
			}
			frame = RemoteFXFrame{ID: r.u32()}
			if r.u16() != 1 {
				return nil, 0, ErrUnsupported
			}
			phase = 1
		case 0xccc6: // REGION
			if phase != 1 {
				return nil, 0, ErrInvalid
			}
			r.u8() // reserved bits and lrf SHOULD/MUST be ignored
			n := int(r.u16())
			if n > 4096-rectCount || n > len(r.data)/8 {
				return nil, 0, ErrInvalid
			}
			rectCount += max(1, n)
			if rectCount > 4096 {
				return nil, 0, ErrInvalid
			}
			for i := 0; i < n; i++ {
				x, y, w, h := int(r.u16()), int(r.u16()), int(r.u16()), int(r.u16())
				if w == 0 || h == 0 || x+w > width || y+h > height {
					return nil, 0, ErrInvalid
				}
				frame.Rectangles = append(frame.Rectangles, image.Rect(x, y, x+w, y+h))
			}
			if n == 0 {
				frame.Rectangles = []image.Rectangle{image.Rect(0, 0, width, height)}
			}
			if r.u16() != 0xcac1 || r.u16() != 1 {
				return nil, 0, ErrInvalid
			}
			phase = 2
		case 0xccc7: // TILESET
			if phase != 2 || r.u16() != 0xcac2 {
				return nil, 0, ErrInvalid
			}
			r.u16() // idx SHOULD be ignored
			properties := r.u16()
			mode := byte(properties >> 10 & 15)
			if mode != 1 && mode != 4 {
				return nil, 0, ErrUnsupported
			}
			// Fixed transform/quantization fields are checked; operational mode
			// comes from CONTEXT as required, ignoring this packet's flags.
			if properties>>4&3 != 1 || properties>>6&15 != 1 || properties>>14&3 != 1 {
				return nil, 0, ErrUnsupported
			}
			qcount := int(r.u8())
			if r.u8() != 64 || qcount == 0 {
				return nil, 0, ErrInvalid
			}
			n := int(r.u16())
			size := r.u32()
			if r.bad || n > 4096-tileCount || n > (budget-work)/(4*rfxTilePixels) {
				return nil, 0, ErrInvalid
			}
			tileCount += n
			work += n * 4 * rfxTilePixels
			quants := make([][10]byte, qcount)
			for i := range quants {
				for j := 0; j < 5; j++ {
					v := r.u8()
					quants[i][j*2], quants[i][j*2+1] = v&15, v>>4
					if v&15 < 6 || v>>4 < 6 {
						return nil, 0, ErrInvalid
					}
				}
			}
			if r.bad || uint64(size) > uint64(len(r.data)) {
				return nil, 0, ErrInvalid
			}
			tiles := clearReader{data: r.take(int(size))}
			seen := make(map[image.Point]bool, n)
			for i := 0; i < n; i++ {
				if tiles.u16() != 0xcac3 {
					return nil, 0, ErrInvalid
				}
				tileSize := tiles.u32()
				if tileSize < 19 || uint64(tileSize-6) > uint64(len(tiles.data)) {
					return nil, 0, ErrInvalid
				}
				tr := clearReader{data: tiles.take(int(tileSize) - 6)}
				qi := [3]byte{tr.u8(), tr.u8(), tr.u8()}
				point := image.Pt(int(tr.u16())*64, int(tr.u16())*64)
				if point.X >= width || point.Y >= height || seen[point] {
					return nil, 0, ErrInvalid
				}
				seen[point] = true
				lengths := [3]int{int(tr.u16()), int(tr.u16()), int(tr.u16())}
				var planes [3][]int64
				for component := 0; component < 3; component++ {
					if int(qi[component]) >= qcount || lengths[component] == 0 {
						return nil, 0, ErrInvalid
					}
					stream := tr.take(lengths[component])
					if tr.bad {
						return nil, 0, ErrInvalid
					}
					var err error
					coefficients[component], _, err = decodeRFXEntropy(stream, mode)
					if err != nil {
						return nil, 0, err
					}
					if err = reconstructRFX(&coefficients[component], quants[qi[component]]); err != nil {
						return nil, 0, err
					}
					planes[component] = inverseRFXWithScratch(&coefficients[component], &transformScratch)
				}
				frame.Tiles = append(frame.Tiles, RemoteFXTile{point, rfxRGB(planes[0], planes[1], planes[2])})
			}
			if tiles.bad || len(tiles.data) != 0 {
				return nil, 0, ErrInvalid
			}
			phase = 3
		case 0xccc5: // FRAME_END
			if phase != 3 {
				return nil, 0, ErrInvalid
			}
			frames = append(frames, frame)
			phase = 0
			next.fresh = 0
			if next.imageMode {
				next.headers = 0
			}
		default:
			return nil, 0, ErrUnsupported
		}
		// blockLen may exceed the required known structure length (3.1.8.3.1).
		// Ignore extension bytes contained by this block, never bytes after it.
		if r.bad {
			return nil, 0, ErrInvalid
		}
	}
	if phase != 0 {
		return nil, 0, ErrInvalid
	}
	*d = next
	return frames, work, nil
}
