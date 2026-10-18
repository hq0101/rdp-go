package rdpgfx

import (
	"fmt"
	"image"
	"maps"

	"github.com/hq0101/rdp-go/h264"
)

// AVCBudget provides explicit nonnegative per-call/retained limits. Zero is a
// zero allowance, not a default. Work includes decoded picture area, region
// traversal, cached tile copies and the returned image. ReferencePixels counts
// H.264 reference luma samples; MainPixels counts allocated 16x16 cache slots.
type AVCBudget struct {
	Work, ReferencePixels, MainPixels int
}

// AVCFrame owns a surface-sized RGB image and the ordered region masks touched
// by the command. Only pixels inside Regions are meaningful (opaque); the rest
// are zero. Copy RGB only to preserve the destination surface's alpha.
type AVCFrame struct {
	Image     *image.NRGBA
	Regions   []image.Rectangle
	Subframes int
}

// AVCDecoder decodes AVC420, AVC444 and AVC444v2 commands for one surface, using
// one H.264 history for every main/auxiliary subframe in wire order. This is an
// independent codec API, not a capability advertisement. The zero value is ready.
// Calls must be serial; value copies branch independently and outputs are owned.
// A failed command changes no state, including a failure in its second view.
// Geometry is fixed until Reset, as for an RDP surface's lifetime.
//
// Main cache pixels retain the last main view for each actual region pixel,
// including its sampled chroma average. Updating one pixel must not replace a
// neighbor's prior main view. Missing main pixels make auxiliary updates invalid.
// The optional near-equal (threshold 30) reverse-filter heuristic is not applied.
type AVCDecoder struct {
	decoder       h264.Decoder
	main          map[image.Point]*avcMainTile
	width, height int
	coded         image.Rectangle
}

// Each pixel keeps its own main-view average, even when pixels in a shared
// 2x2 group were last updated by different main rectangles. Immutable cache
// tiles bound ownership without retaining whole historical decoded frames.
type avcMainTile struct {
	y, u, v [256]byte
	valid   [4]uint64
}

func (d *AVCDecoder) Reset()               { *d = AVCDecoder{} }
func (d *AVCDecoder) ReferencePixels() int { return d.decoder.ReferencePixels() }
func (d *AVCDecoder) MainPixels() int      { return len(d.main) * 256 }

func (d *AVCDecoder) Decode(codec uint16, data []byte, width, height int) (AVCFrame, error) {
	f, _, e := d.DecodeWithBudget(codec, data, width, height, AVCBudget{maxWork, maxAVCReferencePixels, h264.MaxPixels})
	return f, e
}

// DecodeWithBudget limits a decoder that shares resources with other surfaces.
// It returns the charged work only on success. MainPixels is capped at MaxPixels;
// at that limit cache tiles use 50 MiB plus map overhead. H.264 references,
// current reconstruction and the returned NRGBA image are additional storage.
func (d *AVCDecoder) DecodeWithBudget(codec uint16, data []byte, width, height int, budget AVCBudget) (AVCFrame, int, error) {
	return d.decodeWithBudget(codec, data, width, height, budget, image.Rect(0, 0, width, height))
}

// The pipeline supplies destRect here to validate the wire command's bounding
// rectangle without parsing and copying the potentially large bitstreams twice.
func (d *AVCDecoder) decodeWithBudget(codec uint16, data []byte, width, height int, budget AVCBudget, destination image.Rectangle) (AVCFrame, int, error) {
	bad := func(e error) (AVCFrame, int, error) { return AVCFrame{}, 0, e }
	if !validSize(width, height) || budget.Work < 0 || budget.ReferencePixels < 0 || budget.MainPixels < 0 {
		return bad(ErrInvalid)
	}
	if d.width != 0 && (d.width != width || d.height != height) {
		return bad(fmt.Errorf("AVC surface size change requires Reset: %w", ErrInvalid))
	}
	budget.Work = min(budget.Work, maxWork)
	budget.MainPixels = min(budget.MainPixels, h264.MaxPixels)
	var views []*AVC420Stream
	var auxiliary []bool
	switch codec {
	case CodecAVC420:
		s, e := ParseAVC420(data)
		if e != nil {
			return bad(e)
		}
		views = []*AVC420Stream{&s}
		auxiliary = []bool{false}
	case CodecAVC444, CodecAVC444V2:
		s, e := ParseAVC444(data)
		if e != nil {
			return bad(e)
		}
		if s.Main != nil {
			views = append(views, s.Main)
			auxiliary = append(auxiliary, false)
		}
		if s.Auxiliary != nil {
			views = append(views, s.Auxiliary)
			auxiliary = append(auxiliary, true)
		}
	default:
		return bad(ErrUnsupported)
	}
	next := *d
	next.width, next.height = width, height
	work := 0
	spend := func(n int) error {
		if n < 0 || n > budget.Work-work {
			return fmt.Errorf("AVC work budget: %w", ErrInvalid)
		}
		work += n
		return nil
	}
	bounds := image.Rect(0, 0, width, height)
	result := AVCFrame{}
	// Reserve the output before decoding to keep allocation predictable. No
	// image is allocated yet; parameter-only/truncated streams still fail first.
	if e := spend(area(bounds)); e != nil {
		return bad(e)
	}
	for _, view := range views {
		for _, region := range view.Regions {
			if !contained(region.Rect, bounds) || !contained(region.Rect, destination) {
				return bad(fmt.Errorf("AVC region outside surface/destination: %w", ErrInvalid))
			}
			if e := spend(1 + area(region.Rect)); e != nil {
				return bad(e)
			}
		}
	}
	cloned := false
	writable := map[image.Point]bool{}
	for index, view := range views {
		frame, e := next.decoder.DecodeWithBudget(view.Bitstream, budget.Work-work, budget.ReferencePixels)
		if e != nil {
			return bad(e)
		}
		if frame == nil {
			return bad(fmt.Errorf("AVC subframe lacks a picture: %w", ErrInvalid))
		}
		if e := spend(area(frame.Samples.Rect)); e != nil {
			return bad(e)
		}
		for _, r := range view.Regions {
			if !contained(r.Rect, frame.Samples.Rect) {
				return bad(fmt.Errorf("AVC region outside coded subframe: %w", ErrInvalid))
			}
		}
		if auxiliary[index] {
			for _, r := range view.Regions {
				if !r.Rect.Empty() && frame.Samples.Rect != next.coded {
					return bad(fmt.Errorf("AVC auxiliary dimensions lack a matching main view: %w", ErrInvalid))
				}
			}
		} else if next.coded != frame.Samples.Rect {
			// A new coded geometry needs a new main basis. Do not combine a
			// differently packed auxiliary view with stale geometry.
			next.coded = frame.Samples.Rect
			next.main = nil
			cloned = false
			clear(writable)
		}
		if result.Image == nil {
			result.Image = image.NewNRGBA(bounds)
		}
		for _, region := range view.Regions {
			r := region.Rect
			if r.Empty() {
				continue
			}
			if !auxiliary[index] {
				if !cloned {
					if e := spend(len(next.main)); e != nil {
						return bad(e)
					}
					next.main = maps.Clone(next.main)
					if next.main == nil {
						next.main = make(map[image.Point]*avcMainTile)
					}
					cloned = true
				}
				// Preflight/cache each intersecting tile once before writing pixels.
				for my := r.Min.Y / 16; my <= (r.Max.Y-1)/16; my++ {
					for mx := r.Min.X / 16; mx <= (r.Max.X-1)/16; mx++ {
						key := image.Pt(mx, my)
						if writable[key] {
							continue
						}
						if e := spend(256); e != nil {
							return bad(e)
						}
						old := next.main[key]
						if old == nil && (len(next.main)+1)*256 > budget.MainPixels {
							return bad(fmt.Errorf("AVC main cache budget: %w", ErrInvalid))
						}
						tile := new(avcMainTile)
						if old != nil {
							*tile = *old
						}
						next.main[key] = tile
						writable[key] = true
					}
				}
			}
			for y := r.Min.Y; y < r.Max.Y; y++ {
				for x := r.Min.X; x < r.Max.X; x++ {
					key, at := image.Pt(x/16, y/16), (y%16)*16+x%16
					tile := next.main[key]
					var yy, u, v int
					if !auxiliary[index] {
						yy = int(frame.Samples.Y[frame.Samples.YOffset(x, y)])
						ci := frame.Samples.COffset(x, y)
						u, v = int(frame.Samples.Cb[ci]), int(frame.Samples.Cr[ci])
						tile.y[at], tile.u[at], tile.v[at] = byte(yy), byte(u), byte(v)
						tile.valid[at/64] |= 1 << uint(at%64)
					} else {
						if tile == nil || tile.valid[at/64]&(1<<uint(at%64)) == 0 {
							return bad(fmt.Errorf("AVC auxiliary region has no main pixel: %w", ErrInvalid))
						}
						yy = int(tile.y[at])
						u, v = avc444Chroma(frame.Samples, codec, x, y, int(tile.u[at]), int(tile.v[at]))
					}
					avcSetRGB(result.Image, x, y, yy, u, v)
				}
			}
			result.Regions = append(result.Regions, r)
		}
		result.Subframes++
	}
	if next.MainPixels() > budget.MainPixels || next.ReferencePixels() > budget.ReferencePixels {
		return bad(ErrInvalid)
	}
	*d = next
	return result, work, nil
}

// The coordinates passed here denote one output pixel. All other samples of
// its 2x2 group are available in the full decoded auxiliary view even when
// outside the output mask. Signed inverse-filter intermediates never wrap as
// bytes; only the final R/G/B results are saturated, as in the specified matrix.
func avc444Chroma(aux *image.YCbCr, codec uint16, x, y, baseU, baseV int) (int, int) {
	get := func(xx, yy int) (int, int) {
		if codec == CodecAVC444 {
			if yy&1 != 0 {
				row := (yy/16)*16 + (yy%16)/2
				return int(aux.Y[aux.YOffset(xx, row)]), int(aux.Y[aux.YOffset(xx, row+8)])
			}
			ci := aux.COffset(xx, yy)
			return int(aux.Cb[ci]), int(aux.Cr[ci])
		}
		w := aux.Rect.Dx()
		if xx&1 != 0 {
			return int(aux.Y[aux.YOffset(xx/2, yy)]), int(aux.Y[aux.YOffset(w/2+xx/2, yy)])
		}
		// B6/B7 live in the auxiliary U plane; B8/B9 in V. These are
		// full-frame W/4 splits, not independent 16x16 macroblock halves.
		plane := aux.Cb
		if xx&2 != 0 {
			plane = aux.Cr
		}
		off := (yy/2)*aux.CStride + xx/4
		return int(plane[off]), int(plane[off+w/4])
	}
	if x&1 != 0 || y&1 != 0 {
		return get(x, y)
	}
	u1, v1 := get(x+1, y)
	u2, v2 := get(x, y+1)
	u3, v3 := get(x+1, y+1)
	// Solve the v2 specification's averaging identity for its even/even
	// sample; this is the same inverse as the explicit v1 reverse equation.
	return 4*baseU - u1 - u2 - u3, 4*baseV - v1 - v2 - v3
}

func avcSetRGB(dst *image.NRGBA, x, y, yy, u, v int) {
	yy *= 256
	u -= 128
	v -= 128
	i := dst.PixOffset(x, y)
	dst.Pix[i] = byte(min(255, max(0, (yy+403*v)>>8)))
	dst.Pix[i+1] = byte(min(255, max(0, (yy-48*u-120*v)>>8)))
	dst.Pix[i+2] = byte(min(255, max(0, (yy+475*u)>>8)))
	dst.Pix[i+3] = 255
}
