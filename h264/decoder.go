package h264

import (
	"fmt"
	"image"
)

// Frame owns the coded YUV420 planes, including padding outside Visible. Pixels
// are in raster order. No RGB conversion is performed. RDP callers must apply
// its full-range BT.709 matrix instead of image.YCbCr's default RGB conversion.
type Frame struct {
	Samples *image.YCbCr
	Visible image.Rectangle
	// Order is the post-MMCO-5 order count; Decode still returns decode order.
	Order PictureOrder
}

// Decoder holds parameters and immutable reference pictures across access units.
// Progressive 8-bit 4:2:0 I/P/B slices (CAVLC/CABAC)
// produce pixels, with PCM, 4x4/8x8 transforms, intra/inter prediction,
// spatial/temporal Direct, weighting and deblocking.
// Other coding modes return ErrUnsupported. Outputs are in decode order;
// Frame.Order reports the derived POC. Use OutputDecoder for display order.
// Start from an IDR.
// Decode is transactional, accepts one complete Annex B access unit, and must be
// called serially. Value copies can branch state independently; outputs are owned.
// An end-of-sequence/stream NAL releases references; the next picture needs IDR.
type Decoder struct {
	sequences  [32]*SPS
	pictures   [256]NALUnit
	references referenceBuffer
}

func (d *Decoder) Reset() { *d = Decoder{} }

func (d *Decoder) Decode(data []byte) (*Frame, error) {
	return d.DecodeWithBudget(data, MaxPixels, MaxReferencePixels)
}

// ReferencePixels reports retained reference luma samples, excluding missing
// frames, parameter sets and motion records. Returned frames are not retained.
func (d *Decoder) ReferencePixels() int { return d.references.pixels() }

// DecodeWithBudget imposes caller budgets on the current coded picture and
// retained reference luma samples. Both are explicit nonnegative limits, capped
// by MaxPixels and MaxReferencePixels; zero is not a request for defaults.
// Bounds are checked before reconstruction/reference sample allocation. Failure
// preserves state. This is useful when several decoders share an outer budget.
func (d *Decoder) DecodeWithBudget(data []byte, picturePixels, referencePixels int) (*Frame, error) {
	return d.decode(data, nil, picturePixels, referencePixels)
}

func (d *Decoder) decode(data []byte, output *outputProcess, picturePixels, referencePixels int) (*Frame, error) {
	if picturePixels < 0 || referencePixels < 0 {
		return nil, ErrInvalid
	}
	picturePixels, referencePixels = min(MaxPixels, picturePixels), min(MaxReferencePixels, referencePixels)
	units, err := SplitAnnexB(data)
	if err != nil {
		return nil, err
	}
	next := *d
	var frame *Frame
	var blocks []*intraMB
	var weights [3][16]int32
	var weights8 [64]int32
	var interWeights4 [3][16]int32
	var interWeights8 [64]int32
	var firstHeader idrSlice
	var sequence *SPS
	width, height := 0, 0
	var key pictureKey
	filled := 0
	seenVCL, ended := false, false
	for index, n := range units {
		switch n.Type {
		case 7:
			if seenVCL || ended {
				return nil, ErrInvalid
			}
			s, e := ParseSPS(n)
			if e != nil {
				return nil, e
			}
			next.sequences[s.ID] = &s
		case 8:
			if seenVCL || ended {
				return nil, ErrInvalid
			}
			r := bitReader{data: n.RBSP}
			id, sid := r.ue(255), r.ue(31)
			if r.bad || next.sequences[sid] == nil {
				return nil, ErrInvalid
			}
			if _, e := ParsePPS(n, *next.sequences[sid]); e != nil {
				return nil, e
			}
			next.pictures[id] = n
		case 1, 5:
			if ended {
				return nil, ErrInvalid
			}
			seenVCL = true
			r := bitReader{data: n.RBSP}
			h, s, e := next.sliceHeader(&r, n.Type == 5, n.ReferenceIDC != 0)
			if e != nil {
				return nil, e
			}
			if frame == nil {
				if s.CodedWidth*s.CodedHeight > picturePixels {
					return nil, fmt.Errorf("picture pixel budget: %w", ErrUnsupported)
				}
				if e := output.begin(&h, s); e != nil {
					return nil, e
				}
				if e := next.references.prepareOutput(&h, s, output); e != nil {
					return nil, e
				}
				firstHeader, sequence = h, s
				frame = &Frame{Visible: s.Visible, Order: h.storedOrder}
				width, height = s.CodedWidth, s.CodedHeight
				blocks = make([]*intraMB, s.WidthInMBs*s.HeightInMapUnits)
				weights = intraWeights(s, h.parameters)
				weights8 = intraWeights8(s, h.parameters)
				interWeights4 = scalingWeights4(s, h.parameters, true)
				interWeights8 = scalingWeights8(s, h.parameters, true)
				key = h.pictureKey
			} else if h.pictureKey != key {
				return nil, fmt.Errorf("multiple pictures in access unit: %w", ErrInvalid)
			}
			h.order, h.storedOrder = firstHeader.order, firstHeader.storedOrder
			if h.sliceType == 0 || h.sliceType == 1 {
				if e := next.references.list(&h, s); e != nil {
					return nil, e
				}
			}

			var count int
			if h.parameters.CABAC {
				count, e = parseCABACSlice(&r, blocks, &h, s)
			} else {
				count, e = parseCAVLCSlice(&r, blocks, &h, s)
			}
			if e != nil {
				return nil, e
			}
			filled += count
		case 9:
			if index != 0 || seenVCL || ended {
				return nil, ErrInvalid
			}
			r := bitReader{data: n.RBSP}
			r.read(3)
			if e := r.trailing(); e != nil {
				return nil, e
			}
		case 6:
			if seenVCL || ended {
				return nil, ErrInvalid
			}
			if e := validateSEI(n.RBSP); e != nil {
				return nil, e
			}
		case 10, 11:
			if len(n.RBSP) != 0 {
				return nil, ErrInvalid
			}
			ended = true
		case 12:
			if len(n.RBSP) == 0 || n.RBSP[len(n.RBSP)-1] != 0x80 {
				return nil, ErrInvalid
			}
			for _, b := range n.RBSP[:len(n.RBSP)-1] {
				if b != 255 {
					return nil, ErrInvalid
				}
			}
		default:
			return nil, ErrUnsupported
		}
	}
	if frame != nil && filled != len(blocks) {
		return nil, fmt.Errorf("incomplete picture: %w", ErrInvalid)
	}
	// Allocate pixels only after every macroblock's syntax has passed. PCM sample
	// views and bounded residual records avoid allocating large output images for
	// tiny truncated packets. Reconstruction also completes before state is committed.
	if frame != nil {
		frame.Samples = image.NewYCbCr(image.Rect(0, 0, width, height), image.YCbCrSubsampleRatio420)
		if e := reconstructPicture(frame.Samples, blocks, weights, weights8, interWeights4, interWeights8); e != nil {
			return nil, e
		}
		deblockIntra(frame.Samples, blocks)
		if e := next.references.storeOutput(frame.Samples, &firstHeader, sequence, blocks, output, referencePixels); e != nil {
			return nil, e
		}
		if e := output.picture(*frame, &firstHeader, &next.references); e != nil {
			return nil, e
		}
	}
	if ended {
		output.end()
		next.references = referenceBuffer{}
	}
	if next.ReferencePixels() > referencePixels {
		return nil, fmt.Errorf("reference pixel budget: %w", ErrUnsupported)
	}
	*d = next
	return frame, nil
}

func copyPCM(dst *image.YCbCr, address int, pcm []byte) {
	columns := dst.Rect.Dx() / 16
	x, y := address%columns*16, address/columns*16
	for row := 0; row < 16; row++ {
		off := dst.YOffset(x, y+row)
		copy(dst.Y[off:off+16], pcm[row*16:(row+1)*16])
	}
	for row := 0; row < 8; row++ {
		off := dst.COffset(x, y+row*2)
		copy(dst.Cb[off:off+8], pcm[256+row*8:256+(row+1)*8])
		copy(dst.Cr[off:off+8], pcm[320+row*8:320+(row+1)*8])
	}
}

// Unknown SEI payloads do not affect this restricted pixel path, but their
// explicit byte lengths and trailing bits must still be structurally valid.
func validateSEI(b []byte) error {
	if len(b) < 3 {
		return ErrInvalid
	} // at least a type, size and stop byte
	for len(b) > 1 {
		for len(b) > 0 && b[0] == 255 {
			b = b[1:]
		}
		if len(b) == 0 {
			return ErrInvalid
		}
		b = b[1:] // payloadType terminator
		size := 0
		for len(b) > 0 && b[0] == 255 {
			size += 255
			b = b[1:]
		}
		if len(b) == 0 {
			return ErrInvalid
		}
		size += int(b[0])
		b = b[1:]
		if size > len(b) {
			return ErrInvalid
		}
		b = b[size:]
	}
	if len(b) != 1 || b[0] != 0x80 {
		return ErrInvalid
	}
	return nil
}
