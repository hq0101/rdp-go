package h264

import (
	"fmt"
	"image"
)

// OutputDecoder wraps the progressive pixel decoder with bounded display-order
// output. Decode accepts one complete Annex B access unit and may return zero,
// one, or several frames. Flush emits the remaining pictures at sequence end.
// The zero value is ready to use; start with an IDR and its parameters.
//
// Frame.Order may restart at IDR/MMCO 5: consume the returned order rather than
// sorting counts across sequences. This API supplies no timestamps, frame-rate
// scheduler, or HRD/SEI timing conformance. Samples retain their coded rectangle;
// use each frame's Visible rectangle for display.
//
// Calls must be serial. Failed access units return no output and preserve all
// state. Value copies can branch independently; returned planes are caller-owned.
// Pending pictures and references share immutable storage and together retain
// at most MaxReferencePixels luma samples (96 MiB of YUV420), excluding current
// reconstruction, returned frames, and reference motion records.
type OutputDecoder struct {
	decoder Decoder
	queue   outputQueue
}

// Pending returns the number of decoded pictures still awaiting output.
func (d *OutputDecoder) Pending() int { return d.queue.count }

// Reset discards queued pictures, references, and parameter sets.
func (d *OutputDecoder) Reset() { *d = OutputDecoder{} }

func (d *OutputDecoder) Decode(data []byte) ([]*Frame, error) {
	next := *d
	process := outputProcess{queue: &next.queue}
	if _, err := next.decoder.decode(data, &process, MaxPixels, MaxReferencePixels); err != nil {
		return nil, err
	}
	frames := process.owned()
	*d = next
	return frames, nil
}

// Flush ends the coded sequence, draining in display order and releasing all
// references. Parameter sets survive; the next picture must be an IDR. Repeated
// calls are harmless. Do not flush between access units in a continuing sequence.
func (d *OutputDecoder) Flush() []*Frame {
	process := outputProcess{queue: &d.queue}
	process.end()
	d.decoder.references = referenceBuffer{}
	return process.owned()
}

type outputLimits struct {
	buffering, reorder int // buffering is the raw/inferred VUI value (can be zero)
}

// Annex A Table A-1 (2012), A.3.1/A.3.2 and E.2.1. These checks cover DPB and
// picture size limits, not every bitrate/profile/HRD conformance restriction.
// Levels beyond 5.2 are explicitly unsupported by the ordered API for now.
func sequenceOutputLimits(s *SPS) (outputLimits, error) {
	var maxFS, maxDPB int
	switch s.Level {
	case 9:
		if s.Profile == 66 || s.Profile == 77 || s.Profile == 88 {
			return outputLimits{}, ErrInvalid
		}
		maxFS, maxDPB = 99, 396 // level 1b for High-family profiles
	case 10:
		maxFS, maxDPB = 99, 396
	case 11:
		maxFS, maxDPB = 396, 900
		if (s.Profile == 66 || s.Profile == 77 || s.Profile == 88) && s.Constraints&0x10 != 0 {
			maxFS, maxDPB = 99, 396 // level 1b
		}
	case 12, 13, 20:
		maxFS, maxDPB = 396, 2376
	case 21:
		maxFS, maxDPB = 792, 4752
	case 22, 30:
		maxFS, maxDPB = 1620, 8100
	case 31:
		maxFS, maxDPB = 3600, 18000
	case 32:
		maxFS, maxDPB = 5120, 20480
	case 40, 41:
		maxFS, maxDPB = 8192, 32768
	case 42:
		maxFS, maxDPB = 8704, 34816
	case 50:
		maxFS, maxDPB = 22080, 110400
	case 51, 52:
		maxFS, maxDPB = 36864, 184320
	default:
		return outputLimits{}, fmt.Errorf("output buffer level %d: %w", s.Level, ErrUnsupported)
	}
	if !s.FrameOnly {
		return outputLimits{}, ErrUnsupported
	}
	w, h := s.WidthInMBs, s.HeightInMapUnits
	if w <= 0 || h <= 0 || w > MaxDimension/16 || h > MaxDimension/16 || w*h > maxFS || w*w > maxFS*8 || h*h > maxFS*8 {
		return outputLimits{}, fmt.Errorf("picture exceeds level size: %w", ErrInvalid)
	}
	frames := min(16, maxDPB/(w*h))
	limits := outputLimits{frames, frames}
	if s.VUI.Restricted {
		limits = outputLimits{s.VUI.MaxFrameBuffering, s.VUI.MaxReorderFrames}
	} else if s.Constraints&0x10 != 0 {
		switch s.Profile {
		case 44, 86, 100, 110, 122, 244:
			limits = outputLimits{}
		}
	}
	if s.MaxReferences < 0 || s.MaxReferences > limits.buffering || limits.buffering > frames || limits.reorder < 0 || limits.reorder > limits.buffering {
		return outputLimits{}, fmt.Errorf("invalid output buffer limits: %w", ErrInvalid)
	}
	return limits, nil
}

type queuedPicture struct {
	frame     Frame
	reference *referencePicture // identity for shared DPB occupancy, not numeric ID
}

type outputQueue struct {
	pictures        [16]queuedPicture
	count           int
	limits          outputLimits
	width, height   int
	active, emitted bool
	last            int32
}

// All mutations are on Decode's private value copy. References to old immutable
// planes may be accumulated here, but none are exposed before the AU commits.
type outputProcess struct {
	queue *outputQueue
	ready []Frame
}

func (p *outputProcess) begin(h *idrSlice, s *SPS) error {
	if p == nil {
		return nil
	}
	limits, err := sequenceOutputLimits(s)
	if err != nil {
		return err
	}
	q := p.queue
	if !h.idr && (!q.active || q.limits != limits) {
		return fmt.Errorf("output sequence change requires IDR: %w", ErrUnsupported)
	}
	if h.idr || h.resetsOrder() {
		// C.4.4: infer discard on IDR dimensions/buffering changes, even when
		// no_output_of_prior_pics_flag is zero. Compare raw buffering (0 != 1).
		discard := h.idr && (h.noOutput || q.active && (q.width != s.CodedWidth || q.height != s.CodedHeight || q.limits.buffering != limits.buffering))
		if !discard {
			p.drain()
		}
		*q = outputQueue{active: true, limits: limits, width: s.CodedWidth, height: s.CodedHeight}
	}
	return nil
}

func (q *outputQueue) first() int {
	at := 0
	for i := 1; i < q.count; i++ {
		if q.pictures[i].frame.Order.Count() < q.pictures[at].frame.Order.Count() {
			at = i
		}
	}
	return at
}

func (p *outputProcess) emit(f Frame) {
	p.ready = append(p.ready, f)
	p.queue.emitted, p.queue.last = true, f.Order.Count()
}

func (p *outputProcess) bump() {
	q := p.queue
	at := q.first()
	p.emit(q.pictures[at].frame)
	copy(q.pictures[at:q.count-1], q.pictures[at+1:q.count])
	q.count--
	q.pictures[q.count] = queuedPicture{}
}

func (p *outputProcess) drain() {
	for p.queue.count != 0 {
		p.bump()
	}
}

func (p *outputProcess) end() {
	if p != nil {
		p.drain()
		*p.queue = outputQueue{}
	}
}

// union counts each actual reference/pending picture once; non-existing
// references consume slots without pixels. Already-output references still count.
func (q *outputQueue) union(b *referenceBuffer) (slots, pixels int) {
	slots = b.count
	for _, slot := range b.slots[:b.count] {
		if slot.picture != nil {
			r := slot.picture.samples.Rect
			pixels += r.Dx() * r.Dy()
		}
	}
	for _, pic := range q.pictures[:q.count] {
		shared := false
		if pic.reference != nil {
			for _, slot := range b.slots[:b.count] {
				if slot.picture == pic.reference {
					shared = true
					break
				}
			}
		}
		if !shared {
			slots++
			r := pic.frame.Samples.Rect
			pixels += r.Dx() * r.Dy()
		}
	}
	return
}

func (p *outputProcess) makeRoom(b *referenceBuffer) error {
	if p == nil {
		return nil
	}
	for {
		slots, _ := p.queue.union(b)
		if slots < max(1, p.queue.limits.buffering) {
			return nil
		}
		if p.queue.count == 0 {
			return fmt.Errorf("output DPB full of references: %w", ErrInvalid)
		}
		p.bump()
	}
}

func (p *outputProcess) checkPixels(b *referenceBuffer, added int) error {
	if p != nil {
		_, pixels := p.queue.union(b)
		if pixels+added > MaxReferencePixels {
			return fmt.Errorf("combined output/reference pixel limit: %w", ErrUnsupported)
		}
	}
	return nil
}

func (p *outputProcess) picture(frame Frame, h *idrSlice, b *referenceBuffer) error {
	if p == nil {
		return nil
	}
	q := p.queue
	poc := frame.Order.Count()
	if q.emitted && poc <= q.last {
		return fmt.Errorf("picture precedes emitted output: %w", ErrInvalid)
	}
	for _, old := range q.pictures[:q.count] {
		if poc == old.frame.Order.Count() {
			return fmt.Errorf("duplicate output picture order: %w", ErrInvalid)
		}
	}
	var reference *referencePicture
	if h.reference {
		reference = b.slots[b.count-1].picture
		frame.Samples = reference.samples // share immutable retained pixels
	} else {
		// C.4.5.2: a non-reference picture may go directly to output when
		// all DPB slots are occupied and it precedes every pending picture.
		for {
			slots, _ := q.union(b)
			if slots < max(1, q.limits.buffering) {
				break
			}
			if q.count == 0 || poc < q.pictures[q.first()].frame.Order.Count() {
				p.emit(frame)
				return nil
			}
			p.bump()
		}
		if err := p.checkPixels(b, frame.Samples.Rect.Dx()*frame.Samples.Rect.Dy()); err != nil {
			return err
		}
	}
	if q.count == len(q.pictures) {
		return ErrInvalid
	}
	q.pictures[q.count] = queuedPicture{frame, reference}
	q.count++
	// E.2.1's reordering bound permits early delivery, including immediate
	// output for streams declaring zero reorder depth. No timer is implied.
	for q.count > q.limits.reorder {
		p.bump()
	}
	return nil
}

func (p *outputProcess) owned() []*Frame {
	var frames []*Frame
	for _, source := range p.ready {
		f := source
		f.Samples = image.NewYCbCr(source.Samples.Rect, image.YCbCrSubsampleRatio420)
		copy(f.Samples.Y, source.Samples.Y)
		copy(f.Samples.Cb, source.Samples.Cb)
		copy(f.Samples.Cr, source.Samples.Cr)
		frames = append(frames, &f)
	}
	return frames
}
