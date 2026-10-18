package rdpgfx

import (
	"fmt"
	"github.com/hq0101/rdp-go/h264"
)

const maxAVCContexts = 64
const maxAVCReferencePixels = h264.MaxReferencePixels
const maxAVCMainPixels = h264.MaxPixels

// All AVC codecs on one surface share a decoder and main-view basis. Codec
// switches, logical frames and output resets do not discard that state.
func (t *transaction) avc(c Command) error {
	p := t.p
	if !avcAllowed(p.confirmedVersion, p.confirmedFlags, c.CodecID) {
		return ErrUnsupported
	}
	s, ok := p.surfaces[c.SurfaceID]
	if !ok || !p.inFrame || !contained(c.Rect, s.image.Rect) {
		return ErrInvalid
	}
	var decoder AVCDecoder
	previousRefs, previousMain := 0, 0
	if s.avc != nil {
		decoder = *s.avc
		previousRefs, previousMain = decoder.ReferencePixels(), decoder.MainPixels()
	} else if p.avcContexts >= maxAVCContexts {
		return fmt.Errorf("AVC context budget: %w", ErrInvalid)
	}
	budget := AVCBudget{Work: maxWork - t.work,
		ReferencePixels: maxAVCReferencePixels - p.avcPixels + previousRefs,
		MainPixels:      maxAVCMainPixels - p.avcMainPixels + previousMain}
	frame, work, err := decoder.decodeWithBudget(c.CodecID, c.Data, s.image.Rect.Dx(), s.image.Rect.Dy(), budget, c.Rect)
	if err != nil {
		return fmt.Errorf("AVC decode: %w", err)
	}
	if err = t.spend(work); err != nil {
		return err
	}
	if len(frame.Regions) > 0 {
		s, err = t.writable(c.SurfaceID)
		if err != nil {
			return err
		}
		for _, r := range frame.Regions {
			if err = t.spend(area(r)); err != nil {
				return err
			}
			copyPixels(s.image, r.Min, frame.Image, r, true)
		}
	}
	if s.avc == nil {
		p.avcContexts++
	}
	p.avcPixels += decoder.ReferencePixels() - previousRefs
	p.avcMainPixels += decoder.MainPixels() - previousMain
	s.avc = &decoder
	p.surfaces[c.SurfaceID] = s
	switch c.CodecID {
	case CodecAVC420:
		p.stats.AVC420++
	case CodecAVC444:
		p.stats.AVC444++
	case CodecAVC444V2:
		p.stats.AVC444V2++
	}
	p.stats.AVCSubframes += uint64(frame.Subframes)
	return nil
}
