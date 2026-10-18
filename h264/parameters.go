package h264

import "image"

// ScalingList contains signalled values in scan order. Present distinguishes a
// missing list (whose fallback is context-dependent) from a default matrix.
// Values is meaningful only when Present is true and Default is false; default
// and inherited matrices are resolved in context by the transform implementation.
type ScalingList struct {
	Present, Default bool
	Size             int
	Values           [64]byte
}

// SPS describes parsed sequence parameters, including coded and visible sizes.
// Parsing is broader than the current pixel decoder: a parsed profile, scaling
// matrix or interlaced layout is not a claim that it can be decoded yet.
type SPS struct {
	ID                                byte
	Profile, Constraints, Level       byte
	ChromaFormat                      byte
	SeparateColourPlane               bool
	BitDepthLuma, BitDepthChroma      int
	TransformBypass                   bool
	ScalingMatrixPresent              bool
	Scaling                           [12]ScalingList
	Log2FrameNum, POCType, Log2POCLSB int
	DeltaPOCAlwaysZero                bool
	OffsetNonRef, OffsetTopBottom     int
	POCCycle                          []int
	MaxReferences                     int
	AllowFrameNumGaps                 bool
	WidthInMBs, HeightInMapUnits      int
	FrameOnly, MBAFF, Direct8x8       bool
	CodedWidth, CodedHeight           int
	Visible                           image.Rectangle
	VUI                               VUI
}

// VUI stores display/timing information. RDP applies its own specified colour
// conversion; parsing VUI does not choose an RDP RGB conversion policy.
type VUI struct {
	Present                             bool
	AspectRatio                         byte
	SARWidth, SARHeight                 uint16
	FullRange                           bool
	ColourDescription                   bool
	Primaries, Transfer, Matrix         byte
	TimingPresent, FixedFrameRate       bool
	UnitsInTick, TimeScale              uint32
	NALHRD, VCLHRD                      bool
	PicStructPresent                    bool
	Restricted                          bool
	MaxReorderFrames, MaxFrameBuffering int
}

// PPS describes a single slice-group picture configuration. Flexible macroblock
// ordering is explicitly unsupported, rather than parsed with a guessed layout.
type PPS struct {
	ID, SPSID                                                  byte
	CABAC, BottomFieldPOC                                      bool
	ReferencesL0, ReferencesL1                                 int
	WeightedPrediction                                         bool
	WeightedBiPrediction                                       int
	InitialQP, InitialQS, ChromaQPOffset, SecondChromaQPOffset int
	DeblockingControl, ConstrainedIntra, RedundantPictures     bool
	Transform8x8                                               bool
	ScalingMatrixPresent                                       bool
	Scaling                                                    [12]ScalingList
}

func scalingList(r *bitReader, size int) ScalingList {
	s := ScalingList{Present: true, Size: size}
	last, next := 8, 8
	for i := 0; i < size; i++ {
		if next != 0 {
			next = (last + r.se(-128, 127) + 256) % 256
			if i == 0 && next == 0 {
				s.Default = true
			}
		}
		if next != 0 {
			last = next
		}
		s.Values[i] = byte(last)
	}
	return s
}

// ParseSPS consumes a complete unescaped sequence parameter set NAL.
func ParseSPS(n NALUnit) (SPS, error) {
	if n.Type != 7 || n.ReferenceIDC == 0 || n.ReferenceIDC > 3 || len(n.RBSP) > maxParameterBytes {
		return SPS{}, ErrInvalid
	}
	r := bitReader{data: n.RBSP}
	s := SPS{Profile: byte(r.read(8)), Constraints: byte(r.read(8)), Level: byte(r.read(8)), ChromaFormat: 1, BitDepthLuma: 8, BitDepthChroma: 8}
	s.ID = byte(r.ue(31))
	if r.bad {
		return SPS{}, ErrInvalid
	}
	if s.Constraints&3 != 0 {
		return SPS{}, ErrInvalid
	}
	switch s.Profile {
	case 66, 77, 88:
	case 100, 110, 122, 244, 44, 83, 86, 118, 128:
		s.ChromaFormat = byte(r.ue(3))
		if s.ChromaFormat == 3 {
			s.SeparateColourPlane = r.flag()
		}
		s.BitDepthLuma = 8 + int(r.ue(6))
		s.BitDepthChroma = 8 + int(r.ue(6))
		s.TransformBypass = r.flag()
		s.ScalingMatrixPresent = r.flag()
		if s.ScalingMatrixPresent {
			count := 8
			if s.ChromaFormat == 3 {
				count = 12
			}
			for i := 0; i < count; i++ {
				if r.flag() {
					size := 16
					if i >= 6 {
						size = 64
					}
					s.Scaling[i] = scalingList(&r, size)
				}
			}
		}
	default:
		return SPS{}, ErrUnsupported
	}
	s.Log2FrameNum = 4 + int(r.ue(12))
	s.POCType = int(r.ue(2))
	if s.POCType == 0 {
		s.Log2POCLSB = 4 + int(r.ue(12))
	}
	if s.POCType == 1 {
		s.DeltaPOCAlwaysZero = r.flag()
		s.OffsetNonRef = r.se(-2147483647, 2147483647)
		s.OffsetTopBottom = r.se(-2147483647, 2147483647)
		count := int(r.ue(255))
		s.POCCycle = make([]int, count)
		for i := range s.POCCycle {
			s.POCCycle[i] = r.se(-2147483647, 2147483647)
		}
	}
	s.MaxReferences = int(r.ue(16))
	s.AllowFrameNumGaps = r.flag()
	s.WidthInMBs = 1 + int(r.ue(MaxDimension/16-1))
	s.HeightInMapUnits = 1 + int(r.ue(MaxDimension/16-1))
	s.FrameOnly = r.flag()
	factor := 1
	if !s.FrameOnly {
		factor = 2
		s.MBAFF = r.flag()
	}
	s.Direct8x8 = r.flag()
	s.CodedWidth = s.WidthInMBs * 16
	s.CodedHeight = s.HeightInMapUnits * 16 * factor
	if s.CodedHeight > MaxDimension || s.CodedWidth*s.CodedHeight > MaxPixels {
		return SPS{}, ErrInvalid
	}
	s.Visible = image.Rect(0, 0, s.CodedWidth, s.CodedHeight)
	if r.flag() {
		cx, cy := 1, factor
		if !s.SeparateColourPlane && s.ChromaFormat != 0 {
			if s.ChromaFormat <= 2 {
				cx = 2
			}
			if s.ChromaFormat == 1 {
				cy = 2 * factor
			}
		}
		left, right := int(r.ue(MaxDimension))*cx, int(r.ue(MaxDimension))*cx
		top, bottom := int(r.ue(MaxDimension))*cy, int(r.ue(MaxDimension))*cy
		if left+right >= s.CodedWidth || top+bottom >= s.CodedHeight {
			return SPS{}, ErrInvalid
		}
		s.Visible = image.Rect(left, top, s.CodedWidth-right, s.CodedHeight-bottom)
	}
	if r.flag() {
		s.VUI = parseVUI(&r, s.MaxReferences)
	}
	if err := r.trailing(); err != nil {
		return SPS{}, err
	}
	return s, nil
}

func parseVUI(r *bitReader, maxReferences int) VUI {
	v := VUI{Present: true}
	if r.flag() {
		v.AspectRatio = byte(r.read(8))
		if v.AspectRatio == 255 {
			v.SARWidth = uint16(r.read(16))
			v.SARHeight = uint16(r.read(16))
		}
	}
	if r.flag() {
		r.flag()
	} // overscan does not affect decoded samples
	if r.flag() {
		format := r.read(3)
		if format > 5 {
			r.bad = true
		}
		v.FullRange = r.flag()
		v.ColourDescription = r.flag()
		if v.ColourDescription {
			v.Primaries = byte(r.read(8))
			v.Transfer = byte(r.read(8))
			v.Matrix = byte(r.read(8))
		}
	}
	if r.flag() {
		r.ue(5)
		r.ue(5)
	}
	v.TimingPresent = r.flag()
	if v.TimingPresent {
		v.UnitsInTick = r.read(32)
		v.TimeScale = r.read(32)
		v.FixedFrameRate = r.flag()
		if v.UnitsInTick == 0 || v.TimeScale == 0 {
			r.bad = true
		}
	}
	v.NALHRD = r.flag()
	if v.NALHRD {
		parseHRD(r)
	}
	v.VCLHRD = r.flag()
	if v.VCLHRD {
		parseHRD(r)
	}
	if v.NALHRD || v.VCLHRD {
		r.flag()
	}
	v.PicStructPresent = r.flag()
	v.Restricted = r.flag()
	if v.Restricted {
		r.flag()
		r.ue(16)
		r.ue(16)
		r.ue(16)
		r.ue(16)
		v.MaxReorderFrames = int(r.ue(16))
		v.MaxFrameBuffering = int(r.ue(16))
		if v.MaxReorderFrames > v.MaxFrameBuffering || v.MaxFrameBuffering < maxReferences {
			r.bad = true
		}
	}
	return v
}
func parseHRD(r *bitReader) {
	count := 1 + int(r.ue(31))
	r.read(8)
	for i := 0; i < count; i++ {
		r.ue(^uint32(0) - 1)
		r.ue(^uint32(0) - 1)
		r.flag()
	}
	r.read(20)
}

// ParsePPS requires the referenced SPS because extension syntax and QP bounds
// depend on its chroma format and bit depth. Returned data is independently owned.
func ParsePPS(n NALUnit, s SPS) (PPS, error) {
	if n.Type != 8 || n.ReferenceIDC == 0 || n.ReferenceIDC > 3 || len(n.RBSP) > maxParameterBytes || s.ChromaFormat > 3 || s.BitDepthLuma < 8 || s.BitDepthLuma > 14 {
		return PPS{}, ErrInvalid
	}
	r := bitReader{data: n.RBSP}
	p := PPS{ID: byte(r.ue(255)), SPSID: byte(r.ue(31))}
	if p.SPSID != s.ID {
		return PPS{}, ErrInvalid
	}
	p.CABAC = r.flag()
	p.BottomFieldPOC = r.flag()
	groups := r.ue(7)
	if r.bad {
		return PPS{}, ErrInvalid
	}
	if groups != 0 {
		return PPS{}, ErrUnsupported
	}
	p.ReferencesL0 = 1 + int(r.ue(31))
	p.ReferencesL1 = 1 + int(r.ue(31))
	p.WeightedPrediction = r.flag()
	p.WeightedBiPrediction = int(r.read(2))
	if p.WeightedBiPrediction > 2 {
		return PPS{}, ErrInvalid
	}
	p.InitialQP = 26 + r.se(-26-6*(s.BitDepthLuma-8), 25)
	p.InitialQS = 26 + r.se(-26, 25)
	p.ChromaQPOffset = r.se(-12, 12)
	p.DeblockingControl = r.flag()
	p.ConstrainedIntra = r.flag()
	p.RedundantPictures = r.flag()
	p.SecondChromaQPOffset = p.ChromaQPOffset
	if r.more() {
		p.Transform8x8 = r.flag()
		p.ScalingMatrixPresent = r.flag()
		if p.ScalingMatrixPresent {
			count := 6
			if p.Transform8x8 {
				if s.ChromaFormat == 3 {
					count += 6
				} else {
					count += 2
				}
			}
			for i := 0; i < count; i++ {
				if r.flag() {
					size := 16
					if i >= 6 {
						size = 64
					}
					p.Scaling[i] = scalingList(&r, size)
				}
			}
		}
		p.SecondChromaQPOffset = r.se(-12, 12)
	}
	if err := r.trailing(); err != nil {
		return PPS{}, err
	}
	return p, nil
}
