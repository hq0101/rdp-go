package rdpgfx

import (
	"bytes"
	"encoding/binary"
	"image"
)

// AVCRegion carries an output mask and informational quantization/quality data.
// The QP metadata does not replace the parameters inside the H.264 bitstream.
type AVCRegion struct {
	Rect        image.Rectangle
	QP, Quality byte
	Progressive bool
}

// AVC420Stream owns the Annex B bitstream and its RDP output regions. Parsing
// this envelope does not decode a picture or establish AVC protocol support.
type AVC420Stream struct {
	Regions   []AVCRegion
	Bitstream []byte
}

// ParseAVC420 parses RFX_AVC420_BITMAP_STREAM. Rectangles are surface coordinates;
// WIRETOSURFACE1 destRect is their bounding rectangle, not a translation origin.
// A renderer must check decoded picture/surface bounds. H.264 sizes come from SPS,
// rather than from this informational metadata. Zero regions can still carry
// a coded picture needed for later reference pictures or AVC444 subframes.
func ParseAVC420(data []byte) (AVC420Stream, error) {
	if len(data) < 5 || len(data) > MaxMessage {
		return AVC420Stream{}, ErrInvalid
	}
	n := uint64(binary.LittleEndian.Uint32(data))
	if n > 4096 || 4+n*10 >= uint64(len(data)) {
		return AVC420Stream{}, ErrInvalid
	}
	out := AVC420Stream{Regions: make([]AVCRegion, int(n))}
	qoffset := 4 + int(n)*8
	for i := range out.Regions {
		r, e := rectangle(data[4+i*8 : 4+(i+1)*8])
		if e != nil {
			return AVC420Stream{}, e
		}
		qp, quality := data[qoffset+i*2], data[qoffset+i*2+1]
		if qp&63 > 51 || quality > 100 {
			return AVC420Stream{}, ErrInvalid
		}
		out.Regions[i] = AVCRegion{Rect: r, QP: qp & 63, Quality: quality, Progressive: qp&128 != 0}
	}
	out.Bitstream = bytes.Clone(data[4+int(n)*10:])
	return out, nil
}

// AVC444Stream owns the main/auxiliary AVC420 envelopes. LC is 0 for both,
// 1 for main only, and 2 for auxiliary only. Both views share one H.264 history.
// The same envelope is used for AVC444 and AVC444v2; only pixel packing differs.
type AVC444Stream struct {
	LC              byte
	Main, Auxiliary *AVC420Stream
}

// ParseAVC444 checks RFX_AVC444_BITMAP_STREAM / RFX_AVC444V2_BITMAP_STREAM.
// The low 30 bits give the complete main envelope length (including metadata).
// In auxiliary-only mode that length must be zero, although an auxiliary
// AVC420 envelope follows the header. Parsing alone does not decode either view.
func ParseAVC444(data []byte) (AVC444Stream, error) {
	if len(data) < 9 || len(data) > MaxMessage {
		return AVC444Stream{}, ErrInvalid
	}
	info := binary.LittleEndian.Uint32(data)
	lc, n := byte(info>>30), int(info&0x3fffffff)
	data = data[4:]
	out := AVC444Stream{LC: lc}
	parse := func(b []byte) (*AVC420Stream, error) {
		s, e := ParseAVC420(b)
		if e != nil {
			return nil, e
		}
		return &s, nil
	}
	var err error
	switch lc {
	case 0:
		if n < 5 || n >= len(data) {
			return AVC444Stream{}, ErrInvalid
		}
		out.Main, err = parse(data[:n])
		if err == nil {
			out.Auxiliary, err = parse(data[n:])
		}
	case 1:
		if n != len(data) {
			return AVC444Stream{}, ErrInvalid
		}
		out.Main, err = parse(data)
	case 2:
		if n != 0 {
			return AVC444Stream{}, ErrInvalid
		}
		out.Auxiliary, err = parse(data)
	default:
		return AVC444Stream{}, ErrInvalid
	}
	if err != nil {
		return AVC444Stream{}, err
	}
	return out, nil
}
