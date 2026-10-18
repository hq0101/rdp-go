// Package h264 implements bounded H.264 byte-stream/parameter parsing and
// progressive 8-bit YUV420 I/P/B decoding (CAVLC/CABAC),
// including motion compensation, Direct, reference management, weighting,
// POC derivation, deblocking, and bounded display-order output via OutputDecoder.
// RDP does not advertise AVC on this basis.
package h264

import "errors"

var ErrInvalid = errors.New("h264: invalid bitstream")
var ErrUnsupported = errors.New("h264: unsupported coding feature")

const MaxStream = 64 << 20
const MaxNALUnits = 4096
const MaxPixels = 16 << 20
const MaxDimension = 8192
const maxParameterBytes = 64 << 10

// NALUnit owns its unescaped RBSP, without the one-byte NAL header or start code.
// SplitAnnexB handles ordinary AVC NALs; extension headers (SVC/MVC) are excluded.
type NALUnit struct {
	Type         byte
	ReferenceIDC byte
	RBSP         []byte
}

// SplitAnnexB consumes a complete byte stream (not an arbitrary network chunk).
// Both three- and four-byte start codes and framing zero bytes are accepted.
// It rejects AVCC length framing, forbidden headers and malformed escaping.
func SplitAnnexB(data []byte) ([]NALUnit, error) {
	if len(data) == 0 || len(data) > MaxStream {
		return nil, ErrInvalid
	}
	var out []NALUnit
	start, zeros := -1, 0
	appendUnit := func(end int) error {
		if start < 0 {
			return nil
		}
		if len(out) >= MaxNALUnits || end <= start {
			return ErrInvalid
		}
		n, err := parseNAL(data[start:end])
		if err != nil {
			return err
		}
		out = append(out, n)
		return nil
	}
	for i, b := range data {
		if b == 0 {
			zeros++
			continue
		}
		if b == 1 && zeros >= 2 {
			if err := appendUnit(i - zeros); err != nil {
				return nil, err
			}
			start = i + 1
		} else if start < 0 {
			return nil, ErrInvalid
		}
		zeros = 0
	}
	if start < 0 {
		return nil, ErrInvalid
	}
	if err := appendUnit(len(data) - zeros); err != nil {
		return nil, err
	}
	return out, nil
}

func parseNAL(data []byte) (NALUnit, error) {
	if len(data) == 0 || data[0]&0x80 != 0 {
		return NALUnit{}, ErrInvalid
	}
	n := NALUnit{Type: data[0] & 31, ReferenceIDC: data[0] >> 5}
	if n.Type == 0 || n.Type >= 24 {
		return NALUnit{}, ErrInvalid
	}
	if n.Type > 12 {
		return NALUnit{}, ErrUnsupported
	}
	if (n.Type == 5 || n.Type == 7 || n.Type == 8) && n.ReferenceIDC == 0 {
		return NALUnit{}, ErrInvalid
	}
	if (n.Type == 6 || n.Type >= 9) && n.ReferenceIDC != 0 {
		return NALUnit{}, ErrInvalid
	}
	if (n.Type == 7 || n.Type == 8) && len(data) > maxParameterBytes {
		return NALUnit{}, ErrInvalid
	}
	n.RBSP = make([]byte, 0, len(data)-1)
	zeros := 0
	for i := 1; i < len(data); i++ {
		b := data[i]
		if zeros == 2 {
			if b < 3 {
				return NALUnit{}, ErrInvalid
			}
			if b == 3 {
				// A terminal prevention byte is permitted by the NAL syntax;
				// the RBSP consumer validates whether enough payload remains.
				if i+1 < len(data) && data[i+1] > 3 {
					return NALUnit{}, ErrInvalid
				}
				zeros = 0
				continue
			}
		}
		n.RBSP = append(n.RBSP, b)
		if b == 0 {
			zeros++
		} else {
			zeros = 0
		}
	}
	return n, nil
}
