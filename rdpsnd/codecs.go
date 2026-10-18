package rdpsnd

import (
	"encoding/binary"
	"math"
)

// Encoding identifies the negotiated wire codec. Frames always contain decoded
// integer PCM. ADPCM variants here are the 4-bit Microsoft RIFF/WAVE formats.
type Encoding uint16

const (
	PCM      Encoding = 1
	MSADPCM  Encoding = 2
	IMAADPCM Encoding = 0x11
	// MaxPCMFrame bounds decompression and PCM-to-float conversion. Wire audio
	// remains limited by the 16-bit rdpsnd PDU size (at most 65527 bytes).
	MaxPCMFrame = 256 << 10
)

type sourceFormat struct {
	encoding       Encoding
	output         Format
	align, samples int
	coefficients   [][2]int64
}

var msCoefficients = [7][2]int64{{256, 0}, {512, -256}, {0, 0}, {192, 64}, {240, 0}, {460, -208}, {392, -232}}
var msAdaptation = [16]int64{230, 230, 230, 230, 307, 409, 512, 614, 768, 614, 512, 409, 307, 230, 230, 230}

func parseAudioFormat(b []byte) (sourceFormat, bool) {
	var s sourceFormat
	if len(b) < 18 || int(binary.LittleEndian.Uint16(b[16:])) != len(b)-18 {
		return s, false
	}
	s.encoding = Encoding(binary.LittleEndian.Uint16(b))
	s.output = Format{binary.LittleEndian.Uint16(b[2:]), binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint16(b[14:])}
	s.align = int(binary.LittleEndian.Uint16(b[12:]))
	average := uint64(binary.LittleEndian.Uint32(b[8:]))
	if s.encoding == PCM {
		return s, len(b) == 18 && s.output.valid() && s.align == s.output.BlockAlign() && average == uint64(s.output.SampleRate)*uint64(s.align)
	}
	if s.output.BitsPerSample != 4 {
		return s, false
	}
	s.output.BitsPerSample = 16
	if !s.output.valid() || len(b) < 20 {
		return s, false
	}
	channels := int(s.output.Channels)
	s.samples = int(binary.LittleEndian.Uint16(b[18:]))
	switch s.encoding {
	case MSADPCM:
		if len(b) < 22 || s.align < 7*channels || s.samples != 2+(s.align-7*channels)*2/channels {
			return s, false
		}
		n := int(binary.LittleEndian.Uint16(b[20:]))
		if n < 7 || n > 256 || len(b) != 22+4*n {
			return s, false
		}
		for i := 0; i < n; i++ {
			pair := [2]int64{int64(int16(binary.LittleEndian.Uint16(b[22+i*4:]))), int64(int16(binary.LittleEndian.Uint16(b[24+i*4:])))}
			if i < 7 && pair != msCoefficients[i] {
				return sourceFormat{}, false
			}
			s.coefficients = append(s.coefficients, pair)
		}
	case IMAADPCM:
		// Eight codes per channel are grouped in four bytes. A block starts
		// with one four-byte header per channel followed by complete groups.
		if len(b) != 20 || s.align < 4*channels || (s.align-4*channels)%(4*channels) != 0 || s.samples != 1+(s.align-4*channels)*2/channels {
			return s, false
		}
	default:
		return s, false
	}
	expected := uint64(s.output.SampleRate) * uint64(s.align) / uint64(s.samples)
	return s, average == expected && s.samples*channels*2 <= MaxPCMFrame
}

func (s sourceFormat) decodedSize(n int) (int, error) {
	if n <= 0 || n > 65527 || s.align <= 0 || n%s.align != 0 {
		return 0, ErrProtocol
	}
	if s.encoding == PCM {
		return n, nil
	}
	size := n / s.align * s.samples * int(s.output.Channels) * 2
	if size <= 0 || size > MaxPCMFrame {
		return 0, ErrLimit
	}
	return size, nil
}

func (s sourceFormat) decode(data []byte) ([]byte, error) {
	n, err := s.decodedSize(len(data))
	if err != nil {
		return nil, err
	}
	if s.encoding == PCM {
		return append([]byte(nil), data...), nil
	}
	out := make([]byte, n)
	stride := s.samples * int(s.output.Channels) * 2
	for offset, pos := 0, 0; offset < len(data); offset, pos = offset+s.align, pos+stride {
		block := data[offset : offset+s.align]
		if s.encoding == MSADPCM {
			err = s.decodeMS(block, out[pos:pos+stride])
		} else {
			err = s.decodeIMA(block, out[pos:pos+stride])
		}
		if err != nil {
			clear(out)
			return nil, err
		}
	}
	return out, nil
}

func putSample(out []byte, frame, channel, channels int, value int64) {
	binary.LittleEndian.PutUint16(out[(frame*channels+channel)*2:], uint16(int16(value)))
}

func (s sourceFormat) decodeMS(block, out []byte) error {
	channels := int(s.output.Channels)
	var previous, older, delta [2]int64
	var coef [2][2]int64
	for ch := 0; ch < channels; ch++ {
		predictor := int(block[ch])
		if predictor >= len(s.coefficients) {
			return ErrProtocol
		}
		coef[ch] = s.coefficients[predictor]
		delta[ch] = int64(binary.LittleEndian.Uint16(block[channels+2*ch:]))
		previous[ch] = int64(int16(binary.LittleEndian.Uint16(block[3*channels+2*ch:])))
		older[ch] = int64(int16(binary.LittleEndian.Uint16(block[5*channels+2*ch:])))
		putSample(out, 0, ch, channels, older[ch])
		putSample(out, 1, ch, channels, previous[ch])
	}
	for sample := 0; sample < (s.samples-2)*channels; sample++ {
		code := block[7*channels+sample/2]
		if sample%2 == 0 {
			code >>= 4
		} else {
			code &= 15
		}
		ch := sample % channels
		errorDelta := int64(code)
		if code&8 != 0 {
			errorDelta -= 16
		}
		// Windows ACM uses signed fixed-point arithmetic: negative fractional
		// predictions round downward, unlike Go's division toward zero.
		predicted := (previous[ch]*coef[ch][0] + older[ch]*coef[ch][1]) >> 8
		value := max(int64(-32768), min(int64(32767), predicted+errorDelta*delta[ch]))
		putSample(out, 2+sample/channels, ch, channels, value)
		older[ch], previous[ch] = previous[ch], value
		delta[ch] = max(int64(16), delta[ch]*msAdaptation[code]/256)
		// Malicious sustained large codes must not overflow adaptive state.
		if delta[ch] > math.MaxInt32 {
			return ErrProtocol
		}
	}
	return nil
}

var imaSteps = [89]int64{7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767}
var imaIndex = [8]int{-1, -1, -1, -1, 2, 4, 6, 8}

func (s sourceFormat) decodeIMA(block, out []byte) error {
	channels := int(s.output.Channels)
	var value [2]int64
	var index [2]int
	for ch := 0; ch < channels; ch++ {
		value[ch] = int64(int16(binary.LittleEndian.Uint16(block[4*ch:])))
		index[ch] = int(block[4*ch+2])
		if index[ch] > 88 || block[4*ch+3] != 0 {
			return ErrProtocol
		}
		putSample(out, 0, ch, channels, value[ch])
	}
	for base, frame := 4*channels, 1; base < len(block); base, frame = base+4*channels, frame+8 {
		for ch := 0; ch < channels; ch++ {
			for i := 0; i < 8; i++ {
				code := block[base+ch*4+i/2]
				if i%2 == 0 {
					code &= 15
				} else {
					code >>= 4
				}
				step := imaSteps[index[ch]]
				diff := step >> 3
				if code&4 != 0 {
					diff += step
				}
				if code&2 != 0 {
					diff += step >> 1
				}
				if code&1 != 0 {
					diff += step >> 2
				}
				if code&8 != 0 {
					diff = -diff
				}
				value[ch] = max(int64(-32768), min(int64(32767), value[ch]+diff))
				index[ch] = max(0, min(88, index[ch]+imaIndex[code&7]))
				putSample(out, frame+i, ch, channels, value[ch])
			}
		}
	}
	return nil
}
