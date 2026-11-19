package cliphost

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/hq0101/rdp-go/clipole"
	"github.com/hq0101/rdp-go/cliprdr"
)

const maxDropBytes = 1 << 20

// decodeDropEffect validates a CF_HDROP "Preferred DropEffect" HGLOBAL payload.
// Explorer writes a single DWORD; an absent format means copy intent. A present
// but malformed value fails rather than guessing. Observing move intent never
// moves or deletes files.
func decodeDropEffect(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, ErrInvalid
	}
	v := binary.LittleEndian.Uint32(b)
	if v < clipole.DropEffectCopy || v > clipole.DropEffectCopy|clipole.DropEffectMove {
		return 0, ErrInvalid
	}
	return v, nil
}

// Decode DROPFILES bounded before allocating names. Unicode lists are decoded
// directly; ANSI lists decode losslessly only while every byte is ASCII (the
// common subset of all ANSI code pages). Non-ASCII ANSI needs the process code
// page, which is unknowable here, so it fails with ErrUnsupported rather than
// being guessed; the Windows acquisition layer normalizes full ANSI via CP_ACP
// before calling this. Padding after the double terminator is not a path. Never
// expose these local absolute paths in protocol metadata.
func decodeDrop(b []byte) ([]string, error) {
	if len(b) < 24 || len(b) > maxDropBytes {
		return nil, ErrInvalid
	}
	start := uint64(binary.LittleEndian.Uint32(b))
	if binary.LittleEndian.Uint32(b[16:]) != 0 {
		if start < 20 || start%2 != 0 || start > uint64(len(b)-4) {
			return nil, ErrInvalid
		}
		return decodeDropWide(b, int(start))
	}
	if start < 20 || start > uint64(len(b)-2) {
		return nil, ErrInvalid
	}
	return decodeDropANSI(b, int(start))
}

func decodeDropWide(b []byte, start int) ([]string, error) {
	var paths []string
	var chars []uint16
	for pos := start; pos+1 < len(b); pos += 2 {
		c := binary.LittleEndian.Uint16(b[pos:])
		if c != 0 {
			if len(chars) >= 32767 {
				return nil, ErrInvalid
			}
			chars = append(chars, c)
			continue
		}
		if len(chars) == 0 {
			if len(paths) == 0 {
				return nil, ErrInvalid
			}
			return paths, nil
		}
		if len(paths) == cliprdr.MaxFiles {
			return nil, cliprdr.ErrFileLimit
		}
		for i := 0; i < len(chars); i++ {
			if chars[i] >= 0xd800 && chars[i] <= 0xdbff {
				i++
				if i >= len(chars) || chars[i] < 0xdc00 || chars[i] > 0xdfff {
					return nil, ErrInvalid
				}
			} else if chars[i] >= 0xdc00 && chars[i] <= 0xdfff {
				return nil, ErrInvalid
			}
		}
		paths = append(paths, string(utf16.Decode(chars)))
		chars = chars[:0]
	}
	return nil, ErrInvalid
}

func decodeDropANSI(b []byte, start int) ([]string, error) {
	var paths []string
	var chars []byte
	for pos := start; pos < len(b); pos++ {
		c := b[pos]
		if c != 0 {
			if c >= 0x80 {
				return nil, ErrUnsupported
			}
			if len(chars) >= 32767 {
				return nil, ErrInvalid
			}
			chars = append(chars, c)
			continue
		}
		if len(chars) == 0 {
			if len(paths) == 0 {
				return nil, ErrInvalid
			}
			return paths, nil
		}
		if len(paths) == cliprdr.MaxFiles {
			return nil, cliprdr.ErrFileLimit
		}
		paths = append(paths, string(chars))
		chars = chars[:0]
	}
	return nil, ErrInvalid
}
