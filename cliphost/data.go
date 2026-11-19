package cliphost

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/hq0101/rdp-go/cliprdr"
)

// GlobalSize includes allocator padding. Return only the validated representation,
// with owned storage; never send bytes following its logical end to another host.
func cleanData(f cliprdr.Format, b []byte) ([]byte, error) {
	if err := validateData(f, b); err != nil {
		return nil, err
	}
	if f.ID == cliprdr.UnicodeText {
		for i := 0; i+1 < len(b); i += 2 {
			if b[i] == 0 && b[i+1] == 0 {
				return bytes.Clone(b[:i+2]), nil
			}
		}
		return nil, ErrInvalid
	}
	if f.ID == cliprdr.DIB || f.ID == cliprdr.DIBV5 {
		// DecodeDIB above already established dimensions, palettes, masks and
		// supported compression/profile bounds. Preserve that representation.
		u16 := func(i int) int { return int(binary.LittleEndian.Uint16(b[i:])) }
		u32 := func(i int) int { return int(binary.LittleEndian.Uint32(b[i:])) }
		head := u32(0)
		w, h, depth, palette, entry, offset := 0, 0, 0, 0, 4, head
		if head == 12 {
			w, h, depth, entry = u16(4), u16(6), u16(10), 3
		} else {
			w, h, depth, palette = u32(4), int(int32(u32(8))), u16(14), u32(32)
			if h < 0 {
				h = -h
			}
			if head == 40 && u32(16) == 3 {
				offset = 52
			}
		}
		if depth <= 8 && palette == 0 {
			palette = 1 << depth
		}
		pixels := ((w*depth + 31) / 32 * 4) * h
		n := offset + palette*entry + pixels
		if n > len(b) {
			return nil, ErrInvalid
		}
		out := bytes.Clone(b[:n])
		if head != 12 && u32(20) != 0 {
			binary.LittleEndian.PutUint32(out[20:], uint32(pixels))
		}
		return out, nil
	}
	if strings.EqualFold(f.Name, cliprdr.PNGName) {
		for pos := 8; pos+12 <= len(b); {
			n := uint64(binary.BigEndian.Uint32(b[pos:])) + 12
			if n > uint64(len(b)-pos) {
				return nil, ErrInvalid
			}
			end := pos + int(n)
			if string(b[pos+4:pos+8]) == "IEND" {
				return bytes.Clone(b[:end]), nil
			}
			pos = end
		}
		return nil, ErrInvalid
	}
	// Preserve HTML context, URL and selection metadata; trim only bytes after
	// the declared representation. DecodeHTML validated these offsets already.
	end, start := 0, len(b)
	for pos := 0; pos < min(start, 16384); {
		i := pos
		for i < len(b) && b[i] != '\r' && b[i] != '\n' {
			i++
		}
		key, value, ok := strings.Cut(string(b[pos:i]), ":")
		if !ok {
			break
		}
		n, _ := strconv.Atoi(strings.TrimSpace(value))
		switch key {
		case "StartHTML", "StartFragment":
			if n >= 0 {
				start = min(start, n)
			}
		case "EndHTML", "EndFragment", "EndSelection":
			end = max(end, n)
		}
		pos = i
		for pos < len(b) && (b[pos] == '\r' || b[pos] == '\n') {
			pos++
		}
	}
	if end <= 0 || end > len(b) {
		return nil, ErrInvalid
	}
	return append(bytes.Clone(b[:end]), 0), nil
}
