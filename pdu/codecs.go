package pdu

import (
	"bytes"
	"encoding/binary"
)

// GUID fields Data1, Data2 and Data3 use little-endian wire order.
var nsCodecGUID = [16]byte{0xb9, 0x1b, 0x8d, 0xca, 0x0f, 0, 0x4f, 0x15, 0x58, 0x9f, 0xae, 0x2d, 0x1a, 0x87, 0xe2, 0xd6}

// Inspect every variable-length entry, including codecs we do not implement.
// Server-assigned IDs are ignored; the client always assigns NSCodec ID 1.
func parseBitmapCodecs(b []byte) (bool, error) {
	if len(b) < 1 {
		return false, ErrInvalid
	}
	count := int(b[0])
	b = b[1:]
	found := false
	for i := 0; i < count; i++ {
		if len(b) < 19 {
			return false, ErrInvalid
		}
		n := int(binary.LittleEndian.Uint16(b[17:]))
		if n > len(b)-19 {
			return false, ErrInvalid
		}
		if bytes.Equal(b[:16], nsCodecGUID[:]) {
			if found || n != 3 || b[19] > 1 || b[20] > 1 || b[21] < 1 || b[21] > 7 {
				return false, ErrInvalid
			}
			found = true
		}
		b = b[19+n:]
	}
	if len(b) != 0 {
		return false, ErrInvalid
	}
	return found, nil
}
