package vchan

import (
	"encoding/binary"
	"github.com/hq0101/rdp-go/bulk"
)

// DecompressChunk removes bulk encoding before a per-channel Decoder reassembles
// the message. All static channels and graphics share the connection's ordered
// decompressor; creating a separate bulk history for each channel is incorrect.
// The result retains the total uncompressed message length and channel flags,
// but has its compression flags cleared. Raw input aliases the caller's buffer.
func DecompressChunk(b []byte, decompress func(byte, []byte, int) ([]byte, error)) ([]byte, error) {
	return DecompressChunkWithLimit(b, decompress, MaxMessage)
}

// DecompressChunkWithLimit validates the total message even for uncompressed
// chunks; the bulk decoder still has its independent per-chunk output bound.
func DecompressChunkWithLimit(b []byte, decompress func(byte, []byte, int) ([]byte, error), limit int) ([]byte, error) {
	if limit < 1 || limit > HardLimit || len(b) < 8 {
		return nil, ErrInvalid
	}
	n := binary.LittleEndian.Uint32(b)
	if n > uint32(limit) {
		return nil, ErrInvalid
	}
	flags := binary.LittleEndian.Uint32(b[4:])
	if flags & ^uint32(0x00ef00f3) != 0 {
		return nil, ErrUnsupported
	}
	compression := byte(flags >> 16)
	if compression == 0 {
		return b, nil
	}
	if decompress == nil {
		return nil, ErrUnsupported
	}
	body, err := decompress(compression, b[8:], int(min(n, bulk.MaxDecoded)))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8, 8+len(body))
	copy(out, b[:8])
	binary.LittleEndian.PutUint32(out[4:], flags&0xf3)
	return append(out, body...), nil
}
