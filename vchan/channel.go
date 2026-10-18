// Package vchan implements bounded RDP static virtual-channel chunking and
// reassembly. DecompressChunk uses the connection bulk decoder before Feed.
// It does not implement MCS fragmentation or dynamic virtual channels.
package vchan

import (
	"encoding/binary"
	"errors"
)

const MaxMessage = 1 << 20

// HardLimit is the opt-in ceiling; the default per-channel limit stays 1 MiB.
const HardLimit = 32 << 20
const ChunkSize = 1600

var ErrInvalid = errors.New("vchan: invalid chunk or sequence")
var ErrUnsupported = errors.New("vchan: compressed or unsupported channel flags")

// Chunk encodes one portion. Call with increasing offsets until last is true.
func Chunk(data []byte, offset, size int) (packet []byte, last bool, err error) {
	return ChunkWithLimit(data, offset, size, MaxMessage)
}

// ChunkWithLimit permits an explicitly bounded large-message channel.
func ChunkWithLimit(data []byte, offset, size, limit int) (packet []byte, last bool, err error) {
	if limit < 1 || limit > HardLimit || len(data) > limit || offset < 0 || offset > len(data) || size < 1 || size > ChunkSize {
		return nil, false, ErrInvalid
	}
	n := min(size, len(data)-offset)
	// An endpoint normally receives the channel payload without this header.
	// Fragmented messages must expose it so the endpoint can reassemble them.
	flags := uint32(0)
	if len(data) > size {
		flags = 0x10
	}
	if offset == 0 {
		flags |= 1
	}
	last = offset+n == len(data)
	if last {
		flags |= 2
	}
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(data)))
	b = binary.LittleEndian.AppendUint32(b, flags)
	return append(b, data[offset:offset+n]...), last, nil
}

// Decoder is per-channel and requires serialized access. Feed returns an owned
// complete message, or complete=false for a fragment or flow-control notification.
// Reset discards partial data. Errors automatically reset the decoder.
type Decoder struct {
	// Limit is configured before first use. Zero uses MaxMessage. Do not change
	// it while a message is being reassembled. Reset preserves this setting.
	Limit        int
	data         []byte
	total, parts int
	assembling   bool
}

func (d *Decoder) Reset() { *d = Decoder{Limit: d.Limit} }
func (d *Decoder) Feed(b []byte) (message []byte, complete bool, err error) {
	defer func() {
		if err != nil {
			d.Reset()
		}
	}()
	limit := d.Limit
	if limit == 0 {
		limit = MaxMessage
	}
	if limit < 1 || limit > HardLimit || len(b) < 8 {
		return nil, false, ErrInvalid
	}
	n, flags := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:])
	b = b[8:]
	if flags & ^uint32(0xf3) != 0 {
		return nil, false, ErrUnsupported
	}
	if flags&0x60 != 0 {
		if len(b) != 0 || flags&0x60 == 0x60 {
			return nil, false, ErrInvalid
		}
		return nil, false, nil
	}
	if n > uint32(limit) || len(b) > int(n) {
		return nil, false, ErrInvalid
	}
	first, last := flags&1 != 0, flags&2 != 0
	if !d.assembling && flags&3 == 0 {
		if len(b) != int(n) {
			return nil, false, ErrInvalid
		}
		return append([]byte{}, b...), true, nil
	}
	if first {
		if d.assembling {
			return nil, false, ErrInvalid
		}
		d.assembling = true
		d.total = int(n)
	} else if !d.assembling {
		return nil, false, ErrInvalid
	}
	if int(n) != d.total || len(d.data)+len(b) > d.total || d.parts >= max(4096, (limit+255)/256) || (len(b) == 0 && !(first && last && n == 0)) {
		return nil, false, ErrInvalid
	}
	d.parts++
	d.data = append(d.data, b...)
	if last {
		if len(d.data) != d.total {
			return nil, false, ErrInvalid
		}
		message = d.data
		d.Reset()
		return message, true, nil
	}
	if len(d.data) == d.total {
		return nil, false, ErrInvalid
	}
	return nil, false, nil
}
