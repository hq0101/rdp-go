package pdu

import (
	"encoding/binary"
	"github.com/hq0101/rdp-go/bulk"
)

// MaxFastPathUpdate is the advertised fragment reassembly limit.
const MaxFastPathUpdate = 1 << 20

// FastPathEvent uses the same DataType and payload format as slow-path events.
// Bitmap and palette payloads still require decoding by their consumers.
type FastPathEvent struct {
	DataType byte
	Payload  []byte
	// SurfaceCommands has no slow-path PDUTYPE2 equivalent; DataType is zero.
	SurfaceCommands bool
	// LargePointer carries xorBpp plus the wide-length pointer body. There is
	// no slow-path message type for this update; DataType remains zero.
	LargePointer bool
}

// FastPathDecoder decompresses then reassembles TLS fast-path output.
// The zero value is ready to use. It is not safe for concurrent use. Discard it
// after any error; partial results from that Feed call are never returned.
type FastPathDecoder struct {
	// Decompress uses the connection's shared history; nil rejects bulk compression.
	Decompress Decompressor
	// AllowOrders must match the negotiated capability profile.
	AllowOrders                        bool
	AllowSurfaceCommands               bool
	AllowNewPointer, AllowLargePointer bool
	fragment                           []byte
	code, compression                  byte
	parts                              int
}

func (d *FastPathDecoder) Feed(b []byte) ([]FastPathEvent, error) {
	if len(b) == 0 || len(b) > 32765 {
		return nil, ErrInvalid
	}
	var events []FastPathEvent
	decodedBytes := 0
	for len(b) > 0 {
		h := b[0]
		b = b[1:]
		code, frag, compression := h&15, (h>>4)&3, h>>6
		switch code {
		case 0:
			if !d.AllowOrders {
				return nil, ErrInvalid
			}
		case 4:
			if !d.AllowSurfaceCommands {
				return nil, ErrInvalid
			}
		case 11:
			if !d.AllowNewPointer {
				return nil, ErrInvalid
			}
		case 12:
			if !d.AllowNewPointer || !d.AllowLargePointer {
				return nil, ErrInvalid
			}
		case 1, 2, 3, 5, 6, 8, 9, 10:
		default:
			return nil, ErrInvalid // unknown or unsupported update code
		}
		flags := byte(0)
		if compression == 2 {
			if len(b) == 0 {
				return nil, ErrInvalid
			}
			flags = b[0]
			b = b[1:]
		} else if compression != 0 {
			return nil, ErrInvalid
		}
		if len(b) < 2 {
			return nil, ErrInvalid
		}
		n := int(binary.LittleEndian.Uint16(b))
		b = b[2:]
		if n > len(b) {
			return nil, ErrInvalid
		}
		payload := b[:n]
		b = b[n:]
		if flags != 0 {
			if d.Decompress == nil {
				return nil, ErrInvalid
			}
			var err error
			payload, err = d.Decompress(flags, payload, min(bulk.MaxDecoded, MaxFastPathUpdate-decodedBytes))
			if err != nil {
				return nil, err
			}
		}
		n = len(payload)
		decodedBytes += n
		if decodedBytes > MaxFastPathUpdate {
			return nil, ErrInvalid
		}
		if frag == 0 {
			if d.parts != 0 {
				return nil, ErrInvalid
			}
			payload = append([]byte(nil), payload...)
		} else {
			if n == 0 || len(d.fragment)+n > MaxFastPathUpdate || d.parts >= 4096 {
				return nil, ErrInvalid
			}
			if frag == 2 {
				if d.parts != 0 {
					return nil, ErrInvalid
				}
				d.code, d.compression = code, compression
			} else if d.parts == 0 || code != d.code || compression != d.compression {
				return nil, ErrInvalid
			}
			d.fragment = append(d.fragment, payload...)
			d.parts++
			if frag != 1 {
				continue
			}
			payload = d.fragment
			d.fragment, d.parts = nil, 0
		}
		e, err := fastPathEvent(code, payload)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
}

func fastPathEvent(code byte, b []byte) (FastPathEvent, error) {
	if code == 12 {
		if len(b) < 20 {
			return FastPathEvent{}, ErrInvalid
		}
		return FastPathEvent{LargePointer: true, Payload: b}, nil
	}
	if code == 4 {
		if len(b) < 2 {
			return FastPathEvent{}, ErrInvalid
		}
		return FastPathEvent{SurfaceCommands: true, Payload: b}, nil
	}
	if code == 0 {
		if len(b) < 2 {
			return FastPathEvent{}, ErrInvalid
		}
		payload := make([]byte, 8, len(b)+6)
		copy(payload[4:6], b[:2])
		return FastPathEvent{DataType: Update, Payload: append(payload, b[2:]...)}, nil
	}
	if code == 1 || code == 2 {
		if len(b) < 4 || binary.LittleEndian.Uint16(b) != uint16(code) {
			return FastPathEvent{}, ErrInvalid
		}
		return FastPathEvent{DataType: Update, Payload: b}, nil
	}
	if code == 3 {
		if len(b) != 0 {
			return FastPathEvent{}, ErrInvalid
		}
		return FastPathEvent{DataType: Update, Payload: []byte{3, 0, 0, 0}}, nil
	}
	var typ uint16
	switch code {
	case 5, 6:
		if len(b) != 0 {
			return FastPathEvent{}, ErrInvalid
		}
		typ, b = 1, make([]byte, 4)
		if code == 6 {
			binary.LittleEndian.PutUint32(b, 0x7f00)
		}
	case 8:
		if len(b) != 4 {
			return FastPathEvent{}, ErrInvalid
		}
		typ = 3
	case 9:
		if len(b) < 14 {
			return FastPathEvent{}, ErrInvalid
		}
		typ = 6 // color pointer attributes remain opaque
	case 10:
		if len(b) != 2 {
			return FastPathEvent{}, ErrInvalid
		}
		typ = 7
	case 11:
		if len(b) < 16 {
			return FastPathEvent{}, ErrInvalid
		}
		typ = 8
	default:
		return FastPathEvent{}, ErrInvalid
	}
	payload := binary.LittleEndian.AppendUint16(nil, typ)
	payload = append(payload, 0, 0)
	return FastPathEvent{DataType: Pointer, Payload: append(payload, b...)}, nil
}
