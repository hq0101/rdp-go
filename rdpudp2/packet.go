// Package rdpudp2 implements the MS-RDPEUDP2 data phase. It is independent of
// the MS-RDPEUDP initialization and of TLS and RDP session/tunnel binding.
// rdpudp.DialContext selects its serial Endpoint when Version3 is negotiated.
// Session multitransport and authenticated tunnel binding remain separate.
package rdpudp2

import (
	"encoding/binary"
	"errors"
)

var (
	ErrInvalid = errors.New("rdpudp2: invalid packet or parameter")
	ErrLimit   = errors.New("rdpudp2: resource limit exceeded")
	ErrClosed  = errors.New("rdpudp2: endpoint closed")
	ErrTimeout = errors.New("rdpudp2: transport timed out")
	ErrState   = errors.New("rdpudp2: invalid endpoint state or time")
)

const (
	FlagACK       uint16 = 0x001
	FlagData      uint16 = 0x004
	FlagACKVector uint16 = 0x008
	FlagAckOfAcks uint16 = 0x010
	FlagOverhead  uint16 = 0x040
	FlagDelayACK  uint16 = 0x100
	allFlags             = FlagACK | FlagData | FlagACKVector | FlagAckOfAcks | FlagOverhead | FlagDelayACK
	MaxMTU               = 1232
	// Windows 10 sends a full MTU-sized DataBody plus optional transport
	// headers. Bound both independently: prefix/header/overhead/delay/AOA/
	// data-sequence and the largest ACK vector (ACK is mutually exclusive).
	MaxDatagram    = MaxMTU + 1 + 2 + 1 + 3 + 2 + 2 + 3 + 4 + 127
	MaxVectorBytes = 127
	MaxVectorSpan  = MaxVectorBytes * 63
)

type ACK struct {
	Sequence  uint16
	Timestamp uint32 // low 24 bits, in units of four microseconds
	SendGap   byte   // milliseconds
	Scale     byte   // microsecond delta multiplier is 1 << Scale
	Deltas    []byte // newest to oldest, at most 15
}

type ACKVector struct {
	Base             uint16
	TimestampPresent bool
	Timestamp        uint32
	SendGap          byte // 255 is an invalid timing sample
	Codes            []byte
}

type DelayACK struct {
	MaxDelayed byte
	TimeoutMS  uint16
}

// Packet owns its variable-length fields after Parse. Dummy transport packets
// are acknowledged, but their user payload must never reach the application.
// Optional fields are meaningful only when their corresponding flag is set.
type Packet struct {
	Flags           uint16
	LogWindow       byte
	Dummy           bool
	ACK             ACK
	Overhead        byte
	DelayACK        DelayACK
	AckOfAcks       uint16
	DataSequence    uint16
	Vector          ACKVector
	ChannelSequence uint16
	Data            []byte
}

func (p Packet) String() string   { return "rdpudp2.Packet{private payload}" }
func (p Packet) GoString() string { return p.String() }

func validFlags(f uint16) bool {
	return f != 0 && f & ^uint16(allFlags) == 0 && f&(FlagACK|FlagACKVector) != FlagACK|FlagACKVector
}

// Parse accepts network format including the byte swap and short-packet padding.
// The zero short-length marker in Microsoft's section 4.4 example is accepted
// as unpadded, per the receive procedure. Marshal always emits the normative
// min(layout length, 7) marker. Padding bytes are unspecified and ignored.
func Parse(b []byte) (Packet, error) {
	if len(b) > MaxDatagram {
		return Packet{}, ErrLimit
	}
	if len(b) < 8 {
		return Packet{}, ErrInvalid
	}
	prefix := b[7]
	typ, short := prefix>>1&15, int(prefix>>5)
	if prefix&1 != 0 || typ != 0 && typ != 8 {
		return Packet{}, ErrInvalid
	}
	n := len(b) - 1
	if short > 0 && short < 7 {
		if len(b) != 8 {
			return Packet{}, ErrInvalid
		}
		n = short
	}
	if n < 2 {
		return Packet{}, ErrInvalid
	}
	// A bounded owned copy also avoids modifying a shared UDP read buffer.
	layout := append([]byte(nil), b[1:]...)
	layout[6] = b[0]
	layout = layout[:n]
	r := reader{b: layout}
	h := r.u16()
	p := Packet{Flags: h & 0xfff, LogWindow: byte(h >> 12), Dummy: typ == 8}
	if !validFlags(p.Flags) {
		return Packet{}, ErrInvalid
	}
	if p.Flags&FlagACK != 0 {
		p.ACK.Sequence = r.u16()
		p.ACK.Timestamp = r.u24()
		p.ACK.SendGap = r.u8()
		x := r.u8()
		p.ACK.Scale = x >> 4
		p.ACK.Deltas = r.take(int(x & 15))
	}
	if p.Flags&FlagOverhead != 0 {
		p.Overhead = r.u8()
	}
	if p.Flags&FlagDelayACK != 0 {
		p.DelayACK = DelayACK{r.u8(), r.u16()}
		// Preserve the full byte hint: Windows 10 advertises values above 15
		// (including 16 and 92). Endpoint ACKs at 15; Marshal emits <=15 only.
	}
	if p.Flags&FlagAckOfAcks != 0 {
		p.AckOfAcks = r.u16()
	}
	if p.Flags&FlagData != 0 {
		p.DataSequence = r.u16()
	}
	if p.Flags&FlagACKVector != 0 {
		p.Vector.Base = r.u16()
		x := r.u8()
		p.Vector.TimestampPresent = x&128 != 0
		if p.Vector.TimestampPresent {
			p.Vector.Timestamp = r.u24()
			p.Vector.SendGap = r.u8()
		}
		p.Vector.Codes = r.take(int(x & 127))
		if _, err := VectorSpan(p.Vector.Codes); err != nil {
			return Packet{}, err
		}
	}
	if p.Flags&FlagData != 0 {
		p.ChannelSequence = r.u16()
		p.Data = r.take(len(r.b) - r.i)
		if len(p.Data) > MaxMTU-2 {
			return Packet{}, ErrLimit
		}
	}
	if r.bad || r.i != len(r.b) {
		return Packet{}, ErrInvalid
	}
	return p, nil
}

func (p Packet) Marshal() ([]byte, error) {
	if !validFlags(p.Flags) || p.LogWindow > 15 {
		return nil, ErrInvalid
	}
	if len(p.Data) > MaxMTU-2 {
		return nil, ErrLimit
	}
	b := make([]byte, 0, 64+len(p.Data))
	b = binary.LittleEndian.AppendUint16(b, p.Flags|uint16(p.LogWindow)<<12)
	if p.Flags&FlagACK != 0 {
		if p.ACK.Timestamp > 0xffffff || p.ACK.Scale > 15 || len(p.ACK.Deltas) > 15 {
			return nil, ErrInvalid
		}
		b = binary.LittleEndian.AppendUint16(b, p.ACK.Sequence)
		b = append24(b, p.ACK.Timestamp)
		b = append(b, p.ACK.SendGap, p.ACK.Scale<<4|byte(len(p.ACK.Deltas)))
		b = append(b, p.ACK.Deltas...)
	}
	if p.Flags&FlagOverhead != 0 {
		b = append(b, p.Overhead)
	}
	if p.Flags&FlagDelayACK != 0 {
		if p.DelayACK.MaxDelayed > 15 {
			return nil, ErrInvalid
		}
		b = append(b, p.DelayACK.MaxDelayed)
		b = binary.LittleEndian.AppendUint16(b, p.DelayACK.TimeoutMS)
	}
	if p.Flags&FlagAckOfAcks != 0 {
		b = binary.LittleEndian.AppendUint16(b, p.AckOfAcks)
	}
	if p.Flags&FlagData != 0 {
		b = binary.LittleEndian.AppendUint16(b, p.DataSequence)
	}
	if p.Flags&FlagACKVector != 0 {
		if _, err := VectorSpan(p.Vector.Codes); err != nil {
			return nil, err
		}
		if p.Vector.Timestamp > 0xffffff {
			return nil, ErrInvalid
		}
		b = binary.LittleEndian.AppendUint16(b, p.Vector.Base)
		x := byte(len(p.Vector.Codes))
		if p.Vector.TimestampPresent {
			x |= 128
		}
		b = append(b, x)
		if p.Vector.TimestampPresent {
			b = append24(b, p.Vector.Timestamp)
			b = append(b, p.Vector.SendGap)
		}
		b = append(b, p.Vector.Codes...)
	}
	if p.Flags&FlagData != 0 {
		b = binary.LittleEndian.AppendUint16(b, p.ChannelSequence)
		b = append(b, p.Data...)
	} else if len(p.Data) != 0 {
		return nil, ErrInvalid
	}
	if len(b)+1 > MaxDatagram {
		return nil, ErrLimit
	}
	prefix := byte(min(len(b), 7)) << 5
	if p.Dummy {
		prefix |= 0x10
	}
	out := make([]byte, max(8, len(b)+1))
	copy(out[1:], b)
	out[0], out[7] = out[7], prefix
	return out, nil
}

func append24(b []byte, v uint32) []byte { return append(b, byte(v), byte(v>>8), byte(v>>16)) }

type reader struct {
	b   []byte
	i   int
	bad bool
}

func (r *reader) take(n int) []byte {
	if n < 0 || n > len(r.b)-r.i {
		r.bad = true
		return nil
	}
	b := r.b[r.i : r.i+n]
	r.i += n
	return b
}
func (r *reader) u8() byte {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (r *reader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}
func (r *reader) u24() uint32 {
	b := r.take(3)
	if b == nil {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}
