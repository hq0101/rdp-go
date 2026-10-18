// Package rdpudp implements MS-RDPEUDP wire messages, client initialization,
// bounded v1/v2 reliable/lossy delivery, FEC and congestion control, with
// concurrent socket adapters for streams and datagrams. These transports are
// not authenticated RDP sessions. Version3 hands off to the rdpudp2 engine.
// Package rdpemt and Session provide authenticated reliable tunnel integration;
// DTLS and authenticated lossy tunnels remain to be implemented.
package rdpudp

import (
	"encoding/binary"
	"errors"
)

var ErrInvalid = errors.New("rdpudp: invalid datagram")
var ErrLimit = errors.New("rdpudp: resource limit exceeded")

const (
	FlagSYN         uint16 = 0x0001
	FlagACK         uint16 = 0x0004
	FlagData        uint16 = 0x0008
	FlagFEC         uint16 = 0x0010
	FlagCN          uint16 = 0x0020
	FlagCWR         uint16 = 0x0040
	FlagAckOfAcks   uint16 = 0x0100
	FlagLossy       uint16 = 0x0200
	FlagAckDelayed  uint16 = 0x0400
	FlagCorrelation uint16 = 0x0800
	FlagSYNEX       uint16 = 0x1000
	Version1        uint16 = 0x0001
	Version2        uint16 = 0x0002
	Version3        uint16 = 0x0101 // switches data transfer to MS-RDPEUDP2
	MinMTU                 = 1132
	MaxMTU                 = 1232
	MaxAckVector           = 2048
	// Space for the largest payload, ACK vector/alignment, basic and FEC headers.
	// A live connection must additionally enforce its negotiated directional MTU.
	MaxDatagram = MaxMTU + MaxAckVector + 4 + 8 + 12
)

type SYN struct {
	InitialSequence            uint32
	UpstreamMTU, DownstreamMTU uint16
	// Version is effective: an absent/invalid SYNEX version means Version1.
	Version       uint16
	VersionValid  bool
	CorrelationID [16]byte
	// Eight network-order SHA-256 words; populated only on a Version3 client SYN.
	// The codec preserves these words; it does not derive a session cookie hash.
	CookieHash [8]uint32
}

type Source struct {
	CodedSequence, SourceSequence uint32
	Range, FECIndex               byte
}

// Packet is one owned datagram. SYN+ACK uses the SYN layout, without an ACK
// vector. Other ACK messages contain AckVector and optional AckOfAcks before
// the Source/FEC header. Padding is ignored on receive and zeroed on encode.
// CookieHash and Payload may contain sensitive data; do not log Packet values.
type Packet struct {
	SourceAck            uint32
	ReceiveWindow, Flags uint16
	SYN                  SYN
	AckVector            []byte
	AckOfAcks            uint32
	Source               Source
	Payload              []byte
}

func versionOK(v uint16) bool { return v == Version1 || v == Version2 || v == Version3 }
func mtuOK(v uint16) bool     { return v >= MinMTU && v <= MaxMTU }
func zeros(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func validFlags(f uint16) bool {
	if f&FlagSYN != 0 {
		return f & ^uint16(FlagSYN|FlagACK|FlagLossy|FlagCorrelation|FlagSYNEX) == 0
	}
	return f&FlagACK != 0 && f & ^uint16(FlagACK|FlagData|FlagFEC|FlagCN|FlagCWR|FlagAckOfAcks|FlagAckDelayed) == 0 && (f&FlagFEC == 0 || f&FlagData != 0)
}

// Parse copies retained slices and accepts a complete datagram only. It does
// not accept UDP2 data messages. Packet loss is handled by the owning endpoint;
// malformed or out-of-window UDP packets need not terminate the main RDP session.
func Parse(b []byte) (Packet, error) {
	if len(b) < 8 {
		return Packet{}, ErrInvalid
	}
	if len(b) > MaxDatagram {
		return Packet{}, ErrLimit
	}
	p := Packet{SourceAck: binary.BigEndian.Uint32(b), ReceiveWindow: binary.BigEndian.Uint16(b[4:]), Flags: binary.BigEndian.Uint16(b[6:])}
	if !validFlags(p.Flags) {
		return Packet{}, ErrInvalid
	}
	i := 8
	if p.Flags&FlagSYN != 0 {
		if len(b) < i+8 {
			return Packet{}, ErrInvalid
		}
		p.SYN = SYN{InitialSequence: binary.BigEndian.Uint32(b[i:]), UpstreamMTU: binary.BigEndian.Uint16(b[i+4:]), DownstreamMTU: binary.BigEndian.Uint16(b[i+6:]), Version: Version1}
		i += 8
		if !mtuOK(p.SYN.UpstreamMTU) || !mtuOK(p.SYN.DownstreamMTU) || p.ReceiveWindow == 0 {
			return Packet{}, ErrInvalid
		}
		if p.Flags&FlagACK == 0 && p.SourceAck != ^uint32(0) {
			return Packet{}, ErrInvalid
		}
		if p.Flags&FlagCorrelation != 0 {
			if len(b) < i+32 || !zeros(b[i+16:i+32]) {
				return Packet{}, ErrInvalid
			}
			copy(p.SYN.CorrelationID[:], b[i:i+16])
			i += 32
		}
		if p.Flags&FlagSYNEX != 0 {
			if len(b) < i+4 {
				return Packet{}, ErrInvalid
			}
			flags, v := binary.BigEndian.Uint16(b[i:]), binary.BigEndian.Uint16(b[i+2:])
			i += 4
			if flags & ^uint16(1) != 0 {
				return Packet{}, ErrInvalid
			}
			if flags&1 != 0 {
				if !versionOK(v) {
					return Packet{}, ErrInvalid
				}
				p.SYN.Version, p.SYN.VersionValid = v, true
			}
			if p.SYN.Version == Version3 && p.Flags&FlagACK == 0 {
				if len(b) < i+32 {
					return Packet{}, ErrInvalid
				}
				for j := range p.SYN.CookieHash {
					p.SYN.CookieHash[j] = binary.BigEndian.Uint32(b[i+4*j:])
				}
				i += 32
			}
		}
		if p.SYN.Version == Version3 && p.Flags&FlagLossy != 0 {
			return Packet{}, ErrInvalid
		}
		if len(b) != int(min(p.SYN.UpstreamMTU, p.SYN.DownstreamMTU)) || !zeros(b[i:]) {
			return Packet{}, ErrInvalid
		}
		return p, nil
	}
	if len(b) < i+2 {
		return Packet{}, ErrInvalid
	}
	n := int(binary.BigEndian.Uint16(b[i:]))
	size := (n + 2 + 3) &^ 3
	if n > MaxAckVector {
		return Packet{}, ErrLimit
	}
	if len(b) < i+size {
		return Packet{}, ErrInvalid
	}
	vector := b[i+2 : i+2+n]
	if _, err := AckSpan(vector); err != nil {
		return Packet{}, err
	}
	i += size
	if p.Flags&FlagAckOfAcks != 0 {
		if len(b) < i+4 {
			return Packet{}, ErrInvalid
		}
		p.AckOfAcks = binary.BigEndian.Uint32(b[i:])
		i += 4
	}
	if p.Flags&FlagData != 0 {
		size := 8
		if p.Flags&FlagFEC != 0 {
			size = 12
		}
		if len(b) <= i+size || len(b)-(i+size) > MaxMTU {
			return Packet{}, ErrInvalid
		}
		p.Source.CodedSequence, p.Source.SourceSequence = binary.BigEndian.Uint32(b[i:]), binary.BigEndian.Uint32(b[i+4:])
		if size == 12 {
			p.Source.Range, p.Source.FECIndex = b[i+8], b[i+9]
		}
		i += size
		p.Payload = append([]byte(nil), b[i:]...)
	} else if len(b) != i {
		return Packet{}, ErrInvalid
	}
	p.AckVector = append([]byte(nil), vector...)
	return p, nil
}

// Marshal emits canonical zero padding. Fields not selected by Flags must be
// zero/empty, except SYN.Version may specify the implied Version1 without SYNEX.
func (p Packet) Marshal() ([]byte, error) {
	if !validFlags(p.Flags) {
		return nil, ErrInvalid
	}
	b := binary.BigEndian.AppendUint32(nil, p.SourceAck)
	b = binary.BigEndian.AppendUint16(b, p.ReceiveWindow)
	b = binary.BigEndian.AppendUint16(b, p.Flags)
	if p.Flags&FlagSYN != 0 {
		if len(p.AckVector) != 0 || p.AckOfAcks != 0 || p.Source != (Source{}) || len(p.Payload) != 0 || !mtuOK(p.SYN.UpstreamMTU) || !mtuOK(p.SYN.DownstreamMTU) || p.ReceiveWindow == 0 || !versionOK(p.SYN.Version) {
			return nil, ErrInvalid
		}
		if p.Flags&FlagACK == 0 && p.SourceAck != ^uint32(0) {
			return nil, ErrInvalid
		}
		if p.Flags&FlagCorrelation == 0 && p.SYN.CorrelationID != [16]byte{} {
			return nil, ErrInvalid
		}
		if p.Flags&FlagSYNEX == 0 && (p.SYN.Version != Version1 || p.SYN.VersionValid) {
			return nil, ErrInvalid
		}
		if !p.SYN.VersionValid && p.SYN.Version != Version1 {
			return nil, ErrInvalid
		}
		hashPresent := p.SYN.Version == Version3 && p.Flags&FlagACK == 0
		if !hashPresent && p.SYN.CookieHash != [8]uint32{} || p.SYN.Version == Version3 && p.Flags&FlagLossy != 0 {
			return nil, ErrInvalid
		}
		b = binary.BigEndian.AppendUint32(b, p.SYN.InitialSequence)
		b = binary.BigEndian.AppendUint16(b, p.SYN.UpstreamMTU)
		b = binary.BigEndian.AppendUint16(b, p.SYN.DownstreamMTU)
		if p.Flags&FlagCorrelation != 0 {
			b = append(b, p.SYN.CorrelationID[:]...)
			b = append(b, make([]byte, 16)...)
		}
		if p.Flags&FlagSYNEX != 0 {
			valid := uint16(0)
			if p.SYN.VersionValid {
				valid = 1
			}
			b = binary.BigEndian.AppendUint16(b, valid)
			b = binary.BigEndian.AppendUint16(b, p.SYN.Version)
			if hashPresent {
				for _, word := range p.SYN.CookieHash {
					b = binary.BigEndian.AppendUint32(b, word)
				}
			}
		}
		return append(b, make([]byte, int(min(p.SYN.UpstreamMTU, p.SYN.DownstreamMTU))-len(b))...), nil
	}
	if p.SYN != (SYN{}) || p.Flags&FlagAckOfAcks == 0 && p.AckOfAcks != 0 || p.Flags&FlagData == 0 && (p.Source != (Source{}) || len(p.Payload) != 0) {
		return nil, ErrInvalid
	}
	if _, err := AckSpan(p.AckVector); err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(p.AckVector)))
	b = append(b, p.AckVector...)
	b = append(b, make([]byte, (-len(b))&3)...)
	if p.Flags&FlagAckOfAcks != 0 {
		b = binary.BigEndian.AppendUint32(b, p.AckOfAcks)
	}
	if p.Flags&FlagData != 0 {
		if len(p.Payload) == 0 || len(p.Payload) > MaxMTU {
			return nil, ErrInvalid
		}
		if p.Flags&FlagFEC == 0 && (p.Source.Range != 0 || p.Source.FECIndex != 0) {
			return nil, ErrInvalid
		}
		b = binary.BigEndian.AppendUint32(b, p.Source.CodedSequence)
		b = binary.BigEndian.AppendUint32(b, p.Source.SourceSequence)
		if p.Flags&FlagFEC != 0 {
			b = append(b, p.Source.Range, p.Source.FECIndex, 0, 0)
		}
		b = append(b, p.Payload...)
	}
	return b, nil
}
