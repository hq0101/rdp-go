package pdu

import (
	"encoding/binary"
	"fmt"
	"github.com/hq0101/rdp-go/bulk"
)

const (
	DemandActive        uint16 = 1
	ConfirmActive       uint16 = 3
	DeactivateAll       uint16 = 6
	DataPDU             uint16 = 7
	Update              byte   = 2
	Control             byte   = 20
	Pointer             byte   = 27
	Synchronize         byte   = 31
	SaveSessionInfo     byte   = 38
	FontList            byte   = 39
	FontMap             byte   = 40
	SetErrorInfo        byte   = 47
	MonitorLayout       byte   = 55
	AutoReconnectStatus byte   = 50
)

// Share aliases the input buffer. ParseShares handles multiple coalesced PDUs.
type Share struct {
	Type, Source uint16
	Body         []byte
}

func ParseShares(b []byte) ([]Share, error) {
	var out []Share
	for len(b) > 0 {
		if len(b) < 6 || len(out) >= 256 {
			return nil, ErrInvalid
		}
		n, typ := int(binary.LittleEndian.Uint16(b)), binary.LittleEndian.Uint16(b[2:])
		validType := typ&0xfff0 == 0x10 && typ&15 != RedirectionPDU || typ == RedirectionPDU
		if n < 6 || n > len(b) || !validType {
			return nil, ErrInvalid
		}
		out = append(out, Share{Type: typ & 15, Source: binary.LittleEndian.Uint16(b[4:]), Body: b[6:n]})
		b = b[n:]
	}
	if len(out) == 0 {
		return nil, ErrInvalid
	}
	return out, nil
}
func share(typ, source uint16, body []byte) ([]byte, error) {
	if len(body) > 32761 || source < 1001 {
		return nil, ErrInvalid
	}
	b := binary.LittleEndian.AppendUint16(nil, uint16(len(body)+6))
	b = binary.LittleEndian.AppendUint16(b, 0x10|typ)
	b = binary.LittleEndian.AppendUint16(b, source)
	return append(b, body...), nil
}

type Data struct {
	ShareID uint32
	Type    byte
	Payload []byte
}

// Decompressor processes one packet with the connection's shared receive history.
type Decompressor func(flags byte, src []byte, limit int) ([]byte, error)

func ParseData(s Share) (Data, error) { return ParseDataCompressed(s, nil) }

// ParseDataCompressed normalizes compressed payloads before PDU interpretation.
// A nil decompressor retains ParseData's uncompressed-only profile.
func ParseDataCompressed(s Share, decompress Decompressor) (Data, error) {
	var d Data
	b := s.Body
	if s.Type != DataPDU || len(b) < 12 {
		return d, ErrInvalid
	}
	if b[5] != 1 && b[5] != 2 && b[5] != 4 && !(b[5] == 0 && b[8] == Synchronize) {
		return d, ErrInvalid
	}
	payload := b[12:]
	flags, compressedLength := b[9], int(binary.LittleEndian.Uint16(b[10:]))
	if flags&bulk.Compressed != 0 {
		if compressedLength != len(b)+6 {
			return d, ErrInvalid
		}
	} else if compressedLength != 0 {
		return d, ErrInvalid
	}
	if flags != 0 {
		if decompress == nil {
			return d, ErrInvalid
		}
		var err error
		payload, err = decompress(flags, payload, bulk.MaxDecoded)
		if err != nil {
			return d, err
		}
	}
	// Windows has sent uninitialized/inconsistent uncompressedLength fields.
	// Wire framing uses Share Control/ compressedLength; decoder output is bounded
	// independently, and each PDU parser validates its actual decompressed data.
	d = Data{ShareID: binary.LittleEndian.Uint32(b), Type: b[8], Payload: payload}
	return d, nil
}
func MarshalData(source uint16, shareID uint32, typ byte, payload []byte) ([]byte, error) {
	if len(payload) > 32749 {
		return nil, ErrInvalid
	}
	b := binary.LittleEndian.AppendUint32(nil, shareID)
	b = append(b, 0, 1)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(payload)+18))
	b = append(b, typ, 0, 0, 0)
	return share(DataPDU, source, append(b, payload...))
}

type ServerError struct{ Code uint32 }

func (e *ServerError) Error() string { return fmt.Sprintf("rdp: server error info 0x%08x", e.Code) }
