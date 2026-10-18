package mcs

import (
	"encoding/binary"
	"fmt"
)

// MaxDataPDUSize is the MS-RDPBCGR 2.2 bound on a complete MCS Send Data
// Request/Indication, excluding TPKT/X.224. A larger negotiated domain size
// does not enlarge this RDP-specific limit or authorize PER fragmentation.
const MaxDataPDUSize = 16383

// MaxDataPayload reserves the eight-byte header used at the maximum length.
const MaxDataPayload = MaxDataPDUSize - 8

var ErrDataSize = fmt.Errorf("%w: Send Data exceeds RDP size limit", ErrInvalid)

// SendDataRequest encodes a complete, high-priority MCS user-data message.
// Fragmented PER lengths and MCS segmentation are not implemented.
func SendDataRequest(user, channel uint16, payload []byte) ([]byte, error) {
	if len(payload) > MaxDataPayload {
		return nil, ErrDataSize
	}
	if user < 1001 || channel < 1001 || len(payload) == 0 {
		return nil, ErrInvalid
	}
	b := []byte{0x64}
	b = binary.BigEndian.AppendUint16(b, user-1001)
	b = binary.BigEndian.AppendUint16(b, channel)
	b = append(b, 0x70) // high priority, begin | end
	if len(payload) < 128 {
		b = append(b, byte(len(payload)))
	} else {
		b = append(b, 0x80|byte(len(payload)>>8), byte(len(payload)))
	}
	return append(b, payload...), nil
}

type DataIndication struct {
	Initiator, Channel uint16
	Payload            []byte // aliases the input
}

func ParseDataIndication(b []byte) (DataIndication, error) {
	var d DataIndication
	if len(b) > MaxDataPDUSize {
		return d, ErrDataSize
	}
	if len(b) < 7 || b[0] != 0x68 || b[5]&0x3f != 0x30 {
		return d, ErrInvalid
	}
	id := uint32(binary.BigEndian.Uint16(b[1:])) + 1001
	d.Channel = binary.BigEndian.Uint16(b[3:])
	if id > 65535 || d.Channel < 1001 {
		return d, ErrInvalid
	}
	d.Initiator = uint16(id)
	n, header := int(b[6]), 7
	if n&0x80 != 0 {
		if len(b) < 8 || n&0xc0 == 0xc0 {
			return d, ErrInvalid
		}
		n, header = (n&0x7f)<<8|int(b[7]), 8
		if n < 128 {
			return DataIndication{}, ErrInvalid
		}
	}
	if n == 0 || n != len(b)-header {
		return d, ErrInvalid
	}
	d.Payload = b[header:]
	return d, nil
}
