package rdpemt

import (
	"encoding/binary"
	"io"
)

const (
	ActionCreateRequest  byte = 0
	ActionCreateResponse byte = 1
	ActionData           byte = 2
	MaxPayload                = 65535
	MaxHeader                 = 255
)

// SubHeader preserves an extension, including unknown types, for its owner.
// Type 0/1 carry network-detection request/response structures. Their length
// and type bytes are shared with the auto-detect header. Data excludes those
// two bytes (it starts with the sequence number). Raw mode preserves them;
// TunnelOptions.HandleNetworkProbes enables automatic request processing.
type SubHeader struct {
	Type byte
	Data []byte
}

// Packet is a complete MS-RDPEMT PDU; ParsePacket returns owned slices.
// Create requests contain a secret cookie and must not be logged.
type Packet struct {
	Action     byte
	SubHeaders []SubHeader
	Payload    []byte
}

func (p Packet) String() string   { return "rdpemt.Packet{private payload}" }
func (p Packet) GoString() string { return p.String() }

func packetLengths(h []byte, limit int) (int, int, error) {
	if limit == 0 {
		limit = MaxPayload
	}
	if limit < 1 || limit > MaxPayload || len(h) < 4 || h[0] > ActionData || h[3] < 4 {
		return 0, 0, ErrInvalid
	}
	n, header := int(binary.LittleEndian.Uint16(h[1:3])), int(h[3])
	if n > limit {
		return 0, 0, ErrLimit
	}
	if h[0] != ActionData {
		if header != 4 || h[0] == ActionCreateRequest && n != 24 || h[0] == ActionCreateResponse && n != 4 {
			return 0, 0, ErrInvalid
		}
	}
	return header, n, nil
}

// ParsePacket accepts exactly one full PDU. It rejects nonzero reserved flags
// and inconsistent lengths before copying data. Unknown subheader types are
// retained rather than silently dropped; extension semantics belong to callers.
func ParsePacket(b []byte) (Packet, error) {
	h, n, err := packetLengths(b, MaxPayload)
	if err != nil {
		return Packet{}, err
	}
	if len(b) != h+n {
		return Packet{}, ErrInvalid
	}
	if b[0] == ActionCreateRequest && binary.LittleEndian.Uint32(b[8:12]) != 0 {
		return Packet{}, ErrInvalid
	}
	p := Packet{Action: b[0]}
	for i := 4; i < h; {
		if h-i < 2 || b[i] < 2 || int(b[i]) > h-i {
			return Packet{}, ErrInvalid
		}
		end := i + int(b[i])
		p.SubHeaders = append(p.SubHeaders, SubHeader{Type: b[i+1], Data: append([]byte(nil), b[i+2:end]...)})
		i = end
	}
	p.Payload = append([]byte(nil), b[h:]...)
	return p, nil
}

func (p Packet) Marshal() ([]byte, error) {
	if len(p.Payload) > MaxPayload {
		return nil, ErrLimit
	}
	h := 4
	for _, s := range p.SubHeaders {
		if len(s.Data) > 253 || len(s.Data)+2 > MaxHeader-h {
			return nil, ErrLimit
		}
		h += len(s.Data) + 2
	}
	b := make([]byte, h+len(p.Payload))
	b[0], b[3] = p.Action, byte(h)
	binary.LittleEndian.PutUint16(b[1:3], uint16(len(p.Payload)))
	if _, _, err := packetLengths(b, MaxPayload); err != nil {
		return nil, err
	}
	if p.Action == ActionCreateRequest && binary.LittleEndian.Uint32(p.Payload[4:8]) != 0 {
		return nil, ErrInvalid
	}
	i := 4
	for _, s := range p.SubHeaders {
		b[i], b[i+1] = byte(len(s.Data)+2), s.Type
		copy(b[i+2:], s.Data)
		i += len(s.Data) + 2
	}
	copy(b[h:], p.Payload)
	return b, nil
}

// ReadPacket consumes exactly one framed PDU from a reliable byte stream.
// After any error the caller must close the stream: a boundary may be lost.
// limit bounds payload allocation; zero permits the protocol maximum.
func ReadPacket(r io.Reader, limit int) (Packet, error) {
	if r == nil || limit < 0 || limit > MaxPayload {
		return Packet{}, ErrInvalid
	}
	var fixed [4]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return Packet{}, err
	}
	h, n, err := packetLengths(fixed[:], limit)
	if err != nil {
		return Packet{}, err
	}
	b := make([]byte, h+n)
	defer clear(b)
	copy(b, fixed[:])
	if _, err = io.ReadFull(r, b[4:]); err != nil {
		return Packet{}, err
	}
	return ParsePacket(b)
}

// CreateRequest copies the main connection's request ID and secret cookie.
// The returned wire bytes must be sent only over the verified secure sideband.
func CreateRequest(r InitiateRequest) ([]byte, error) {
	if r.Protocol != ReliableUDP && r.Protocol != LossyUDP {
		return nil, ErrInvalid
	}
	payload := make([]byte, 24)
	defer clear(payload)
	binary.LittleEndian.PutUint32(payload, r.ID)
	copy(payload[8:], r.Cookie[:])
	return (Packet{Action: ActionCreateRequest, Payload: payload}).Marshal()
}
