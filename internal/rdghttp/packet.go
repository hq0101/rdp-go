// Package rdghttp implements internal RDGHTTP framing, a serial binary engine,
// and an explicit HTTPS/NTLM transport profile. It does not yet dial an RDP
// session. Callers must serialize Client operations and apply gateway policy.
package rdghttp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	ErrInvalid     = errors.New("rdghttp: invalid packet")
	ErrLimit       = errors.New("rdghttp: resource limit")
	ErrUnsupported = errors.New("rdghttp: unsupported feature")
	ErrState       = errors.New("rdghttp: unexpected state")
	ErrDenied      = errors.New("rdghttp: decision denied")
)

// Limits are local implementation bounds, not enlarged HTTP body limits.
const (
	HeaderSize     = 8
	MaxPacketSize  = 256 * 1024
	MaxDataSize    = 65535
	MaxStringBytes = 65534
)

type Type uint16

const (
	HandshakeRequest     Type = 1
	HandshakeResponse    Type = 2
	ExtendedAuth         Type = 3
	TunnelCreate         Type = 4
	TunnelResponse       Type = 5
	TunnelAuth           Type = 6
	TunnelAuthResponse   Type = 7
	ChannelCreate        Type = 8
	ChannelResponse      Type = 9
	Data                 Type = 10
	ServiceMessage       Type = 11
	ReauthMessage        Type = 12
	Keepalive            Type = 13
	CloseChannel         Type = 16
	CloseChannelResponse Type = 17
)

const (
	CapSoH uint32 = 1 << iota
	CapIdleTimeout
	CapConsent
	CapService
	CapReauth
	CapUDP
)

// HTTP_TUNNEL_REDIR_FLAGS values are policy constraints, not RDP capabilities.
const (
	RedirEnableAll        uint32 = 0x80000000
	RedirDisableAll       uint32 = 0x40000000
	RedirDisableDrive     uint32 = 1
	RedirDisablePrinter   uint32 = 2
	RedirDisablePort      uint32 = 4
	RedirDisableClipboard uint32 = 8
	RedirDisablePnP       uint32 = 16
)

// Frame owns its body. Reserved header bytes are ignored on receive and zero
// on transmit; unknown packet types fail closed rather than being skipped.
type Frame struct {
	Type Type
	Body []byte
}

func known(t Type) bool {
	return t >= HandshakeRequest && t <= Keepalive || t == CloseChannel || t == CloseChannelResponse
}

func header(b []byte) (Type, int, error) {
	if len(b) < HeaderSize {
		return 0, 0, ErrInvalid
	}
	t := Type(binary.LittleEndian.Uint16(b))
	n := binary.LittleEndian.Uint32(b[4:])
	if !known(t) {
		return 0, 0, ErrUnsupported
	}
	if n < HeaderSize {
		return 0, 0, ErrInvalid
	}
	if n > MaxPacketSize {
		return 0, 0, ErrLimit
	}
	return t, int(n), nil
}

func ParseFrame(b []byte) (Frame, error) {
	t, n, err := header(b)
	if err != nil {
		return Frame{}, err
	}
	if n != len(b) {
		return Frame{}, ErrInvalid
	}
	return Frame{t, append([]byte(nil), b[HeaderSize:]...)}, nil
}

// ReadFrame reads exactly one packet from an already decoded HTTP entity body.
// It never allocates from an unchecked advertised length. HTTP chunk boundaries
// are unrelated to RDG packet boundaries. An error requires closing the stream.
func ReadFrame(r io.Reader) (Frame, error) {
	var h [HeaderSize]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	t, n, err := header(h[:])
	if err != nil {
		return Frame{}, err
	}
	b := make([]byte, n-HeaderSize)
	if _, err = io.ReadFull(r, b); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	return Frame{t, b}, nil
}

func (f Frame) MarshalBinary() ([]byte, error) {
	if !known(f.Type) {
		return nil, ErrUnsupported
	}
	if len(f.Body) > MaxPacketSize-HeaderSize {
		return nil, ErrLimit
	}
	b := make([]byte, HeaderSize+len(f.Body))
	binary.LittleEndian.PutUint16(b, uint16(f.Type))
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	copy(b[8:], f.Body)
	return b, nil
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = ErrInvalid
		return nil
	}
	b := r.b[:n]
	r.b = r.b[n:]
	return b
}
func (r *reader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}
func (r *reader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}
func (r *reader) u64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}
func (r *reader) blob() []byte { return append([]byte(nil), r.take(int(r.u16()))...) }
func (r *reader) text() string {
	b := r.blob()
	if r.err != nil {
		return ""
	}
	s, err := decodeText(b)
	if err != nil {
		r.err = err
	}
	return s
}
func (r *reader) end() error {
	if r.err != nil {
		return r.err
	}
	if len(r.b) != 0 {
		return ErrInvalid
	}
	return nil
}
func (r *reader) flags(mask uint16) uint16 {
	f := r.u16()
	if f & ^mask != 0 {
		r.err = ErrUnsupported
	}
	return f
}
func put16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }
func put32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }
func blob(b, v []byte) []byte         { b = put16(b, uint16(len(v))); return append(b, v...) }

// MS-TSGU counts bytes. Send UTF-16LE including NUL, as in its normal scenario.
// Accept length-delimited strings with or without a final NUL; reject embedded
// NUL, odd byte counts, and unpaired surrogates rather than replacing characters.
func encodeText(s string) ([]byte, error) {
	if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		return nil, ErrInvalid
	}
	if len(s) > MaxStringBytes*2 {
		return nil, ErrLimit
	}
	u := utf16.Encode([]rune(s))
	if len(u)+1 > MaxStringBytes/2 {
		return nil, ErrLimit
	}
	b := make([]byte, 2*(len(u)+1))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b, nil
}
func decodeText(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", ErrInvalid
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	if len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	for i := 0; i < len(u); i++ {
		v := u[i]
		if v == 0 {
			return "", ErrInvalid
		}
		if v >= 0xD800 && v <= 0xDBFF {
			if i+1 >= len(u) || u[i+1] < 0xDC00 || u[i+1] > 0xDFFF {
				return "", ErrInvalid
			}
			i++
		} else if v >= 0xDC00 && v <= 0xDFFF {
			return "", ErrInvalid
		}
	}
	return string(utf16.Decode(u)), nil
}

// Outgoing requests for the ordinary, already HTTP-authenticated profile.
func NewHandshake() Frame { return Frame{HandshakeRequest, []byte{1, 0, 0, 0, 0, 0}} }
func NewTunnel(caps uint32) (Frame, error) {
	if caps & ^uint32(0x3f) != 0 {
		return Frame{}, ErrUnsupported
	}
	b := put32(nil, caps)
	b = append(b, 0, 0, 0, 0)
	return Frame{TunnelCreate, b}, nil
}
func NewAuthorization(name string) (Frame, error) {
	if name == "" {
		return Frame{}, ErrInvalid
	}
	b, err := encodeText(name)
	if err != nil {
		return Frame{}, err
	}
	// MS-TSGU 3.5.1 / note56: 513-byte Windows buffer, including terminator.
	if len(b) > 512 {
		return Frame{}, ErrLimit
	}
	return Frame{TunnelAuth, blob([]byte{0, 0}, b)}, nil
}
func NewChannel(resources, alternatives []string, port uint16) (Frame, error) {
	if len(resources) < 1 || len(resources) > 50 || len(alternatives) > 3 || port == 0 {
		return Frame{}, ErrInvalid
	}
	b := []byte{byte(len(resources)), byte(len(alternatives))}
	b = put16(b, port)
	b = put16(b, 3)
	for _, list := range [][]string{resources, alternatives} {
		for _, s := range list {
			if s == "" {
				return Frame{}, ErrInvalid
			}
			v, err := encodeText(s)
			if err != nil {
				return Frame{}, err
			}
			if len(b)+2+len(v) > MaxPacketSize-HeaderSize {
				return Frame{}, ErrLimit
			}
			b = blob(b, v)
		}
	}
	return Frame{ChannelCreate, b}, nil
}
func NewData(b []byte) (Frame, error) {
	if len(b) > MaxDataSize {
		return Frame{}, ErrLimit
	}
	return Frame{Data, blob(nil, b)}, nil
}
func NewClose(response bool, status uint32) Frame {
	t := CloseChannel
	if response {
		t = CloseChannelResponse
	}
	return Frame{t, put32(nil, status)}
}

type HandshakeInfo struct {
	Status                      uint32
	Major, Minor                byte
	ServerVersion, ExtendedAuth uint16
}
type TunnelInfo struct {
	ServerVersion              uint16
	Status                     uint32
	Fields                     uint16
	ID, Capabilities           uint32
	Nonce                      [16]byte
	ServerCertificate, Consent string
}
type AuthorizationInfo struct {
	Status                               uint32
	Fields                               uint16
	RedirectionFlags, IdleTimeoutMinutes uint32
	SoH                                  []byte
}
type ChannelInfo struct {
	Status  uint32
	Fields  uint16
	ID      uint32
	UDPPort uint16
	Cookie  []byte `json:"-"`
}

// Response decodes one server packet. Blob contents stay opaque; no certificate,
// service text, auth token, or cookie is trusted or acted upon by this codec.
type Response struct {
	Type          Type
	Handshake     HandshakeInfo
	Tunnel        TunnelInfo
	Authorization AuthorizationInfo
	Channel       ChannelInfo
	Status        uint32
	Data          []byte `json:"-"`
	ReauthContext uint64
}

func Decode(f Frame) (Response, error) {
	v := Response{Type: f.Type}
	if len(f.Body) > MaxPacketSize-HeaderSize {
		return Response{}, ErrLimit
	}
	r := reader{b: f.Body}
	switch f.Type {
	case HandshakeResponse:
		v.Handshake.Status = r.u32()
		b := r.take(2)
		if len(b) == 2 {
			v.Handshake.Major = b[0]
			v.Handshake.Minor = b[1]
		}
		v.Handshake.ServerVersion = r.u16()
		v.Handshake.ExtendedAuth = r.u16()
	case TunnelResponse:
		t := &v.Tunnel
		t.ServerVersion = r.u16()
		t.Status = r.u32()
		t.Fields = r.flags(0x17)
		r.take(2)
		if t.Fields&1 != 0 {
			t.ID = r.u32()
		}
		if t.Fields&2 != 0 {
			t.Capabilities = r.u32()
		}
		if t.Fields&4 != 0 {
			copy(t.Nonce[:], r.take(16))
			t.ServerCertificate = r.text()
		}
		if t.Fields&16 != 0 {
			t.Consent = r.text()
		}
	case TunnelAuthResponse:
		a := &v.Authorization
		a.Status = r.u32()
		a.Fields = r.flags(7)
		r.take(2)
		if a.Fields&1 != 0 {
			a.RedirectionFlags = r.u32()
		}
		if a.Fields&2 != 0 {
			a.IdleTimeoutMinutes = r.u32()
		}
		if a.Fields&4 != 0 {
			a.SoH = r.blob()
		}
	case ChannelResponse:
		c := &v.Channel
		c.Status = r.u32()
		c.Fields = r.flags(7)
		r.take(2)
		if c.Fields&1 != 0 {
			c.ID = r.u32()
		}
		if c.Fields&4 != 0 {
			c.UDPPort = r.u16()
		}
		if c.Fields&2 != 0 {
			c.Cookie = r.blob()
		}
	case ExtendedAuth:
		v.Status = r.u32()
		v.Data = r.blob()
	case Data, ServiceMessage:
		v.Data = r.blob()
	case ReauthMessage:
		v.ReauthContext = r.u64()
	case CloseChannel, CloseChannelResponse:
		v.Status = r.u32()
	case Keepalive:
	default:
		return Response{}, ErrUnsupported
	}
	if err := r.end(); err != nil {
		return Response{}, fmt.Errorf("%w: type %d", err, f.Type)
	}
	return v, nil
}

// StatusError preserves the server HRESULT without treating nonzero success
// codes as authorization. The supported exchanges require exactly S_OK.
type StatusError struct {
	Type Type
	Code uint32
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("rdghttp: type %d status 0x%08x", e.Type, e.Code)
}
