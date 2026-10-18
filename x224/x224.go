// Package x224 implements the RDP subset of X.224 and security negotiation
// defined in MS-RDPBCGR sections 2.2.1.1 and 2.2.1.2. Packets exclude TPKT.
package x224

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type Protocol uint32

// ExtendedClientDataSupported is a server RDP_NEG_RSP flag authorizing optional
// extended GCC client blocks, including monitor geometry and attributes.
const ExtendedClientDataSupported byte = 0x01

const (
	ProtocolRDP      Protocol = 0
	ProtocolTLS      Protocol = 1
	ProtocolHybrid   Protocol = 2
	ProtocolRDSTLS   Protocol = 4
	ProtocolHybridEx Protocol = 8
	ProtocolRDSAAD   Protocol = 16
)

func (p Protocol) String() string {
	switch p {
	case ProtocolRDP:
		return "RDP Standard Security"
	case ProtocolTLS:
		return "TLS"
	case ProtocolHybrid:
		return "CredSSP/NLA"
	case ProtocolRDSTLS:
		return "RDSTLS"
	case ProtocolHybridEx:
		return "CredSSP/NLA + early authorization"
	case ProtocolRDSAAD:
		return "RDS AAD Auth"
	default:
		return fmt.Sprintf("Protocol(0x%x)", uint32(p))
	}
}

var (
	ErrInvalidPacket = errors.New("x224: invalid packet")
	ErrNLARequired   = errors.New("rdp: server requires NLA/CredSSP")
)

type FailureCode uint32

const (
	TLSRequired           FailureCode = 1
	TLSNotAllowed         FailureCode = 2
	TLSCertificateMissing FailureCode = 3
	InconsistentFlags     FailureCode = 4
	HybridRequired        FailureCode = 5
	TLSUserAuthRequired   FailureCode = 6
	EntraAuthRequired     FailureCode = 7
)

// NegotiationError retains the server's wire-level failure code.
type NegotiationError struct{ Code FailureCode }

func (e *NegotiationError) Error() string {
	names := map[FailureCode]string{
		TLSRequired: "TLS required", TLSNotAllowed: "TLS not allowed",
		TLSCertificateMissing: "server TLS certificate missing",
		InconsistentFlags:     "inconsistent negotiation flags",
		HybridRequired:        "NLA/CredSSP required",
		TLSUserAuthRequired:   "TLS client certificate required",
		EntraAuthRequired:     "Entra ID authentication required",
	}
	if s, ok := names[e.Code]; ok {
		return "rdp negotiation: " + s
	}
	return fmt.Sprintf("rdp negotiation: unknown failure 0x%08x", uint32(e.Code))
}

func (e *NegotiationError) Is(target error) bool {
	return target == ErrNLARequired && e.Code == HybridRequired
}

// Request is an RDP X.224 connection request. Cookie is an optional printable
// ASCII mstshash routing identifier, not a password or authentication token.
// This implementation emits no negotiation flags or correlation information.
type Request struct {
	Protocols Protocol
	Cookie    string
	// RoutingToken is an opaque load-balancer token including its final CRLF.
	// It is sent before TLS. Mutually exclusive with Cookie, at most 241 bytes.
	// The caller controls its destination and lifetime; never log the token.
	RoutingToken []byte `json:"-"`
}

func (r Request) MarshalBinary() ([]byte, error) {
	const known = ProtocolTLS | ProtocolHybrid | ProtocolRDSTLS | ProtocolHybridEx | ProtocolRDSAAD
	if r.Protocols & ^known != 0 {
		return nil, fmt.Errorf("%w: unknown requested protocol", ErrInvalidPacket)
	}
	if r.Protocols&ProtocolHybridEx != 0 && r.Protocols&ProtocolHybrid == 0 {
		return nil, fmt.Errorf("%w: HYBRID_EX requires HYBRID", ErrInvalidPacket)
	}
	var cookie string
	if len(r.RoutingToken) > 0 && r.Cookie != "" {
		return nil, fmt.Errorf("%w: cookie and routing token are mutually exclusive", ErrInvalidPacket)
	}
	if len(r.RoutingToken) > 241 || len(r.RoutingToken) > 0 && !bytes.HasSuffix(r.RoutingToken, []byte{'\r', '\n'}) {
		return nil, fmt.Errorf("%w: routing token length or terminator", ErrInvalidPacket)
	}
	if r.Cookie != "" {
		for _, c := range []byte(r.Cookie) {
			if c < 0x20 || c > 0x7e {
				return nil, fmt.Errorf("%w: cookie must be printable ASCII", ErrInvalidPacket)
			}
		}
		cookie = "Cookie: mstshash=" + r.Cookie + "\r\n"
	}
	// The length indicator is one octet and excludes itself.
	if len(cookie) > 241 {
		return nil, fmt.Errorf("%w: cookie too long", ErrInvalidPacket)
	}
	routing := []byte(cookie)
	if len(r.RoutingToken) > 0 {
		routing = r.RoutingToken
	}
	b := make([]byte, 15+len(routing))
	b[0], b[1] = byte(len(b)-1), 0xe0
	copy(b[7:], routing)
	n := b[7+len(routing):]
	n[0], n[2] = 1, 8
	binary.LittleEndian.PutUint32(n[4:], uint32(r.Protocols))
	return b, nil
}

// Confirm is the server's untrusted, pre-authentication security selection.
// NegotiationPresent is false when an old server omits RDP_NEG_RSP.
type Confirm struct {
	SelectedProtocol   Protocol
	Flags              byte
	NegotiationPresent bool
}

func ParseConfirm(b []byte) (Confirm, error) {
	var c Confirm
	if (len(b) != 7 && len(b) != 15) || int(b[0])+1 != len(b) || b[1] != 0xd0 {
		return c, fmt.Errorf("%w: connection confirm header or length", ErrInvalidPacket)
	}
	// Destination/source references and class/options may be ignored (3.2.5.3.2).
	if len(b) == 7 {
		return c, nil
	}
	n := b[7:]
	if binary.LittleEndian.Uint16(n[2:4]) != 8 {
		return c, fmt.Errorf("%w: negotiation length", ErrInvalidPacket)
	}
	value := binary.LittleEndian.Uint32(n[4:8])
	switch n[0] {
	case 3:
		if n[1] != 0 {
			return c, fmt.Errorf("%w: failure flags", ErrInvalidPacket)
		}
		return c, &NegotiationError{Code: FailureCode(value)}
	case 2:
		p := Protocol(value)
		switch p {
		case ProtocolRDP, ProtocolTLS, ProtocolHybrid, ProtocolRDSTLS, ProtocolHybridEx, ProtocolRDSAAD:
		default:
			return c, fmt.Errorf("%w: selected protocol 0x%x", ErrInvalidPacket, value)
		}
		return Confirm{SelectedProtocol: p, Flags: n[1], NegotiationPresent: true}, nil
	default:
		return c, fmt.Errorf("%w: negotiation type 0x%x", ErrInvalidPacket, n[0])
	}
}

// MarshalData wraps one unsegmented MCS PDU in an X.224 data TPDU.
func MarshalData(payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > 65528 {
		return nil, fmt.Errorf("%w: data length", ErrInvalidPacket)
	}
	b := make([]byte, 3+len(payload))
	b[0], b[1], b[2] = 2, 0xf0, 0x80
	copy(b[3:], payload)
	return b, nil
}

// ParseData returns a view into b. The caller must retain b while using it.
func ParseData(b []byte) ([]byte, error) {
	if len(b) < 4 || b[0] != 2 || b[1] != 0xf0 || b[2] != 0x80 {
		return nil, fmt.Errorf("%w: data TPDU", ErrInvalidPacket)
	}
	return b[3:], nil
}
