// Package rdpemt implements multitransport bootstrap and TLS/DTLS tunnel
// binding/message framing. Soft-Sync and Session policy remain separate;
// a bootstrap message alone is not an authenticated tunnel.
package rdpemt

import (
	"encoding/binary"
	"errors"
)

var ErrInvalid = errors.New("rdpemt: invalid message or configuration")

const (
	ReliableUDP uint16 = 1
	LossyUDP    uint16 = 2
	Success     uint32 = 0
	Abort       uint32 = 0x80004004
)

// InitiateRequest contains a secret from the authenticated main connection.
// Never log Cookie; clear it after the tunnel setup or failure is complete.
type InitiateRequest struct {
	ID       uint32
	Protocol uint16
	Cookie   [16]byte
}

func (r InitiateRequest) String() string   { return "rdpemt.InitiateRequest{private cookie}" }
func (r InitiateRequest) GoString() string { return r.String() }

// ParseInitiateRequest includes the four-byte Basic Security Header; callers
// must have verified TLS and selected the negotiated message channel first.
func ParseInitiateRequest(b []byte) (InitiateRequest, error) {
	if len(b) != 28 || binary.LittleEndian.Uint16(b)&^uint16(0x8000) != 2 || binary.LittleEndian.Uint16(b[10:]) != 0 {
		return InitiateRequest{}, ErrInvalid
	}
	r := InitiateRequest{ID: binary.LittleEndian.Uint32(b[4:]), Protocol: binary.LittleEndian.Uint16(b[8:])}
	if r.Protocol != ReliableUDP && r.Protocol != LossyUDP {
		return InitiateRequest{}, ErrInvalid
	}
	copy(r.Cookie[:], b[12:])
	return r, nil
}

// InitiateResponse emits S_OK only when the server advertised Soft-Sync. Abort
// is allowed regardless of that capability. It includes the security header.
func InitiateResponse(id uint32, success, serverSoftSync bool) ([]byte, error) {
	if success && !serverSoftSync {
		return nil, ErrInvalid
	}
	result := Abort
	if success {
		result = Success
	}
	b := binary.LittleEndian.AppendUint32([]byte{4, 0, 0, 0}, id)
	return binary.LittleEndian.AppendUint32(b, result), nil
}
