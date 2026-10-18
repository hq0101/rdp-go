// Package mcs implements the RDP subset of T.125 connection and channel PDUs.
package mcs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/hq0101/rdp-go/internal/der"
)

var ErrInvalid = errors.New("mcs: invalid or unsupported PDU")

type ResultError struct {
	Operation string
	Result    uint32
}

func (e *ResultError) Error() string {
	return fmt.Sprintf("mcs: %s rejected (result %d)", e.Operation, e.Result)
}

func parameters(values ...uint32) []byte {
	var b []byte
	for _, n := range values {
		b = append(b, der.Integer(2, n)...)
	}
	return der.Wrap(0x30, b)
}

func ConnectInitial(gcc []byte) ([]byte, error) {
	// Extended Client Data permits a complete GCC request smaller than 4096.
	// The caller enforces the smaller legacy limit using negotiation flags.
	if len(gcc) == 0 || len(gcc) >= 4096 {
		return nil, ErrInvalid
	}
	b := der.Wrap(4, []byte{1})
	b = append(b, der.Wrap(4, []byte{1})...)
	b = append(b, 1, 1, 0xff)
	b = append(b, parameters(34, 2, 0, 1, 0, 1, 65535, 2)...)
	b = append(b, parameters(1, 1, 1, 1, 0, 1, 1056, 2)...)
	b = append(b, parameters(65535, 65535, 65535, 1, 0, 1, 65535, 2)...)
	b = append(b, der.Wrap(4, gcc)...)
	// Application tag 101 uses the two-byte high-tag-number form 7f 65.
	return append([]byte{0x7f}, der.Wrap(0x65, b)...), nil
}

type ConnectResponse struct {
	UserData   []byte
	MaxPDUSize uint32
}

func ParseConnectResponse(b []byte) (ConnectResponse, error) {
	var r ConnectResponse
	if len(b) < 2 || b[0] != 0x7f {
		return r, ErrInvalid
	}
	b = b[1:]
	p, err := der.Take(&b, 0x66)
	if err != nil || len(b) != 0 {
		return r, ErrInvalid
	}
	v, err := der.Take(&p, 10)
	if err != nil {
		return r, err
	}
	result, err := der.Uint(v)
	if err != nil {
		return r, err
	}
	if result != 0 {
		return r, &ResultError{"connect", result}
	}
	v, err = der.Take(&p, 2)
	if err != nil {
		return r, err
	}
	if _, err = der.Uint(v); err != nil {
		return r, err
	}
	domain, err := der.Take(&p, 0x30)
	if err != nil {
		return r, err
	}
	var vals [8]uint32
	for i := range vals {
		v, err = der.Take(&domain, 2)
		if err != nil {
			return r, err
		}
		vals[i], err = der.Uint(v)
		if err != nil {
			return r, err
		}
	}
	if len(domain) != 0 || vals[6] < 1056 || vals[6] > 65535 || vals[7] != 2 {
		return r, ErrInvalid
	}
	r.MaxPDUSize = vals[6]
	r.UserData, err = der.Take(&p, 4)
	if err != nil || len(p) != 0 {
		return r, ErrInvalid
	}
	return r, nil
}

func ErectDomainRequest() []byte { return []byte{4, 1, 0, 1, 0} }
func AttachUserRequest() []byte  { return []byte{0x28} }

func ParseAttachUserConfirm(b []byte) (uint16, error) {
	if len(b) < 2 || (b[0] != 0x2c && b[0] != 0x2e) {
		return 0, ErrInvalid
	}
	// AttachUserConfirm CHOICE is 11 (0x2c); bit 1 denotes optional initiator.
	if b[1] != 0 {
		return 0, &ResultError{"attach user", uint32(b[1])}
	}
	if len(b) != 4 || b[0] != 0x2e {
		return 0, ErrInvalid
	}
	id := uint32(binary.BigEndian.Uint16(b[2:])) + 1001
	if id > 65535 {
		return 0, ErrInvalid
	}
	return uint16(id), nil
}

func ChannelJoinRequest(user, channel uint16) ([]byte, error) {
	if user < 1001 || channel < 1001 {
		return nil, ErrInvalid
	}
	b := []byte{0x38}
	b = binary.BigEndian.AppendUint16(b, user-1001)
	return binary.BigEndian.AppendUint16(b, channel), nil
}
func ParseChannelJoinConfirm(b []byte, user, channel uint16) error {
	if len(b) < 6 || (b[0] != 0x3c && b[0] != 0x3e) {
		return ErrInvalid
	}
	if b[1] != 0 {
		return &ResultError{"channel join", uint32(b[1])}
	}
	if len(b) != 8 || b[0] != 0x3e || user < 1001 || binary.BigEndian.Uint16(b[2:]) != user-1001 || binary.BigEndian.Uint16(b[4:]) != channel || binary.BigEndian.Uint16(b[6:]) != channel {
		return ErrInvalid
	}
	return nil
}
