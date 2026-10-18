package pdu

import (
	"encoding/binary"
	"fmt"
)

// LicenseError is a server licensing failure, not an NTLM logon failure.
type LicenseError struct{ Code, Transition uint32 }

func (e *LicenseError) Error() string {
	return fmt.Sprintf("rdp licensing: error 0x%08x, transition %d", e.Code, e.Transition)
}

// UnsupportedLicenseError means the server requires the full MS-RDPELE license
// issuance/renewal protocol. No valid-client success is inferred in that case.
type UnsupportedLicenseError struct{ MessageType byte }

func (e *UnsupportedLicenseError) Error() string {
	return fmt.Sprintf("rdp licensing: message 0x%02x requires unsupported license issuance/renewal", e.MessageType)
}

// ParseLicense validates a complete licensing message including its basic
// security header. Only a server-issued STATUS_VALID_CLIENT completes licensing.
func ParseLicense(b []byte) error {
	if len(b) < 8 || binary.LittleEndian.Uint16(b) != 0x80 {
		return ErrInvalid
	}
	// flagsHi is ignored because SEC_FLAGSHI_VALID is not set.
	p := b[4:]
	if p[1]&0x7f != 3 || int(binary.LittleEndian.Uint16(p[2:])) != len(p) {
		return ErrInvalid
	}
	if p[0] != 0xff {
		return &UnsupportedLicenseError{MessageType: p[0]}
	}
	if len(p) < 16 || int(binary.LittleEndian.Uint16(p[14:])) != len(p)-16 {
		return ErrInvalid
	}
	code, transition := binary.LittleEndian.Uint32(p[4:]), binary.LittleEndian.Uint32(p[8:])
	if code != 7 {
		return &LicenseError{Code: code, Transition: transition}
	}
	if transition != 2 || binary.LittleEndian.Uint16(p[12:]) != 4 || len(p) != 16 {
		return ErrInvalid
	}
	return nil
}
