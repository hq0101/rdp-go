package rdpdr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Limits are implementation budgets, not new wire-format restrictions. Configure
// the surrounding virtual-channel decoder with MaxDeviceMessage as its limit.
const (
	MaxDevices         = 64
	MaxDeviceMessage   = (1 << 20) + 64
	MaxPendingRequests = 128
	MaxPendingBytes    = 16 << 20
)

var (
	ErrLimit       = errors.New("rdpdr: resource limit")
	ErrDevice      = errors.New("rdpdr: invalid or duplicate device")
	ErrNotReady    = errors.New("rdpdr: device negotiation not ready")
	ErrUnsupported = errors.New("rdpdr: required capability not supported")
	ErrBusy        = errors.New("rdpdr: device has pending requests")
	ErrRequest     = errors.New("rdpdr: stale, foreign or completed request")
)

// Drive identifies an application-supplied logical device, never a local path.
// Name is a 1..7 byte ASCII DOS name; ':' is allowed only at its end. Label, if
// supplied, is the full Unicode device/share name for drive capability v2.
// It replaces Name for remote access; it is not merely an Explorer label and
// is unrelated to FileFsVolumeInformation.Label.
type Drive struct {
	ID          uint32
	Name, Label string
}

// RemoteName returns the share name used by the v2 DriveClient (Label if set,
// otherwise Name). The standalone v1 announcement encoder uses Name instead.
func (d Drive) RemoteName() string {
	if d.Label != "" {
		return d.Label
	}
	return d.Name
}

func validDrive(d Drive) bool {
	if len(d.Name) == 0 || len(d.Name) > 7 {
		return false
	}
	for i, ch := range []byte(d.Name) {
		if ch < 32 || ch > 126 || strings.ContainsRune(`<>"/\|`, rune(ch)) || ch == ':' && i != len(d.Name)-1 {
			return false
		}
	}
	label := d.RemoteName()
	if !utf8.ValidString(label) {
		return false
	}
	units := 0
	for _, ch := range label {
		if ch < 32 || ch == 127 || ch == '/' || ch == '\\' {
			return false
		}
		units++
		if ch > 0xffff {
			units++
		}
		if units > 255 {
			return false
		}
	}
	return units > 0
}

func validateDrives(drives []Drive) error {
	if len(drives) > MaxDevices {
		return ErrLimit
	}
	for i, d := range drives {
		if !validDrive(d) {
			return ErrDevice
		}
		for _, old := range drives[:i] {
			if old.ID == d.ID || strings.EqualFold(old.Name, d.Name) || strings.EqualFold(old.RemoteName(), d.RemoteName()) {
				return ErrDevice
			}
		}
	}
	return nil
}

// EncodeDriveAnnouncements encodes filesystem devices, with short DOS names for
// version 1 and null-terminated UTF-16 full names for version 2. The latter
// replace PreferredDosName on the server (MS-RDPEFS 2.2.3.1). It accesses no paths.
func EncodeDriveAnnouncements(drives []Drive, version uint32) ([]byte, error) {
	return encodeDriveAnnouncements(drives, version, false)
}

func encodeDriveAnnouncements(drives []Drive, version uint32, asciiNames bool) ([]byte, error) {
	if version != 1 && version != 2 {
		return nil, ErrUnsupported
	}
	if err := validateDrives(drives); err != nil {
		return nil, err
	}
	if asciiNames {
		for _, d := range drives {
			if !asciiDriveName(d.RemoteName()) {
				return nil, ErrDevice
			}
		}
	}
	b := []byte{0x72, 0x44, 0x41, 0x44}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(drives)))
	for _, d := range drives {
		b = binary.LittleEndian.AppendUint32(b, 8) // RDPDR_DTYP_FILESYSTEM
		b = binary.LittleEndian.AppendUint32(b, d.ID)
		var name [8]byte
		copy(name[:], d.Name)
		b = append(b, name[:]...)
		var data []byte
		if version == 2 && asciiNames {
			data = append([]byte(d.RemoteName()), 0)
		} else if version == 2 {
			for _, ch := range utf16.Encode([]rune(d.RemoteName())) {
				data = binary.LittleEndian.AppendUint16(data, ch)
			}
			data = append(data, 0, 0)
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
		b = append(b, data...)
	}
	return b, nil
}

type DeviceReply struct{ DeviceID, Status uint32 }

func DecodeDeviceReply(data []byte) (DeviceReply, error) {
	if len(data) != 12 || !bytes.Equal(data[:4], []byte{0x72, 0x44, 0x72, 0x64}) {
		return DeviceReply{}, ErrProtocol
	}
	return DeviceReply{binary.LittleEndian.Uint32(data[4:]), binary.LittleEndian.Uint32(data[8:])}, nil
}

func EncodeDeviceRemoval(ids []uint32) ([]byte, error) {
	if len(ids) == 0 || len(ids) > MaxDevices {
		return nil, ErrLimit
	}
	b := []byte{0x72, 0x44, 0x4d, 0x44}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(ids)))
	for i, id := range ids {
		for _, old := range ids[:i] {
			if old == id {
				return nil, ErrDevice
			}
		}
		b = binary.LittleEndian.AppendUint32(b, id)
	}
	return b, nil
}

// IOHeader is the common header. Major/minor-specific bodies and file handles
// must be validated by the backend before it performs any operation.
type IOHeader struct{ DeviceID, FileID, CompletionID, MajorFunction, MinorFunction uint32 }

// DecodeIOHeader validates framing and bounds, without interpreting an operation
// body. Unknown major/minor functions are preserved for an explicit error reply.
func DecodeIOHeader(data []byte) (IOHeader, error) {
	if len(data) < 24 || len(data) > MaxDeviceMessage || !bytes.Equal(data[:4], []byte{0x72, 0x44, 0x52, 0x49}) {
		return IOHeader{}, ErrProtocol
	}
	return IOHeader{binary.LittleEndian.Uint32(data[4:]), binary.LittleEndian.Uint32(data[8:]), binary.LittleEndian.Uint32(data[12:]), binary.LittleEndian.Uint32(data[16:]), binary.LittleEndian.Uint32(data[20:])}, nil
}

// EncodeIOCompletion encodes only the common completion envelope. Payload must
// include the operation-specific response fields, including required failure
// padding/lengths. STATUS_PENDING is not a final completion and is rejected.
func EncodeIOCompletion(deviceID, completionID, status uint32, payload []byte) ([]byte, error) {
	if len(payload) > MaxDeviceMessage-16 {
		return nil, ErrLimit
	}
	if status == 0x103 {
		return nil, ErrProtocol
	}
	b := make([]byte, 16, 16+len(payload))
	copy(b, []byte{0x72, 0x44, 0x43, 0x49})
	binary.LittleEndian.PutUint32(b[4:], deviceID)
	binary.LittleEndian.PutUint32(b[8:], completionID)
	binary.LittleEndian.PutUint32(b[12:], status)
	return append(b, payload...), nil
}

// Called only after the common UTF-8/name validation. Reject instead of
// replacing characters or silently creating a differently named share.
func asciiDriveName(name string) bool {
	for _, b := range []byte(name) {
		if b > 0x7e {
			return false
		}
	}
	return true
}
