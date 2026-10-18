package rdgateway

import (
	"encoding/binary"
	"errors"
)

var ErrPolicy = errors.New("rdgateway: resource prohibited by gateway policy")

// Policy is an immutable interpretation of the gateway's device restrictions.
// An enable flag never enables a resource the application did not request.
// Applications must additionally apply policy to custom channels/resources.
type Policy struct {
	disabled uint32
	all      bool
}

func NewPolicy(info Info) (Policy, error) {
	if !info.RedirectionFlagsPresent {
		return Policy{}, nil
	}
	f := info.RedirectionFlags
	const known = RedirEnableAll | RedirDisableAll | RedirDisableDrive | RedirDisablePrinter | RedirDisablePort | RedirDisableClipboard | RedirDisablePnP
	if f & ^uint32(known) != 0 {
		return Policy{}, ErrUnsupported
	}
	if f&RedirEnableAll != 0 && f&RedirDisableAll != 0 {
		return Policy{}, ErrInvalid
	}
	if f&RedirEnableAll != 0 {
		return Policy{}, nil
	}
	if f&RedirDisableAll != 0 {
		return Policy{disabled: 31, all: true}, nil
	}
	return Policy{disabled: f}, nil
}
func (p Policy) AllDisabled() bool      { return p.all }
func (p Policy) ClipboardAllowed() bool { return p.disabled&RedirDisableClipboard == 0 }
func (p Policy) PnPAllowed() bool       { return p.disabled&RedirDisablePnP == 0 }

// DeviceAllowed checks MS-RDPEFS DEVICE_ANNOUNCE types: serial=1, parallel=2,
// printer=4, filesystem=8, smartcard=32. Unknown types are not classified.
func (p Policy) DeviceAllowed(kind uint32) bool {
	if p.all {
		return false
	}
	switch kind {
	case 1, 2:
		return p.disabled&RedirDisablePort == 0
	case 4:
		return p.disabled&RedirDisablePrinter == 0
	case 8:
		return p.disabled&RedirDisableDrive == 0
	case 32:
		return true
	default:
		return false
	}
}

// CheckDeviceAnnouncement validates a complete, uncompressed RDPDR device-list
// announcement before fragmentation or transmission. It rejects the entire
// message if any device is disallowed; silently dropping records would desync
// the device client's state. Empty core announcements remain valid for audio.
// Other RDPDR messages are not interpreted. This does not implement devices.
func (p Policy) CheckDeviceAnnouncement(b []byte) error {
	if len(b) < 4 {
		return ErrInvalid
	}
	if binary.LittleEndian.Uint16(b) != 0x4472 || binary.LittleEndian.Uint16(b[2:]) != 0x4441 {
		return nil
	}
	if len(b) < 8 || len(b) > (1<<20)+64 {
		return ErrInvalid
	}
	n := binary.LittleEndian.Uint32(b[4:])
	b = b[8:]
	if n > 64 {
		return ErrLimit
	}
	var ids [64]uint32
	for i := uint32(0); i < n; i++ {
		if len(b) < 20 {
			return ErrInvalid
		}
		kind, id, length := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint32(b[16:])
		if uint64(length) > uint64(len(b)-20) {
			return ErrInvalid
		}
		if !p.DeviceAllowed(kind) {
			return ErrPolicy
		}
		for _, old := range ids[:i] {
			if old == id {
				return ErrInvalid
			}
		}
		ids[i] = id
		b = b[20+int(length):]
	}
	if len(b) != 0 {
		return ErrInvalid
	}
	return nil
}
