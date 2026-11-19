// Package rdpdr implements MS-RDPEFS channel negotiation and device message
// routing. CoreClient advertises no devices, as needed alongside Windows audio.
// DriveClient announces only explicitly configured logical devices; it performs
// no filesystem access. PrinterClient likewise announces explicitly configured
// queues per MS-RDPEPC without touching a local spooler. File request/response
// codecs handle wire layouts; filesystem policy, handles, operation semantics
// and I/O belong to a backend.
package rdpdr

import (
	"encoding/binary"
	"errors"
)

const ChannelName = "rdpdr"

var ErrProtocol = errors.New("rdpdr: invalid, unsupported or out-of-sequence core message")

type Result struct {
	Replies [][]byte
	// Ready means the server confirmed our client ID, exchanged capabilities,
	// and our empty device announcement was returned in Replies. The caller must
	// still send Replies. It does not indicate a redirected device.
	Ready bool
}

// CoreClient has a usable zero value and requires serialized access. The only
// client name it sends is "rdpgo". Its zero value advertises minor version 12
// with servers advertising 12 or 13; DriveClient may explicitly opt into 13.
// Older device protocols are not implemented.
// Unknown/malformed messages return ErrProtocol without changing its state.
// A Server Announce starts a fresh sequence, including after reconnect.
type CoreClient struct {
	started, capabilities, confirmed, loggedOn, listed, userLoggedOn bool
	clientID                                                         uint32
	preferredMinor, minor                                            uint16
}

func (c *CoreClient) Handle(data []byte) (Result, error) {
	var out Result
	if len(data) < 4 || len(data) > 65535 || binary.LittleEndian.Uint16(data) != 0x4472 {
		return out, ErrProtocol
	}
	kind := binary.LittleEndian.Uint16(data[2:])
	body := data[4:]
	if kind == 0x496e {
		if len(body) != 8 || binary.LittleEndian.Uint16(body) != 1 || (binary.LittleEndian.Uint16(body[2:]) != 12 && binary.LittleEndian.Uint16(body[2:]) != 13) {
			return out, ErrProtocol
		}
		minor := uint16(12)
		if c.preferredMinor == 13 && binary.LittleEndian.Uint16(body[2:]) == 13 {
			minor = 13
		}
		id := binary.LittleEndian.Uint32(body[4:])
		reply := []byte{0x72, 0x44, 0x43, 0x43, 1, 0, 12, 0}
		binary.LittleEndian.PutUint16(reply[6:], minor)
		reply = binary.LittleEndian.AppendUint32(reply, id)
		name := []byte{0x72, 0x44, 0x4e, 0x43, 1, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 'r', 0, 'd', 0, 'p', 0, 'g', 0, 'o', 0, 0, 0}
		*c = CoreClient{started: true, clientID: id, preferredMinor: c.preferredMinor, minor: minor}
		out.Replies = [][]byte{reply, name}
		return out, nil
	}
	if !c.started {
		return out, ErrProtocol
	}
	switch kind {
	case 0x5350:
		if c.capabilities || len(body) < 4 {
			return out, ErrProtocol
		}
		count := int(binary.LittleEndian.Uint16(body))
		if count > 64 {
			return out, ErrProtocol
		}
		rest := body[4:]
		version := uint32(1)
		userLoggedOn := false
		seenGeneral := false
		for i := 0; i < count; i++ {
			if len(rest) < 8 {
				return out, ErrProtocol
			}
			n := int(binary.LittleEndian.Uint16(rest[2:]))
			if n < 8 || n > len(rest) {
				return out, ErrProtocol
			}
			if binary.LittleEndian.Uint16(rest) == 1 {
				v := binary.LittleEndian.Uint32(rest[4:])
				if seenGeneral || (v != 1 && v != 2) || (v == 1 && n != 40) || (v == 2 && n != 44) || binary.LittleEndian.Uint16(rest[16:]) != 1 {
					return out, ErrProtocol
				}
				version = v
				userLoggedOn = binary.LittleEndian.Uint32(rest[28:])&4 != 0
				seenGeneral = true
			}
			rest = rest[n:]
		}
		if len(rest) != 0 {
			return out, ErrProtocol
		}
		n := 40
		if version == 2 {
			n = 44
		}
		capability := make([]byte, n)
		binary.LittleEndian.PutUint16(capability, 1)
		binary.LittleEndian.PutUint16(capability[2:], uint16(n))
		binary.LittleEndian.PutUint32(capability[4:], version)
		binary.LittleEndian.PutUint16(capability[16:], 1)
		binary.LittleEndian.PutUint16(capability[18:], c.minor)
		binary.LittleEndian.PutUint32(capability[20:], 0x3fff) // Unused bits mandated as set by 2.2.2.7.1, no devices advertised.
		capability[28] = 2                                     // DISPLAY_NAME unused, always set; no removal or asynchronous I/O.
		if userLoggedOn {
			capability[28] |= 4
		}
		out.Replies = [][]byte{append([]byte{0x72, 0x44, 0x50, 0x43, 1, 0, 0, 0}, capability...)}
		c.capabilities, c.userLoggedOn = true, userLoggedOn
	case 0x4343:
		if len(body) != 8 || binary.LittleEndian.Uint16(body) != 1 || (binary.LittleEndian.Uint16(body[2:]) != 12 && binary.LittleEndian.Uint16(body[2:]) != 13) || binary.LittleEndian.Uint32(body[4:]) != c.clientID {
			return out, ErrProtocol
		}
		if c.confirmed {
			c.loggedOn = true
		}
		c.confirmed = true
	case 0x554c:
		if len(body) != 0 || !c.capabilities || !c.userLoggedOn {
			return out, ErrProtocol
		}
		c.loggedOn = true
	default:
		return out, ErrProtocol
	}
	if c.capabilities && c.confirmed && (!c.userLoggedOn || c.loggedOn) && !c.listed {
		out.Replies = append(out.Replies, []byte{0x72, 0x44, 0x41, 0x44, 0, 0, 0, 0})
		c.listed = true
	}
	out.Ready = c.listed
	return out, nil
}
