package mcs

import "fmt"

// DisconnectReason is the T.125 reason enumeration carried by an MCS
// Disconnect Provider Ultimatum (MS-RDPBCGR 2.2.2.3).
type DisconnectReason uint8

const (
	DisconnectDomainDisconnected DisconnectReason = iota
	DisconnectProviderInitiated
	DisconnectTokenPurged
	DisconnectUserRequested
	DisconnectChannelPurged
)

func (r DisconnectReason) String() string {
	switch r {
	case DisconnectDomainDisconnected:
		return "domain disconnected"
	case DisconnectProviderInitiated:
		return "provider initiated"
	case DisconnectTokenPurged:
		return "token purged"
	case DisconnectUserRequested:
		return "user requested"
	case DisconnectChannelPurged:
		return "channel purged"
	}
	return fmt.Sprintf("reason(%d)", uint8(r))
}

// EncodeDisconnectProviderUltimatum encodes the two-byte PER body of MCS
// choice 8: the reason's high bits share the choice byte and its low bit
// leads the second byte.
func EncodeDisconnectProviderUltimatum(reason DisconnectReason) ([]byte, error) {
	if reason > DisconnectChannelPurged {
		return nil, ErrInvalid
	}
	return []byte{byte(8<<2) | byte(reason>>1), byte(reason&1) << 7}, nil
}

// ParseDisconnectProviderUltimatum decodes a complete two-byte body. The
// padding bits of the second byte are ignored.
func ParseDisconnectProviderUltimatum(b []byte) (DisconnectReason, error) {
	if len(b) != 2 || b[0]>>2 != 8 {
		return 0, ErrInvalid
	}
	r := DisconnectReason((b[0]&3)<<1 | b[1]>>7)
	if r > DisconnectChannelPurged {
		return 0, ErrInvalid
	}
	return r, nil
}
