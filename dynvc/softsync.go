package dynvc

import "encoding/binary"

// Transport identifies a DVC carrier. UDP values are MS-RDPEDYC tunnel types,
// not the differently numbered MS-RDPBCGR bootstrap protocol or GCC flags.
type Transport uint32

const (
	TCP         Transport = 0
	ReliableUDP Transport = 1
	LossyUDP    Transport = 3
)

// SoftSyncChannelList owns the IDs that the server will move to one tunnel.
type SoftSyncChannelList struct {
	Transport Transport
	IDs       []uint32
}

// ParseSoftSyncRequest validates one complete DYNVC_SOFT_SYNC_REQUEST. It
// accepts both defined tunnel types; Router currently supports reliable only.
// Allocations are bounded by MaxPDU and MaxChannels, including across lists.
func ParseSoftSyncRequest(b []byte) ([]SoftSyncChannelList, error) {
	if len(b) < 10 || len(b) > MaxPDU || b[0] != 0x80 || b[1] != 0 || binary.LittleEndian.Uint32(b[2:]) != uint32(len(b)-2) {
		return nil, ErrProtocol
	}
	flags := binary.LittleEndian.Uint16(b[6:])
	n := int(binary.LittleEndian.Uint16(b[8:]))
	if flags&^uint16(3) != 0 || flags&1 == 0 || (flags&2 != 0) != (n != 0) || n > 2 {
		return nil, ErrProtocol
	}
	b = b[10:]
	lists := make([]SoftSyncChannelList, 0, n)
	seenTypes := make(map[Transport]bool, n)
	seenIDs := make(map[uint32]bool)
	for i := 0; i < n; i++ {
		if len(b) < 6 {
			return nil, ErrProtocol
		}
		tr := Transport(binary.LittleEndian.Uint32(b))
		count := int(binary.LittleEndian.Uint16(b[4:]))
		b = b[6:]
		if (tr != ReliableUDP && tr != LossyUDP) || seenTypes[tr] || count > len(b)/4 {
			return nil, ErrProtocol
		}
		if count > MaxChannels-len(seenIDs) {
			return nil, ErrSize
		}
		seenTypes[tr] = true
		ids := make([]uint32, count)
		for j := range ids {
			id := binary.LittleEndian.Uint32(b[j*4:])
			if seenIDs[id] {
				return nil, ErrProtocol
			}
			seenIDs[id], ids[j] = true, id
		}
		b = b[count*4:]
		lists = append(lists, SoftSyncChannelList{Transport: tr, IDs: ids})
	}
	if len(b) != 0 {
		return nil, ErrProtocol
	}
	return lists, nil
}

// SoftSyncResponse encodes all tunnels the client will use for DVC writes.
// Unlike the request, its count is a 32-bit field and it has no Length field.
func SoftSyncResponse(tunnels []Transport) ([]byte, error) {
	if len(tunnels) > 2 {
		return nil, ErrProtocol
	}
	b := make([]byte, 6, 6+4*len(tunnels))
	b[0] = 0x90
	binary.LittleEndian.PutUint32(b[2:], uint32(len(tunnels)))
	var seen uint32
	for _, tr := range tunnels {
		if tr != ReliableUDP && tr != LossyUDP {
			return nil, ErrProtocol
		}
		if seen&(1<<tr) != 0 {
			return nil, ErrProtocol
		}
		seen |= 1 << tr
		b = binary.LittleEndian.AppendUint32(b, uint32(tr))
	}
	return b, nil
}
