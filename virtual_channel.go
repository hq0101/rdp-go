package rdp

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/hq0101/rdp-go/bulk"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/mcs"
	"github.com/hq0101/rdp-go/rdgateway"
	"github.com/hq0101/rdp-go/vchan"
	"strings"
)

var ErrChannelSuspended = errors.New("rdp: virtual channel traffic suspended by server")

// ChannelID resolves the server-assigned ID for a requested GCC channel name.
func (s *Session) ChannelID(name string) (uint16, bool) { id, ok := s.channelIDs[name]; return id, ok }

// WriteChannel sends one complete static-channel message, compressing its chunks
// when BulkCompression and the server capability allow it. Messages
// are serialized across channels; MCS chunks may interleave desktop input. Feed
// the matching ReadEvent payloads to a per-channel vchan.Decoder for reception.
// Cancellation after a fragment was sent closes the transport to avoid leaving
// an ambiguous partial message. Virtual channels can run during reactivation.
// Set gcc.ChannelShowProtocol in the requested channel's Options when its
// endpoint requires visible headers (cliprdr). Leave it unset for drdynvc.
func (s *Session) WriteChannel(ctx context.Context, id uint16, data []byte) error {
	if s.dynamic != nil && id == s.dynamic.id {
		return errors.New("rdp: use SendDynamic for Session-managed drdynvc")
	}
	return s.writeChannel(ctx, id, data)
}
func (s *Session) writeChannel(ctx context.Context, id uint16, data []byte) error {
	known := false
	channelName := ""
	for name, v := range s.channelIDs {
		if v == id {
			known = true
			channelName = name
			break
		}
	}
	if !known || len(data) > s.channelLimit(id) {
		return errors.New("rdp: unknown static channel or oversized message")
	}
	if i, ok := s.GatewayInfo(); ok && strings.EqualFold(channelName, "rdpdr") {
		policy, err := rdgateway.NewPolicy(i)
		if err != nil {
			return err
		}
		if err = policy.CheckDeviceAnnouncement(data); err != nil {
			return err
		}
	}
	if err := s.connection.Transport.acquire(ctx, s.channelGate); err != nil {
		return err
	}
	defer func() { <-s.channelGate }()
	if s.channelSuspended.Load() {
		return ErrChannelSuspended
	}
	size := int(min(uint32(vchan.ChunkSize), s.Info().ChannelChunkSize))
	size = min(size, mcs.MaxDataPayload-8, int(s.connection.MaxPDUSize)-16, s.connection.Transport.maxSize-23)
	if size < 1 {
		return ErrInvalidFrame
	}
	for off := 0; ; {
		if s.channelSuspended.Load() {
			if off > 0 {
				s.closeNow()
			}
			return ErrChannelSuspended
		}
		b, last, err := vchan.ChunkWithLimit(data, off, size, s.channelLimit(id))
		historyAdvanced := false
		sourceBytes, wireBytes := 0, 0
		if err == nil && s.Info().ChannelCompression && s.channelOptions[id]&(gcc.ChannelCompressRDP|gcc.ChannelCompress) != 0 {
			flags, payload, encodeErr := s.bulkEncoder.Encode(b[8:])
			err = encodeErr
			if err == nil {
				historyAdvanced = flags != 0 // a failed send after history changed is fatal
				if flags&bulk.Compressed != 0 {
					sourceBytes, wireBytes = len(b)-8, len(payload)
				}
				binary.LittleEndian.PutUint32(b[4:], binary.LittleEndian.Uint32(b[4:])|uint32(flags)<<16)
				b = append(b[:8], payload...)
			}
		}
		// Windows RDPDR expects its completion payload without an injected
		// channel header, including fragmented READ responses. Keep this
		// compatibility rule local to rdpdr; an explicit header request wins.
		if err == nil && id == s.channelIDs["rdpdr"] && s.channelOptions[id]&gcc.ChannelShowProtocol == 0 {
			binary.LittleEndian.PutUint32(b[4:], binary.LittleEndian.Uint32(b[4:])&^0x10)
		}
		if err == nil && s.channelOptions[id]&gcc.ChannelShowProtocol != 0 {
			binary.LittleEndian.PutUint32(b[4:], binary.LittleEndian.Uint32(b[4:])|0x10)
		}
		if err == nil {
			b, err = mcs.SendDataRequest(s.connection.UserID, id, b)
		}
		if err == nil {
			err = s.connection.Transport.WriteMCS(ctx, b)
		}
		if err != nil {
			select {
			case <-s.connection.Transport.closed:
				s.failSession(err)
			default:
				if off > 0 || historyAdvanced {
					s.closeNow()
				}
			}
			return err
		}
		if sourceBytes != 0 {
			s.compressionStats.sentWire.Add(uint64(wireBytes))
			s.compressionStats.sentSource.Add(uint64(sourceBytes))
			s.compressionStats.sentPackets.Add(1)
		}
		if last {
			return nil
		}
		off += size
	}
}

func (s *Session) channelLimit(id uint16) int {
	if n := s.channelLimits[id]; n != 0 {
		return n
	}
	return vchan.MaxMessage
}

func validateStaticChannelLimits(input map[string]int, channels []gcc.Channel) (map[string]int, error) {
	if input == nil {
		return nil, nil
	}
	if len(input) > len(channels) {
		return nil, errors.New("rdp: limits for unknown static channels")
	}
	out := make(map[string]int, len(input))
	for name, n := range input {
		found := false
		for _, ch := range channels {
			if ch.Name == name {
				found = true
				break
			}
		}
		if !found || n < 1 || n > vchan.HardLimit {
			return nil, errors.New("rdp: invalid static channel message limit")
		}
		out[name] = n
	}
	return out, nil
}
