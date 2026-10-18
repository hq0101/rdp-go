package rdp

import (
	"github.com/hq0101/rdp-go/bulk"
	"sync/atomic"
)

// CompressionStats counts successfully decoded server bulk packets/chunks and
// compressed client chunks handed to the transport (the Sent fields).
// Raw packets (including flush-only packets) are excluded. These counters prove
// actual use, unlike the advertised SessionInfo.BulkCompression preference.
type CompressionStats struct {
	Packets         uint64 `json:"packets"`
	WireBytes       uint64 `json:"wire_bytes"`
	DecodedBytes    uint64 `json:"decoded_bytes"`
	SentPackets     uint64 `json:"sent_packets"`
	SentWireBytes   uint64 `json:"sent_wire_bytes"`
	SentSourceBytes uint64 `json:"sent_source_bytes"`
	// ByType counts received compressed packets indexed by bulk.Type* (0..3).
	ByType [4]uint64 `json:"packets_by_type"`
}

type compressionCounters struct {
	packets, wire, decoded, sentPackets, sentWire, sentSource atomic.Uint64
	byType                                                    [4]atomic.Uint64
}

// CompressionStats can be called concurrently with ReadEvent. Each field is an
// atomic counter; a snapshot taken during an update can straddle that update.
func (s *Session) CompressionStats() CompressionStats {
	return CompressionStats{
		Packets: s.compressionStats.packets.Load(), WireBytes: s.compressionStats.wire.Load(), DecodedBytes: s.compressionStats.decoded.Load(),
		SentPackets: s.compressionStats.sentPackets.Load(), SentWireBytes: s.compressionStats.sentWire.Load(), SentSourceBytes: s.compressionStats.sentSource.Load(),
		ByType: [4]uint64{s.compressionStats.byType[0].Load(), s.compressionStats.byType[1].Load(), s.compressionStats.byType[2].Load(), s.compressionStats.byType[3].Load()},
	}
}

func (s *Session) decompress(flags byte, src []byte, limit int) ([]byte, error) {
	if flags&15 > s.maximumCompression {
		return nil, bulk.ErrInvalid
	}
	out, err := s.bulkDecoder.Decode(flags, src, limit)
	if err == nil && flags&bulk.Compressed != 0 {
		s.compressionStats.wire.Add(uint64(len(src)))
		s.compressionStats.decoded.Add(uint64(len(out)))
		s.compressionStats.packets.Add(1)
		s.compressionStats.byType[flags&15].Add(1)
	}
	return out, err
}
