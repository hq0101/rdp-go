package rdpudp

// RejectionStats partitions RejectedDatagrams in the established connection.
// These are local validation failures, not an estimate of network packet loss.
// All fields are counters; no raw packet, peer-provided string or payload is kept.
type RejectionStats struct {
	DatagramSize, Initialization, Packet, PayloadSize                                     uint64
	ACK, AckOfAcks, DataSequence, DataWindow, ChannelSequence, ChannelWindow, ChannelData uint64
	LegacyInvalid, LegacyLimit, Other                                                     uint64
}

// mu is held. Fixed counters keep diagnostic storage independent of traffic.
func (b *connBase) rejectLocked(reason string) {
	b.rejected++
	switch reason {
	case "datagram-size":
		b.rejections.DatagramSize++
	case "initialization":
		b.rejections.Initialization++
	case "packet":
		b.rejections.Packet++
	case "payload-size":
		b.rejections.PayloadSize++
	case "ack":
		b.rejections.ACK++
	case "ack-of-acks":
		b.rejections.AckOfAcks++
	case "data-sequence":
		b.rejections.DataSequence++
	case "data-window":
		b.rejections.DataWindow++
	case "channel-sequence":
		b.rejections.ChannelSequence++
	case "channel-window":
		b.rejections.ChannelWindow++
	case "channel-data":
		b.rejections.ChannelData++
	case "legacy-invalid":
		b.rejections.LegacyInvalid++
	case "legacy-limit":
		b.rejections.LegacyLimit++
	default:
		b.rejections.Other++
	}
}
