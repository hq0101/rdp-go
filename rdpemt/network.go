package rdpemt

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/hq0101/rdp-go/autodetect"
)

// TunnelNetworkInfo describes this reliable tunnel only. Metrics are server
// reports; unknown is distinct from measured zero. Messages/PayloadBytes count
// validated incoming messages before application delivery. ResponsesSent counts
// results accepted by the local stream, not acknowledgments from the server.
// Time samples are taken after assembling a message; application backpressure
// can delay them. These values are not a health or throughput guarantee.
type TunnelNetworkInfo struct {
	Enabled                               bool
	Messages, PayloadBytes, ResponsesSent uint64
	Stats                                 autodetect.Stats
}

type tunnelDetector struct {
	client                 autodetect.Client
	messages, payloadBytes uint64
}

// handle validates a complete message and commits all subheaders/counts as one
// transaction. Subheaders precede payload: a start includes this PDU's payload,
// a stop excludes it. Multiple results are packed into bounded response headers.
// Unknown extensions are rejected here; raw Tunnel mode continues to preserve
// them for callers that implement additional extension semantics.
func (d *tunnelDetector) handle(m Message, now time.Time) ([]Message, error) {
	if len(m.Data) > MaxPayload || len(m.SubHeaders) > (MaxHeader-4)/2 {
		return nil, ErrLimit
	}
	header := 4
	for _, s := range m.SubHeaders {
		if len(s.Data)+2 > MaxHeader-header {
			return nil, ErrLimit
		}
		header += len(s.Data) + 2
		if s.Type != 0 {
			return nil, ErrInvalid
		}
	}
	next := *d
	var replies []Message
	replyHeader := 4
	for _, s := range m.SubHeaders {
		// SubHeaderLength/Type ARE the auto-detect headerLength/headerTypeId,
		// not an additional envelope (MS-RDPEMT 2.2.1.1.1).
		request := append([]byte{byte(len(s.Data) + 2), s.Type}, s.Data...)
		b, err := next.client.HandleReliable(request, now)
		if err != nil {
			if len(request) >= 6 {
				return nil, fmt.Errorf("rdpemt: probe type=%#x bytes=%d measuring=%t: %w", binary.LittleEndian.Uint16(request[4:]), len(request), next.client.Stats().Measuring, err)
			}
			return nil, err
		}
		if b == nil {
			continue
		}
		if len(replies) == 0 || len(b) > MaxHeader-replyHeader {
			replies = append(replies, Message{})
			replyHeader = 4
		}
		i := len(replies) - 1
		replies[i].SubHeaders = append(replies[i].SubHeaders, SubHeader{Type: b[1], Data: b[2:]})
		replyHeader += len(b)
	}
	if err := next.client.ObserveData(len(m.Data)); err != nil {
		return nil, err
	}
	next.messages++
	next.payloadBytes += uint64(len(m.Data))
	*d = next
	return replies, nil
}

// NetworkInfo returns an owned snapshot. It is safe during reads/writes/Close.
// Disabled mode preserves raw subheaders and has no measurement counters.
func (t *Tunnel) NetworkInfo() TunnelNetworkInfo {
	if t == nil || t.conn == nil {
		return TunnelNetworkInfo{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return TunnelNetworkInfo{Enabled: t.handleNetwork, Messages: t.detector.messages,
		PayloadBytes: t.detector.payloadBytes, ResponsesSent: t.probeResponses,
		Stats: t.detector.client.Stats()}
}
