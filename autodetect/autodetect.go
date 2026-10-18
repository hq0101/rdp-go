// Package autodetect implements network-characteristics detection on the main
// TLS-protected RDP connection and reliable UDP tunnels (MS-RDPBCGR 2.2.14 and
// 3.2.5.14). Use a separate Client for each carrier. Lossy tunnel measurements
// and client-originated probes are not implemented.
package autodetect

import (
	"encoding/binary"
	"errors"
	"math"
	"time"
)

var ErrInvalid = errors.New("rdp autodetect: invalid request or measurement state")

const (
	RTTContinuous   uint16 = 0x0001
	RTTConnect      uint16 = 0x1001
	StartContinuous uint16 = 0x0014
	StartConnect    uint16 = 0x1014
	Payload         uint16 = 0x0002
	StopConnect     uint16 = 0x002b
	StopContinuous  uint16 = 0x0429
	ResultRTT       uint16 = 0x0840
	ResultBandwidth uint16 = 0x0880
	ResultAll       uint16 = 0x08c0
)

// Metrics contains server-reported values, not a local speed test. The known
// bits distinguish absent fields from measured zero; results update only fields
// present in that message. Units are milliseconds and decimal kilobits/second.
type Metrics struct {
	BaseRTT, AverageRTT, Bandwidth                uint32
	BaseRTTKnown, AverageRTTKnown, BandwidthKnown bool
}

type Request struct {
	Type, Sequence, PayloadLength uint16
	Metrics                       Metrics
}

// ParseRequest does not retain or allocate a copy of random probe payloads.
// It accepts exactly one complete main-connection request, without Security Header.
func ParseRequest(b []byte) (Request, error) {
	var r Request
	if len(b) < 6 || b[1] != 0 {
		return r, ErrInvalid
	}
	r.Type, r.Sequence = binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[2:])
	header, total := 6, 6
	switch r.Type {
	case RTTContinuous, RTTConnect, StartContinuous, StartConnect, StopContinuous:
	case Payload, StopConnect:
		if len(b) < 8 {
			return Request{}, ErrInvalid
		}
		r.PayloadLength = binary.LittleEndian.Uint16(b[6:])
		if r.Type == StopConnect && r.PayloadLength == 0 {
			return Request{}, ErrInvalid
		}
		header, total = 8, 8+int(r.PayloadLength)
	case ResultRTT, ResultBandwidth, ResultAll:
		header, total = 14, 14
		if r.Type == ResultAll {
			header, total = 18, 18
		}
		if len(b) != total {
			return Request{}, ErrInvalid
		}
		i := 6
		if r.Type != ResultBandwidth {
			r.Metrics.BaseRTT = binary.LittleEndian.Uint32(b[i:])
			r.Metrics.BaseRTTKnown = true
			i += 4
		}
		if r.Type != ResultRTT {
			r.Metrics.Bandwidth = binary.LittleEndian.Uint32(b[i:])
			r.Metrics.BandwidthKnown = true
			i += 4
		}
		r.Metrics.AverageRTT = binary.LittleEndian.Uint32(b[i:])
		r.Metrics.AverageRTTKnown = true
	default:
		return Request{}, ErrInvalid
	}
	if int(b[0]) != header || len(b) != total {
		return Request{}, ErrInvalid
	}
	return r, nil
}

type Stats struct {
	Requests, RTTResponses, Measurements, ResultUpdates uint64
	Measuring                                           bool
	LastSequence                                        uint16
	LastTimeDelta, LastByteCount                        uint32
	Metrics                                             Metrics
}

// Client is a bounded, allocation-free measurement state except for replies.
// It is not concurrency-safe. Use a monotonic clock for Handle. Invalid input
// does not commit any state. The zero value is ready for a new connection.
type Client struct {
	stats Stats
	start time.Time
	mode  uint16
	bytes uint64
}

func (c *Client) Stats() Stats { return c.stats }

// ObserveData counts a received RDP payload for continuous measurement only.
// Call once per on-wire PDU, before decompression or application buffering,
// excluding a Basic Security Header when present. Do not call it for measurement
// start/stop messages; Handle accounts for other auto-detect messages itself.
// uint32 overflow aborts instead of reporting a wrapped or fabricated result.
func (c *Client) ObserveData(n int) error {
	if n < 0 {
		return ErrInvalid
	}
	if c.mode != StartContinuous {
		return nil
	}
	if uint64(n) > math.MaxUint32-c.bytes {
		return ErrInvalid
	}
	c.bytes += uint64(n)
	return nil
}

func response(sequence, typ uint16, values ...uint32) []byte {
	b := []byte{byte(6 + 4*len(values)), 1, byte(sequence), byte(sequence >> 8), byte(typ), byte(typ >> 8)}
	for _, value := range values {
		b = binary.LittleEndian.AppendUint32(b, value)
	}
	return b
}

// Handle returns a response without the Security Header, or nil for requests
// with no response. established means the initial connection sequence finished;
// it remains true across reactivation. Repeated start resets the measurement.
// An RTT response contains the server's sequence, not an invented local RTT.
func (c *Client) Handle(b []byte, now time.Time, established bool) ([]byte, error) {
	return c.handle(b, now, established, false)
}

// HandleReliable processes an MS-RDPEMT reliable-tunnel request subheader.
// Only bandwidth start/stop and network results are legal here. Header bytes
// are never counted. Process subheaders in wire order, then call ObserveData
// once with the tunnel payload length (excluding the entire tunnel header).
// Send any response as a response subheader over the same reliable tunnel.
// This is independent of main-connection activation and its measurement state.
func (c *Client) HandleReliable(b []byte, now time.Time) ([]byte, error) {
	return c.handle(b, now, true, true)
}

func (c *Client) handle(b []byte, now time.Time, established, tunnel bool) ([]byte, error) {
	r, err := ParseRequest(b)
	if err != nil {
		return nil, err
	}
	if tunnel {
		switch r.Type {
		case StartContinuous, StopContinuous, ResultRTT, ResultBandwidth, ResultAll:
		default:
			return nil, ErrInvalid
		}
	}
	next := *c
	var reply []byte
	switch r.Type {
	case RTTConnect, StartConnect, Payload, StopConnect:
		if established {
			return nil, ErrInvalid
		}
	case RTTContinuous, StartContinuous, StopContinuous:
		if !established {
			return nil, ErrInvalid
		}
	}
	if !tunnel && r.Type != StartContinuous && r.Type != StartConnect && r.Type != StopContinuous && r.Type != StopConnect {
		if err := next.ObserveData(len(b)); err != nil {
			return nil, err
		}
	}
	switch r.Type {
	case RTTContinuous, RTTConnect:
		reply = response(r.Sequence, 0)
		next.stats.RTTResponses++
	case StartContinuous, StartConnect:
		next.mode, next.start, next.bytes = r.Type, now, 0
		next.stats.Measuring = true
	case Payload:
		if next.mode != StartConnect || uint64(len(b)) > math.MaxUint32-next.bytes {
			return nil, ErrInvalid
		}
		next.bytes += uint64(len(b))
	case StopContinuous, StopConnect:
		want, typ := StartContinuous, uint16(0x000b)
		if r.Type == StopConnect {
			want, typ = StartConnect, 3
		}
		if next.mode != want || now.Before(next.start) {
			return nil, ErrInvalid
		}
		if r.Type == StopConnect {
			if uint64(len(b)) > math.MaxUint32-next.bytes {
				return nil, ErrInvalid
			}
			next.bytes += uint64(len(b))
		}
		delta := now.Sub(next.start).Milliseconds()
		if delta > math.MaxUint32 {
			return nil, ErrInvalid
		}
		next.stats.LastTimeDelta, next.stats.LastByteCount = uint32(delta), uint32(next.bytes)
		reply = response(r.Sequence, typ, uint32(delta), uint32(next.bytes))
		next.mode, next.bytes, next.start = 0, 0, time.Time{}
		next.stats.Measuring = false
		next.stats.Measurements++
	case ResultRTT, ResultBandwidth, ResultAll:
		m := &next.stats.Metrics
		if r.Metrics.BaseRTTKnown {
			m.BaseRTT, m.BaseRTTKnown = r.Metrics.BaseRTT, true
		}
		if r.Metrics.BandwidthKnown {
			m.Bandwidth, m.BandwidthKnown = r.Metrics.Bandwidth, true
		}
		m.AverageRTT, m.AverageRTTKnown = r.Metrics.AverageRTT, true
		next.stats.ResultUpdates++
	}
	next.stats.Requests++
	next.stats.LastSequence = r.Sequence
	*c = next
	return reply, nil
}

// Heartbeat is a server hint, not proof of responsiveness. Zero values are kept
// as received. Consumers choose warning policy; missed heartbeats alone never
// authorize dropping a healthy connection or replaying user input.
type Heartbeat struct{ Period, WarningCount, ReconnectCount byte }

func ParseHeartbeat(b []byte) (Heartbeat, error) {
	if len(b) != 4 || b[0] != 0 {
		return Heartbeat{}, ErrInvalid
	}
	return Heartbeat{Period: b[1], WarningCount: b[2], ReconnectCount: b[3]}, nil
}
