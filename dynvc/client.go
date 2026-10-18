// Package dynvc implements the uncompressed, version 1 MS-RDPEDYC client
// manager. Client handles PDUs without I/O; Router adds ordered carrier writes
// and optional Soft-Sync from the drdynvc static channel to reliable UDP.
package dynvc

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const MaxMessage = 1 << 20
const MaxBuffered = 4 << 20
const MaxChannels = 32
const MaxPDU = 1600

// HardLimit bounds opt-in large listeners such as RDPGFX, including their
// aggregate in-flight reservations. Ordinary listeners retain the old limits.
const HardLimit = 128 << 20

var ErrProtocol = errors.New("dynvc: invalid or unexpected PDU")
var ErrChannel = errors.New("dynvc: channel is not open")
var ErrSize = errors.New("dynvc: message exceeds resource limit")

type Kind uint8

const (
	None Kind = iota
	Ready
	Opened
	Data
	Closed
)

// Event owns its Data. Name is the registered listener, not a system resource.
type Event struct {
	Kind Kind
	ID   uint32
	Name string
	Data []byte
}

type channel struct {
	name         string
	total, parts int
	data         []byte
}

// Client requires serialized calls, including sending each returned PDU in
// order before the next call. Use one manager per RDP connection. Protocol or
// wire-send errors are terminal. The zero value accepts no channel listeners.
// Client excludes compression and priority scheduling. Use Router for carrier
// selection and Soft-Sync; Client alone does not process transport switches.
type Client struct {
	ready       bool
	listeners   map[string]int
	channels    map[uint32]*channel
	buffered    int // reserved sizes of all incomplete messages
	maxBuffered int
	// Retain only recent local closes to discard crossing data without keeping
	// listeners or reassembly buffers active. Create revokes the old ID.
	closedIDs []uint32 // at most MaxChannels, oldest first
}

// New registers exact ANSI byte-string listener names. Unknown names are
// rejected with a failure response, never opened implicitly.
func New(names ...string) (*Client, error) {
	limits := make(map[string]int, len(names))
	for _, name := range names {
		if _, exists := limits[name]; exists {
			return nil, ErrProtocol
		}
		limits[name] = MaxMessage
	}
	return NewWithLimits(limits, MaxBuffered)
}

// NewWithLimits configures maximum message bytes per exact listener name and
// the aggregate reservation limit. It copies the map. Limits apply to incoming
// and outgoing messages; they cannot exceed HardLimit. No channel is implicit.
func NewWithLimits(limits map[string]int, buffered int) (*Client, error) {
	if len(limits) > MaxChannels || buffered < 1 || buffered > HardLimit {
		return nil, ErrSize
	}
	c := &Client{listeners: make(map[string]int), channels: make(map[uint32]*channel), maxBuffered: buffered}
	for name, limit := range limits {
		if len(name) == 0 || len(name) > 255 || bytes.IndexByte([]byte(name), 0) >= 0 {
			return nil, ErrProtocol
		}
		if limit < 1 || limit > buffered {
			return nil, ErrSize
		}
		c.listeners[name] = limit
	}
	return c, nil
}

func (c *Client) Ready() bool { return c.ready }

func number(b []byte, code byte) (uint32, []byte, error) {
	if code > 2 || len(b) < 1<<code {
		return 0, nil, ErrProtocol
	}
	n := 1 << code
	var value uint32
	for i := 0; i < n; i++ {
		value |= uint32(b[i]) << (8 * i)
	}
	return value, b[n:], nil
}

func width(n uint32) byte {
	if n <= 255 {
		return 0
	}
	if n <= 65535 {
		return 1
	}
	return 2
}
func appendNumber(b []byte, n uint32, code byte) []byte {
	for i := 0; i < 1<<code; i++ {
		b = append(b, byte(n>>(8*i)))
	}
	return b
}
func header(cmd byte, id uint32) []byte {
	return appendNumber([]byte{cmd<<4 | width(id)}, id, width(id))
}

// Handle consumes exactly one PDU after static-channel reassembly. Unknown
// channel opens receive a negative HRESULT. Different channels may interleave
// fragmented messages; close discards the channel's incomplete message.
func (c *Client) Handle(b []byte) ([][]byte, Event, error) {
	if len(b) == 0 || len(b) > MaxPDU {
		return nil, Event{}, ErrProtocol
	}
	h := b[0]
	if h>>4 == 5 {
		if c.ready || h&3 != 0 || len(b) < 4 || b[1] != 0 {
			return nil, Event{}, ErrProtocol
		}
		version := binary.LittleEndian.Uint16(b[2:])
		if (version == 1 && len(b) != 4) || ((version == 2 || version == 3) && len(b) != 12) || version < 1 || version > 3 {
			return nil, Event{}, ErrProtocol
		}
		c.ready = true
		return [][]byte{{0x50, 0, 1, 0}}, Event{Kind: Ready}, nil
	}
	if !c.ready {
		return nil, Event{}, ErrProtocol
	}
	id, body, err := number(b[1:], h&3)
	if err != nil {
		return nil, Event{}, err
	}
	ch := c.channels[id]
	switch h >> 4 {
	case 1:
		if len(body) < 2 || len(body) > 256 || body[len(body)-1] != 0 || bytes.IndexByte(body[:len(body)-1], 0) >= 0 || ch != nil {
			return nil, Event{}, ErrProtocol
		}
		c.forgetClosed(id)
		name := string(body[:len(body)-1])
		accept := c.listeners[name] > 0 && len(c.channels) < MaxChannels
		// This implementation exposes one active endpoint per listener.
		for _, existing := range c.channels {
			if existing.name == name {
				accept = false
			}
		}
		status := uint32(0x80004005) // E_FAIL for unknown/unavailable listener
		e := Event{}
		if accept {
			status = 0
			c.channels[id] = &channel{name: name}
			e = Event{Kind: Opened, ID: id, Name: name}
		}
		return [][]byte{binary.LittleEndian.AppendUint32(header(1, id), status)}, e, nil
	case 4:
		if len(body) != 0 {
			return nil, Event{}, ErrProtocol
		}
		if ch == nil {
			return nil, Event{}, nil
		} // already closed; do not echo-loop
		c.buffered -= ch.total
		delete(c.channels, id)
		return [][]byte{header(4, id)}, Event{Kind: Closed, ID: id, Name: ch.name}, nil
	case 2, 3:
		if ch == nil {
			for _, closed := range c.closedIDs {
				if closed == id {
					return nil, Event{}, nil // crossing data after local close
				}
			}
			return nil, Event{}, ErrChannel
		}
		if h>>4 == 2 {
			n, payload, err := number(body, (h>>2)&3)
			if err != nil {
				return nil, Event{}, err
			}
			if n == 0 || uint64(n) > uint64(c.listeners[ch.name]) || uint64(n)+uint64(c.buffered) > uint64(c.maxBuffered) {
				return nil, Event{}, ErrSize
			}
			if ch.total != 0 || len(payload) == 0 || len(payload) > int(n) {
				return nil, Event{}, ErrProtocol
			}
			ch.total = int(n)
			c.buffered += ch.total
			body = payload
		}
		if ch.total == 0 {
			if len(body) > c.listeners[ch.name] {
				return nil, Event{}, ErrSize
			}
			return nil, Event{Kind: Data, ID: id, Name: ch.name, Data: append([]byte{}, body...)}, nil
		}
		if len(body) == 0 || len(body)+len(ch.data) > ch.total || ch.parts >= max(4096, (ch.total+255)/256) {
			return nil, Event{}, ErrProtocol
		}
		ch.parts++
		ch.data = append(ch.data, body...)
		if len(ch.data) != ch.total {
			return nil, Event{}, nil
		}
		e := Event{Kind: Data, ID: id, Name: ch.name, Data: ch.data}
		c.buffered -= ch.total
		ch.data, ch.total, ch.parts = nil, 0, 0
		return nil, e, nil
	default:
		return nil, Event{}, ErrProtocol // no compressed data or multitransport
	}
}

// Send encodes an owned sequence of DATA_FIRST/DATA PDUs for an open channel.
// Send the entire sequence in order without interleaving another message on the
// same channel. A partial send failure must terminate the manager/connection.
func (c *Client) Send(id uint32, data []byte) ([][]byte, error) {
	ch := c.channels[id]
	if !c.ready || ch == nil {
		return nil, ErrChannel
	}
	if len(data) > c.listeners[ch.name] {
		return nil, ErrSize
	}
	if len(data) <= 1590 {
		return [][]byte{append(header(3, id), data...)}, nil
	}
	code := width(uint32(len(data)))
	h := header(2, id)
	h[0] |= code << 2
	h = appendNumber(h, uint32(len(data)), code)
	var packets [][]byte
	for {
		n := min(MaxPDU-len(h), len(data))
		packets = append(packets, append(h, data[:n]...))
		data = data[n:]
		if len(data) == 0 {
			return packets, nil
		}
		h = header(3, id)
	}
}

// Close removes the channel and returns an unsolicited DYNVC_CLOSE response.
// Send it before the next call. MS-RDPEDYC 3.2.5.2 specifies no server reply;
// the next Create may reuse the ID or listener immediately. No Closed event is
// generated for a local close. Crossing data for the last MaxChannels local
// closes is discarded until the corresponding ID is reused.
func (c *Client) Close(id uint32) ([]byte, error) {
	ch := c.channels[id]
	if ch == nil {
		return nil, ErrChannel
	}
	c.buffered -= ch.total
	delete(c.channels, id)
	if len(c.closedIDs) == MaxChannels {
		copy(c.closedIDs, c.closedIDs[1:])
		c.closedIDs = c.closedIDs[:MaxChannels-1]
	}
	c.closedIDs = append(c.closedIDs, id)
	return header(4, id), nil
}

func (c *Client) forgetClosed(id uint32) {
	for i, closed := range c.closedIDs {
		if closed == id {
			c.closedIDs = append(c.closedIDs[:i], c.closedIDs[i+1:]...)
			return
		}
	}
}
