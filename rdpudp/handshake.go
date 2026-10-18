package rdpudp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

var ErrState = errors.New("rdpudp: invalid initialization state")
var ErrTimeout = errors.New("rdpudp: initialization timed out")
var ErrClosed = errors.New("rdpudp: initializer closed")

type InitState uint8

const (
	InitReady InitState = iota
	InitSYNSent
	InitACKReady // local negotiation only; not server authentication or TLS readiness
	InitClosed
)

// InitConfig describes a wire-level offer. The owning transport MUST implement
// data transfer for every offered version and its lower versions before using
// this on a real RDP sideband. Version3 requires MS-RDPEUDP2 data transfer.
type InitConfig struct {
	MaxVersion                 uint16 // zero defaults to Version2
	Lossy                      bool
	ReceiveWindow              uint16        // zero defaults to 64 packets
	UpstreamMTU, DownstreamMTU uint16        // zero defaults to 1232
	CorrelationID              *[16]byte     // optional, copied; same as main negotiation correlation
	CookieHash                 *[8]uint32    // required only for Version3; already derived SHA-256 words
	Retransmits                int           // zero defaults to 3; allowed range 3..5
	Interval                   time.Duration // zero defaults to 800ms; range 10ms..10s
}

// Parameters has no cookie or correlation bytes. The peer's response is
// unauthenticated: pin/verify TLS or DTLS and complete the RDP tunnel binding
// before accepting desktop traffic. Version3 cannot use the Packet data codec.
type Parameters struct {
	Version                                     uint16
	Lossy                                       bool
	LocalInitialSequence, RemoteInitialSequence uint32
	LocalWindow, RemoteWindow                   uint16
	SendMTU, ReceiveMTU                         uint16
}

// Initializer is a single-reader handshake state machine. It opens no socket or
// goroutine. Feed only datagrams from the chosen remote endpoint; call Next at
// Deadline, write returned bytes exactly once, and close it on write/cancel
// failure. Invalid/unrelated packets do not reset its retry timer or commit state.
// Retain it during data handoff to ACK duplicate SYN+ACKs if the final ACK is lost.
type Initializer struct {
	state                                     InitState
	maxVersion, receiveWindow, upMTU, downMTU uint16
	lossy                                     bool
	localSequence                             uint32
	syn                                       []byte
	peer                                      SYN
	parameters                                Parameters
	interval                                  time.Duration
	limit, sent                               int
	next, expires, last                       time.Time
	started                                   time.Time
	roundTrip                                 time.Duration
}

func (h *Initializer) State() InitState               { return h.state }
func (h *Initializer) Parameters() (Parameters, bool) { return h.parameters, h.state == InitACKReady }
func (h *Initializer) Deadline() time.Time            { return h.next }
func (h *Initializer) String() string                 { return "rdpudp.Initializer{private handshake state}" }
func (h *Initializer) GoString() string               { return h.String() }

// RoundTrip is measured only when the SYN was not retransmitted (Karn rule).
// Duplicate SYN+ACKs never replace the initial measurement.
func (h *Initializer) RoundTrip() time.Duration { return h.roundTrip }

func NewInitializer(c InitConfig) (*Initializer, error) { return newInitializer(c, rand.Reader) }

func newInitializer(c InitConfig, entropy io.Reader) (*Initializer, error) {
	if c.MaxVersion == 0 {
		c.MaxVersion = Version2
	}
	if c.ReceiveWindow == 0 {
		c.ReceiveWindow = 64
	}
	if c.UpstreamMTU == 0 {
		c.UpstreamMTU = MaxMTU
	}
	if c.DownstreamMTU == 0 {
		c.DownstreamMTU = MaxMTU
	}
	if c.Retransmits == 0 {
		c.Retransmits = 3
	}
	if c.Interval == 0 {
		c.Interval = 800 * time.Millisecond
	}
	if !versionOK(c.MaxVersion) || c.MaxVersion == Version3 && c.Lossy || (c.CookieHash != nil) != (c.MaxVersion == Version3) || !mtuOK(c.UpstreamMTU) || !mtuOK(c.DownstreamMTU) || c.Retransmits < 3 || c.Retransmits > 5 || c.Interval < 10*time.Millisecond || c.Interval > 10*time.Second {
		return nil, ErrInvalid
	}
	if c.CorrelationID != nil {
		if c.CorrelationID[0] == 0 || c.CorrelationID[0] == 0xf4 {
			return nil, ErrInvalid
		}
		for _, v := range c.CorrelationID {
			if v == 0x0d {
				return nil, ErrInvalid
			}
		}
	}
	var seed [4]byte
	if _, err := io.ReadFull(entropy, seed[:]); err != nil {
		return nil, err
	}
	p := Packet{SourceAck: ^uint32(0), ReceiveWindow: c.ReceiveWindow, Flags: FlagSYN, SYN: SYN{InitialSequence: binary.BigEndian.Uint32(seed[:]), UpstreamMTU: c.UpstreamMTU, DownstreamMTU: c.DownstreamMTU, Version: c.MaxVersion}}
	if c.Lossy {
		p.Flags |= FlagLossy
	}
	if c.MaxVersion != Version1 {
		p.Flags |= FlagSYNEX
		p.SYN.VersionValid = true
	}
	if c.CorrelationID != nil {
		p.Flags |= FlagCorrelation
		p.SYN.CorrelationID = *c.CorrelationID
	}
	if c.CookieHash != nil {
		p.SYN.CookieHash = *c.CookieHash
	}
	b, err := p.Marshal()
	if err != nil {
		return nil, err
	}
	return &Initializer{maxVersion: c.MaxVersion, receiveWindow: c.ReceiveWindow, upMTU: c.UpstreamMTU, downMTU: c.DownstreamMTU, lossy: c.Lossy, localSequence: p.SYN.InitialSequence, syn: b, interval: c.Interval, limit: c.Retransmits + 1}, nil
}

// Next returns an owned initial/retransmitted SYN, or nil before its deadline.
// A delayed caller cannot extend the fixed total handshake deadline. Packet
// loss changes neither sequence numbers nor the original capability offer.
func (h *Initializer) Next(now time.Time) ([]byte, error) {
	if h.state == InitClosed {
		return nil, ErrClosed
	}
	if now.Before(h.last) {
		return nil, ErrState
	}
	if h.state == InitACKReady {
		return nil, nil
	}
	if h.state == InitReady {
		if len(h.syn) == 0 {
			return nil, ErrState // require NewInitializer, not an empty offer
		}
		h.state = InitSYNSent
		h.started = now
		h.expires = now.Add(time.Duration(h.limit) * h.interval)
	} else if !now.Before(h.expires) {
		h.Close()
		return nil, ErrTimeout
	} else if now.Before(h.next) {
		return nil, nil
	}
	h.last = now
	if h.sent >= h.limit {
		h.next = h.expires
		return nil, nil
	}
	h.sent++
	h.next = now.Add(h.interval)
	if h.next.After(h.expires) {
		h.next = h.expires
	}
	return append([]byte(nil), h.syn...), nil
}

// Handle returns the final ACK for an acceptable SYN+ACK. Callers must send that
// ACK before handing off to a data engine. An identical retransmission receives
// the same ACK; a changed peer offer cannot silently change established state.
func (h *Initializer) Handle(datagram []byte, now time.Time) ([]byte, error) {
	if h.state == InitClosed {
		return nil, ErrClosed
	}
	if h.state == InitReady || now.Before(h.last) {
		return nil, ErrState
	}
	if h.state == InitSYNSent && !now.Before(h.expires) {
		h.Close()
		return nil, ErrTimeout
	}
	p, err := Parse(datagram)
	if err != nil {
		return nil, err
	}
	if p.Flags&(FlagSYN|FlagACK) != (FlagSYN|FlagACK) || p.SourceAck != h.localSequence || p.SYN.Version > h.maxVersion || !h.lossy && p.Flags&FlagLossy != 0 || p.SYN.UpstreamMTU > h.upMTU || p.SYN.DownstreamMTU > h.downMTU {
		return nil, ErrInvalid
	}
	if h.state == InitACKReady && (p.SYN != h.peer || p.ReceiveWindow != h.parameters.RemoteWindow) {
		return nil, ErrInvalid
	}
	ack := Packet{SourceAck: p.SYN.InitialSequence, ReceiveWindow: h.receiveWindow, Flags: FlagACK, AckVector: []byte{1}}
	b, err := ack.Marshal()
	if err != nil {
		return nil, err
	}
	if h.state == InitSYNSent && h.sent == 1 {
		h.roundTrip = max(time.Nanosecond, now.Sub(h.started))
	}
	h.state = InitACKReady
	h.peer = p.SYN
	h.parameters = Parameters{Version: p.SYN.Version, Lossy: h.lossy, LocalInitialSequence: h.localSequence, RemoteInitialSequence: p.SYN.InitialSequence, LocalWindow: h.receiveWindow, RemoteWindow: p.ReceiveWindow, SendMTU: p.SYN.UpstreamMTU, ReceiveMTU: p.SYN.DownstreamMTU}
	h.last = now
	h.next = time.Time{}
	clear(h.syn)
	h.syn = nil
	return b, nil
}

// Close clears the retained SYN and peer metadata and permanently prevents use.
// It does not close sockets; those are owned by the transport integrating it.
func (h *Initializer) Close() { clear(h.syn); *h = Initializer{state: InitClosed} }
