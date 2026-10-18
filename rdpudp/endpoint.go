package rdpudp

import (
	"errors"
	"time"
)

const (
	MaxWindowPackets = 1024
	MaxQueuedPackets = 1024
	maxFECGroups     = 8
	maxCodedWindow   = 8192
	keepalivePeriod  = 15 * time.Second
	idleTimeout      = 65 * time.Second
)

var (
	ErrEndpointClosed = errors.New("rdpudp: endpoint closed")
	ErrDataTimeout    = errors.New("rdpudp: peer silent for 65 seconds")
	ErrRetransmits    = errors.New("rdpudp: data retransmit limit reached")
	ErrClock          = errors.New("rdpudp: clock moved backwards")
)

// Available returns the number of source slots available to Queue.
func (e *Endpoint) Available() int {
	if e == nil || !e.ready || e.closed {
		return 0
	}
	return e.c.QueuePackets - len(e.queue) - len(e.tx)
}

// EndpointConfig sets local resource/transport policy, not wire capabilities.
type EndpointConfig struct {
	QueuePackets int // zero defaults to 1024; includes sent but unretired sources
	Retransmits  int // reliable mode only; zero defaults to 5; 3..5
	FECGroup     int // zero disables parity generation; otherwise 2..32 sources
	// ReorderTimeout is only for UDP-L. Zero defaults to 200ms; 10ms..2s.
	ReorderTimeout time.Duration
}

type sentSource struct {
	seq     uint32
	payload []byte
	sent    time.Time
	due     time.Time
	rto     time.Duration
	retries int
	acked   bool
	fast    bool // fast retransmit is used once; timer handles further loss
	fastDue bool
	expired bool // UDP-L: release congestion flight credit, never retransmit
	lost    bool // UDP-L: three distinct higher source ACKs declared this lost
}

type fecKey struct {
	first uint32
	count byte // Range, not number of sources
}

// Endpoint is a deterministic v1/v2 RDP-UDP-R or RDP-UDP-L engine after initialization.
// Calls MUST be serialized. It owns no socket, goroutine, TLS, or RDP session.
// Feed only packets from the selected peer. UDP data is unauthenticated until
// the higher-layer TLS/DTLS and RDP tunnel binding succeed. Version3 is not
// supported here. Retain Initializer separately to answer duplicate SYN+ACKs.
//
// Queue copies stream bytes and splits them into source chunks. Call Next until
// nil, write each returned datagram exactly once, and service Deadline. A write
// error/cancellation must Close the engine. Read drains ordered chunks; joining
// them reconstructs the byte stream. Queue, Read and Next never expose retained
// buffers. In UDP-L each Queue is exactly one datagram, and Read returns an
// ordered subsequence of those datagrams; skipped/late data is never delivered.
// The zero value cannot send or receive.
type Endpoint struct {
	ready, closed bool
	p             Parameters
	c             EndpointConfig
	last          time.Time
	lastReceive   time.Time
	lastSend      time.Time
	sendReady     time.Time
	queue         [][]byte
	tx            []sentSource
	txCum         uint32
	txLast        uint32
	coded         uint32
	peerHigh      uint32
	peerCum       uint32
	peerRight     uint32
	peerACK       bool
	cwnd          float64
	threshold     float64
	rtt           time.Duration
	reduced       time.Time
	cwr           bool
	cwrSent       bool
	lastCWR       uint32
	rxRead        uint32
	rxCum         uint32
	rxHigh        uint32
	rxReset       uint32
	rxSkipTo      uint32 // UDP-L: any absent source at/below this point was skipped
	reorderDue    time.Time
	rx            map[uint32][]byte // unread packets plus 255 consumed FEC sources
	codedBase     uint32
	codedSeen     map[uint32]bool
	cn            bool
	ackPending    bool
	ackSince      time.Time
	fec           map[fecKey][]FECBlock
	fecBuild      [][]byte
	fecFirst      uint32
	fecPending    []FECBlock
	parityFlight  []time.Time
	stats         EndpointStats
}

// EndpointStats contains only counters/transport measurements, never payloads.
type EndpointStats struct {
	SourcesSent, SourcesReceived, Retransmitted, FastRetransmitted uint64
	ParitySent, ParityReceived, Recovered, Duplicates, Discarded   uint64
	Acknowledged, CongestionEvents, Keepalives                     uint64
	Queued, InFlight, Buffered, FECGroups                          int
	CongestionWindow, PeerWindow                                   int
	RTT, RTO                                                       time.Duration
	Closed                                                         bool
	// UDP-L counters are separate from ACKs, which can cover consumed/lost
	// prefixes and therefore do not prove application delivery in lossy mode.
	SendExpired, SendLost, ReceiveSkipped uint64
}

func NewEndpoint(p Parameters, c EndpointConfig, now time.Time) (*Endpoint, error) {
	if c.QueuePackets == 0 {
		c.QueuePackets = MaxQueuedPackets
	}
	if c.Retransmits == 0 {
		c.Retransmits = 5
	}
	if p.Lossy && c.ReorderTimeout == 0 {
		c.ReorderTimeout = 200 * time.Millisecond
	}
	if p.Version != Version1 && p.Version != Version2 || p.LocalWindow == 0 || p.LocalWindow > MaxWindowPackets || p.RemoteWindow == 0 || !mtuOK(p.SendMTU) || !mtuOK(p.ReceiveMTU) || c.QueuePackets < 1 || c.QueuePackets > MaxQueuedPackets || c.Retransmits < 3 || c.Retransmits > 5 || c.FECGroup != 0 && (c.FECGroup < 2 || c.FECGroup > MaxFECBlocks) || p.Lossy && (c.ReorderTimeout < 10*time.Millisecond || c.ReorderTimeout > 2*time.Second) || !p.Lossy && c.ReorderTimeout != 0 {
		return nil, ErrInvalid
	}
	return &Endpoint{
		ready: true, p: p, c: c, last: now, lastReceive: now, lastSend: now, sendReady: now,
		txCum: p.LocalInitialSequence, txLast: p.LocalInitialSequence, coded: p.LocalInitialSequence,
		peerHigh: p.LocalInitialSequence, peerCum: p.LocalInitialSequence, peerRight: p.LocalInitialSequence + uint32(p.RemoteWindow),
		cwnd: 2, threshold: float64(p.RemoteWindow),
		rxRead: p.RemoteInitialSequence, rxCum: p.RemoteInitialSequence, rxHigh: p.RemoteInitialSequence, rxReset: p.RemoteInitialSequence, rxSkipTo: p.RemoteInitialSequence,
		rx: make(map[uint32][]byte), codedBase: p.RemoteInitialSequence, codedSeen: make(map[uint32]bool), fec: make(map[fecKey][]FECBlock),
	}, nil
}

func (e *Endpoint) String() string   { return "rdpudp.Endpoint{private transport state}" }
func (e *Endpoint) GoString() string { return e.String() }

func (e *Endpoint) status() error {
	if e.closed {
		return ErrEndpointClosed
	}
	if !e.ready {
		return ErrInvalid
	}
	return nil
}

func (e *Endpoint) checkTime(now time.Time) error {
	if err := e.status(); err != nil {
		return err
	}
	if now.Before(e.last) {
		return ErrClock
	}
	if !now.Before(e.lastReceive.Add(idleTimeout)) {
		e.Close()
		return ErrDataTimeout
	}
	return nil
}

// PayloadLimit reserves two FEC prefix bytes in reliable mode and whenever
// parity generation is enabled. UDP-L without parity can use the full MTU.
// The peer may send ordinary sources up to ReceiveMTU. ACK/header overhead is
// separate from the negotiated payload.
func (e *Endpoint) PayloadLimit() int {
	if !e.ready || e.closed {
		return 0
	}
	if e.p.Lossy && e.c.FECGroup == 0 {
		return int(e.p.SendMTU)
	}
	return int(e.p.SendMTU) - 2
}

// Queue is atomic: on ErrLimit no bytes were retained. Backpressure is in
// source chunks, so retained application data is bounded by 1024*MaxMTU bytes.
func (e *Endpoint) Queue(data []byte) error {
	if err := e.status(); err != nil {
		return err
	}
	n := e.PayloadLimit()
	available := e.c.QueuePackets - len(e.queue) - len(e.tx)
	if e.p.Lossy {
		if len(data) == 0 {
			return ErrInvalid
		}
		if len(data) > n || available == 0 {
			return ErrLimit
		}
		e.queue = append(e.queue, append([]byte(nil), data...))
		return nil
	}
	if len(data) > available*n {
		return ErrLimit
	}
	for len(data) > 0 {
		count := min(n, len(data))
		e.queue = append(e.queue, append([]byte(nil), data[:count]...))
		data = data[count:]
	}
	return nil
}

// Read returns nil when the next chunk has not arrived. Reading one chunk
// reopens one position in the receive window and schedules an updated ACK.
// UDP-L also retires already abandoned gaps before the next readable chunk.
func (e *Endpoint) Read() ([]byte, error) {
	if err := e.status(); err != nil {
		return nil, err
	}
	if e.rxRead == e.rxCum {
		return nil, nil
	}
	e.rxRead++
	b := append([]byte(nil), e.rx[e.rxRead]...)
	delete(e.rx, e.rxRead-MaxFECSources)
	e.skipLeadingLoss()
	for k := range e.fec {
		if serialLE(k.first+uint32(k.count), e.rxRead) {
			delete(e.fec, k)
		}
	}
	e.scheduleACK(e.last)
	return b, nil
}

func serialLE(a, b uint32) bool { c, ok := SequenceCompare(a, b); return ok && c <= 0 }
func serialLT(a, b uint32) bool { c, ok := SequenceCompare(a, b); return ok && c < 0 }

func (e *Endpoint) scheduleACK(now time.Time) {
	if !e.ackPending {
		e.ackSince = now
	}
	e.ackPending = true
}

func (e *Endpoint) baseRTO() time.Duration {
	minimum := 300 * time.Millisecond
	if e.p.Version == Version1 {
		minimum = 500 * time.Millisecond
	}
	return min(120*time.Second, max(minimum, 2*e.rtt))
}

func (e *Endpoint) roundTrip() time.Duration {
	if e.rtt > 0 {
		return e.rtt
	}
	return 100 * time.Millisecond
}

func (e *Endpoint) delayedACK() time.Duration {
	if e.p.Version == Version1 {
		return 200 * time.Millisecond
	}
	return min(200*time.Millisecond, max(50*time.Millisecond, e.rtt/2))
}

func (e *Endpoint) inFlight(now time.Time) int {
	n := 0
	for _, s := range e.tx {
		if !s.acked && !s.lost && (!e.p.Lossy || !s.expired) {
			n++
		}
	}
	for _, until := range e.parityFlight {
		if now.Before(until) {
			n++
		}
	}
	return n
}

func (e *Endpoint) Stats() EndpointStats {
	s := e.stats
	s.Queued, s.InFlight, s.FECGroups = len(e.queue), e.inFlight(e.last), len(e.fec)
	for seq := range e.rx {
		if serialLT(e.rxRead, seq) {
			s.Buffered++
		}
	}
	s.CongestionWindow = int(e.cwnd)
	if serialLT(e.txCum, e.peerRight) {
		s.PeerWindow = int(e.peerRight - e.txCum)
	}
	s.RTT, s.RTO, s.Closed = e.rtt, e.baseRTO(), e.closed
	return s
}

// Close permanently stops the engine and releases all retained data. It is
// idempotent. Counters remain available, but no application bytes can be read.
func (e *Endpoint) Close() {
	e.closed = true
	e.queue, e.tx, e.rx, e.fec = nil, nil, nil, nil
	e.fecBuild, e.fecPending, e.parityFlight, e.codedSeen = nil, nil, nil, nil
	e.ackPending = false
}

// clone makes Receive transactional. Payload slices are immutable and shared;
// map/slice membership and sent-packet state are independently owned.
func (e *Endpoint) clone() Endpoint {
	n := *e
	if e.tx != nil {
		n.tx = make([]sentSource, len(e.tx))
		copy(n.tx, e.tx)
	}
	n.rx = make(map[uint32][]byte, len(e.rx))
	for k, v := range e.rx {
		n.rx[k] = v
	}
	n.codedSeen = make(map[uint32]bool, len(e.codedSeen))
	for k, v := range e.codedSeen {
		n.codedSeen[k] = v
	}
	n.fec = make(map[fecKey][]FECBlock, len(e.fec))
	for k, v := range e.fec {
		n.fec[k] = append([]FECBlock(nil), v...)
	}
	return n
}
