package rdpudp2

import (
	"bytes"
	"math"
	"sort"
	"time"
)

const (
	MaxWindowPackets = 512
	MaxQueuePackets  = 1024
	keepalive        = 4 * time.Second
	idleTimeout      = 16 * time.Second
)

// Config initializes an isolated data-phase endpoint. The full first coded and
// channel numbers must agree with the owning initialization/transition layer;
// zero defaults to one for standalone tests. This does not infer them from an
// RDP-UDP SYN. Window sizes are log2 packet counts, with one slot reserved.
// The local bounded implementation supports log windows 1..9 (default 9).
type Config struct {
	LocalFirstCoded, RemoteFirstCoded     uint64
	LocalFirstChannel, RemoteFirstChannel uint64
	LogWindow                             byte
	RemoteLogWindow                       byte          // zero defaults to 9; later wire zero means stop new data
	MTU                                   int           // full network datagram, 1132..1232, default 1232
	ReceiveMTU                            int           // DataBody limit including channel sequence; zero uses MTU
	InitialRTT                            time.Duration // zero assumes 100ms for initial delayed ACKs
	QueuePackets                          int           // default 1024
	Retransmits                           int           // default 5, range 3..5
}

type Stats struct {
	SourcesSent, SourcesReceived                                              uint64 // unique application sources, excluding retransmits and Dummy packets
	Sent, Received, Retransmitted, Acknowledged, Duplicates, Dummy, Delivered uint64
	Queued, Pending, Buffered                                                 int
	ReceiveWindow                                                             int    // configured packet capacity, not currently advertised free space
	PeakBuffered                                                              int    // retained application packets, including unread in-order data
	PeakReceiptSpan                                                           uint64 // largest coded gap span retained after a valid receive
	CongestionWindow                                                          float64
	RoundTrip, RetransmitTimeout                                              time.Duration
	Closed                                                                    bool
}

type source struct {
	data     []byte
	coded    uint64
	sent     time.Time
	attempts int
	retry    bool
}

// Endpoint is a deterministic single-caller reliable UDP2 engine. It opens no
// sockets or goroutines. Drive Next at Deadline and feed only the chosen peer's
// packets to Receive. Queue copies application bytes; Read transfers ownership.
// A malformed packet commits no ACK, window, timer or payload changes. These
// checks are resource/consistency checks, not peer authentication or integrity.
type Endpoint struct {
	c                                                Config
	last, lastRX, lastTX, nextSend, ackDue, lastLoss time.Time
	txNext, channelNext, rxBase, rxHigh, readNext    uint64
	rxTime                                           time.Time
	remoteLog                                        byte
	queue                                            [][]byte
	sources                                          map[uint64]source
	pending                                          map[uint64]uint64 // current coded number -> channel number
	received                                         map[uint64]bool   // coded receipt ledger, independent of stream buffer
	buffer                                           map[uint64][]byte
	ackCount                                         int
	peerDelay                                        DelayACK
	announce                                         bool
	windowNotice                                     bool
	lastAdvertised                                   byte
	cwnd                                             float64
	srtt, rto                                        time.Duration
	stats                                            Stats
	closed                                           bool
}

func NewEndpoint(c Config, now time.Time) (*Endpoint, error) {
	if c.LocalFirstCoded == 0 {
		c.LocalFirstCoded = 1
	}
	if c.RemoteFirstCoded == 0 {
		c.RemoteFirstCoded = 1
	}
	if c.LocalFirstChannel == 0 {
		c.LocalFirstChannel = 1
	}
	if c.RemoteFirstChannel == 0 {
		c.RemoteFirstChannel = 1
	}
	if c.LogWindow == 0 {
		c.LogWindow = 9
	}
	if c.RemoteLogWindow == 0 {
		c.RemoteLogWindow = 9
	}
	if c.MTU == 0 {
		c.MTU = MaxMTU
	}
	if c.ReceiveMTU == 0 {
		c.ReceiveMTU = c.MTU
	}
	if c.ReceiveMTU < 1132 || c.ReceiveMTU > MaxMTU || c.InitialRTT < 0 || c.InitialRTT > 10*time.Second {
		return nil, ErrInvalid
	}
	if c.QueuePackets == 0 {
		c.QueuePackets = MaxQueuePackets
	}
	if c.Retransmits == 0 {
		c.Retransmits = 5
	}
	if now.IsZero() || c.LogWindow > 9 || c.RemoteLogWindow > 15 || c.MTU < 1132 || c.MTU > MaxMTU || c.QueuePackets < 1 || c.QueuePackets > MaxQueuePackets || c.Retransmits < 3 || c.Retransmits > 5 || uint16(c.LocalFirstChannel) == 0 || uint16(c.RemoteFirstChannel) == 0 || c.LocalFirstCoded == math.MaxUint64 || c.RemoteFirstCoded == math.MaxUint64 || c.LocalFirstChannel == math.MaxUint64 || c.RemoteFirstChannel == math.MaxUint64 {
		return nil, ErrInvalid
	}
	ackRTT := c.InitialRTT
	if ackRTT == 0 {
		ackRTT = 100 * time.Millisecond
	}
	return &Endpoint{c: c, last: now, lastRX: now, lastTX: now, txNext: c.LocalFirstCoded, channelNext: c.LocalFirstChannel, rxBase: c.RemoteFirstCoded, rxHigh: c.RemoteFirstCoded - 1, readNext: c.RemoteFirstChannel, remoteLog: c.RemoteLogWindow, sources: make(map[uint64]source), pending: make(map[uint64]uint64), received: make(map[uint64]bool), buffer: make(map[uint64][]byte), peerDelay: DelayACK{8, uint16(ackRTT / (2 * time.Millisecond))}, announce: true, cwnd: 2, srtt: c.InitialRTT, rto: min(3*time.Second, max(300*time.Millisecond, 2*c.InitialRTT))}, nil
}

func (e *Endpoint) String() string   { return "rdpudp2.Endpoint{private transport state}" }
func (e *Endpoint) GoString() string { return e.String() }
func (e *Endpoint) valid() bool      { return e != nil && e.sources != nil && !e.closed }
func (e *Endpoint) PayloadLimit() int {
	if !e.valid() {
		return 0
	}
	return e.c.MTU - 9
}
func (e *Endpoint) Available() int {
	if !e.valid() {
		return 0
	}
	return e.c.QueuePackets - len(e.queue) - len(e.sources)
}
func (e *Endpoint) Stats() Stats {
	if e == nil {
		return Stats{Closed: true}
	}
	s := e.stats
	if e.c.LogWindow > 0 {
		s.ReceiveWindow = 1 << e.c.LogWindow
	}
	s.Queued = len(e.queue)
	s.Pending = len(e.sources)
	s.Buffered = len(e.buffer)
	s.CongestionWindow = e.cwnd
	s.RoundTrip = e.srtt
	s.RetransmitTimeout = e.rto
	s.Closed = !e.valid()
	return s
}
func (e *Endpoint) Close() {
	if e != nil {
		e.closed = true
		e.sources = nil
		e.pending = nil
		e.received = nil
		e.buffer = nil
		e.queue = nil
	}
}

// Queue atomically accepts and fragments a stream write, or changes nothing.
func (e *Endpoint) Queue(data []byte) error {
	if !e.valid() {
		return ErrClosed
	}
	if len(data) == 0 {
		return nil
	}
	limit := e.PayloadLimit()
	if len(data) > e.Available()*limit {
		return ErrLimit
	}
	for len(data) > 0 {
		n := min(limit, len(data))
		e.queue = append(e.queue, append([]byte(nil), data[:n]...))
		data = data[n:]
	}
	return nil
}

func (e *Endpoint) Read() ([]byte, error) {
	if !e.valid() {
		return nil, ErrClosed
	}
	b, ok := e.buffer[e.readNext]
	if !ok {
		return nil, nil
	}
	next, err := NextChannel(e.readNext)
	if err != nil {
		return nil, err
	}
	delete(e.buffer, e.readNext)
	e.readNext = next
	e.stats.Delivered++
	e.windowNotice = e.advertisedWindow() != e.lastAdvertised
	return b, nil
}

// Advertise the largest power-of-two window whose active span fits the free
// stream buffer. An out-of-order gap retains one slot for its retransmission.
// Read triggers a window update; keepalives recover a lost update.
func (e *Endpoint) advertisedWindow() byte {
	free := (1 << e.c.LogWindow) - len(e.buffer)
	var log byte
	for log < e.c.LogWindow && (1<<(log+1))-1 <= free {
		log++
	}
	return log
}

func (e *Endpoint) checkTime(now time.Time) error {
	if !e.valid() {
		return ErrClosed
	}
	if now.Before(e.last) {
		return ErrState
	}
	return nil
}

func (e *Endpoint) clone() *Endpoint {
	n := *e
	n.sources = make(map[uint64]source, len(e.sources))
	for k, v := range e.sources {
		n.sources[k] = v
	}
	n.pending = make(map[uint64]uint64, len(e.pending))
	for k, v := range e.pending {
		n.pending[k] = v
	}
	n.received = make(map[uint64]bool, len(e.received))
	for k, v := range e.received {
		n.received[k] = v
	}
	n.buffer = make(map[uint64][]byte, len(e.buffer))
	for k, v := range e.buffer {
		n.buffer[k] = v
	}
	return &n // payload slices are immutable until ownership passes through Read
}

func (e *Endpoint) Receive(datagram []byte, now time.Time) error {
	if err := e.checkTime(now); err != nil {
		return err
	}
	p, err := Parse(datagram)
	if err != nil {
		return reject("packet", err)
	}
	if p.Flags&FlagData != 0 && len(p.Data)+2 > e.c.ReceiveMTU {
		return reject("payload-size", ErrLimit)
	}
	n := e.clone()
	if err = n.receive(p, now); err != nil {
		return err
	}
	if !now.Before(e.lastRX.Add(idleTimeout)) {
		e.Close()
		return ErrTimeout
	}
	n.last = now
	n.lastRX = now
	n.stats.Received++
	n.stats.PeakBuffered = max(n.stats.PeakBuffered, len(n.buffer))
	if n.rxBase <= n.rxHigh {
		n.stats.PeakReceiptSpan = max(n.stats.PeakReceiptSpan, n.rxHigh-n.rxBase+1)
	}
	*e = *n
	return nil
}

func (e *Endpoint) receive(p Packet, now time.Time) error {
	if p.Flags&FlagDelayACK != 0 {
		e.peerDelay = p.DelayACK
		e.peerDelay.MaxDelayed = min(e.peerDelay.MaxDelayed, 15)
	}
	if p.Flags&(FlagACK|FlagACKVector) != 0 {
		if err := e.applyACK(p, now); err != nil {
			return reject("ack", err)
		}
	}
	if p.Flags&FlagAckOfAcks != 0 {
		a, err := ExpandSequence(p.AckOfAcks, e.rxHigh)
		if err != nil {
			return reject("ack-of-acks", err)
		}
		if a > e.rxHigh && a-e.rxHigh > uint64(1<<e.c.LogWindow) {
			return reject("ack-of-acks", ErrInvalid)
		}
		if a > e.rxBase {
			e.rxBase = a
			for seq := range e.received {
				if seq < a {
					delete(e.received, seq)
				}
			}
			if a > e.rxHigh {
				e.rxHigh = a - 1
				e.rxTime = time.Time{} // skipped packets have no receipt timestamp
			}
			e.advanceReceipt()
		}
	}
	if p.Flags&FlagData != 0 {
		seq, err := ExpandSequence(p.DataSequence, e.rxHigh)
		if err != nil {
			return reject("data-sequence", err)
		}
		if seq >= e.rxBase && seq-e.rxBase >= uint64(1<<e.c.LogWindow)-1 {
			return reject("data-window", ErrLimit)
		}
		if seq == math.MaxUint64 {
			return reject("data-sequence", ErrLimit)
		}
		if !p.Dummy {
			if p.ChannelSequence == 0 || len(p.Data) == 0 {
				return reject("channel-data", ErrInvalid)
			}
			channel, err := ExpandSequence(p.ChannelSequence, e.readNext)
			if err != nil {
				return reject("channel-sequence", err)
			}
			if channel >= e.readNext {
				// Reserve the missing head's slot even when all later data arrives.
				if channel-e.readNext >= uint64(1<<e.c.LogWindow) {
					return reject("channel-window", ErrLimit)
				}
				if old, ok := e.buffer[channel]; ok {
					if !bytes.Equal(old, p.Data) {
						return reject("channel-data", ErrInvalid)
					}
					e.stats.Duplicates++
				} else {
					if len(e.buffer) >= 1<<e.c.LogWindow {
						return reject("channel-data", ErrLimit)
					}
					e.buffer[channel] = p.Data
					e.stats.SourcesReceived++
				}
			} else {
				e.stats.Duplicates++
			}
		} else {
			e.stats.Dummy++
		}
		gapBefore := e.rxBase <= e.rxHigh
		if seq > e.rxHigh {
			e.rxHigh = seq
			e.rxTime = now
		}
		if seq >= e.rxBase {
			e.received[seq] = true
		}
		e.advanceReceipt()
		e.ackCount++
		due := now.Add(time.Duration(e.peerDelay.TimeoutMS) * time.Millisecond)
		if gapBefore || e.rxBase <= e.rxHigh || e.ackCount >= max(1, int(e.peerDelay.MaxDelayed)) {
			due = now
		}
		if e.ackDue.IsZero() || due.Before(e.ackDue) {
			e.ackDue = due
		}
	}
	e.remoteLog = p.LogWindow
	return nil
}

func (e *Endpoint) advanceReceipt() {
	for e.received[e.rxBase] {
		delete(e.received, e.rxBase)
		e.rxBase++
	}
}

func (e *Endpoint) applyACK(p Packet, now time.Time) error {
	last := e.txNext - 1
	var base, high uint64
	var states []bool
	var gap byte = 255
	if p.Flags&FlagACK != 0 {
		var err error
		high, err = ExpandSequence(p.ACK.Sequence, last)
		if err != nil || high > last {
			return ErrInvalid
		}
		if high < 15 && len(p.ACK.Deltas) > int(high) {
			return ErrInvalid
		}
		base = high + 1
		gap = p.ACK.SendGap
	} else {
		var err error
		base, err = ExpandSequence(p.Vector.Base, last)
		if err != nil || base > e.txNext {
			return ErrInvalid
		}
		states, err = DecodeVector(p.Vector.Codes)
		if err != nil {
			return err
		}
		if base > math.MaxUint64-uint64(len(states)) {
			return ErrInvalid
		}
		if base > 0 {
			high = base - 1
		}
		for i, yes := range states {
			if yes {
				seq := base + uint64(i)
				if seq > last {
					return ErrInvalid
				}
				high = seq
			}
		}
		if p.Vector.TimestampPresent {
			gap = p.Vector.SendGap
		}
	}
	// Only current coded attempts are acknowledged. Old lost attempts have
	// already left this map, so an AOA-assisted cumulative ACK cannot delete a
	// channel still awaiting retransmission.
	for seq, channel := range e.pending {
		yes := seq < base
		if seq >= base && seq-base < uint64(len(states)) {
			yes = states[seq-base]
		}
		if !yes {
			continue
		}
		s := e.sources[channel]
		if seq == high && s.attempts == 1 && gap != 255 {
			sample := now.Sub(s.sent) - time.Duration(gap)*time.Millisecond
			if sample > 0 && sample < idleTimeout {
				if e.srtt == 0 {
					e.srtt = sample
				} else {
					e.srtt = (7*e.srtt + sample) / 8
				}
				e.rto = min(3*time.Second, max(300*time.Millisecond, 2*e.srtt))
			}
		}
		delete(e.pending, seq)
		delete(e.sources, channel)
		e.stats.Acknowledged++
		e.cwnd = min(float64(MaxWindowPackets-1), e.cwnd+1/e.cwnd)
	}
	if high >= 3 {
		e.loseThrough(high-3, now)
	}
	return nil
}

func (e *Endpoint) loseThrough(seq uint64, now time.Time) {
	lost := false
	for coded, channel := range e.pending {
		if coded > seq {
			continue
		}
		s := e.sources[channel]
		s.retry = true
		e.sources[channel] = s
		delete(e.pending, coded)
		lost = true
	}
	if lost && (e.lastLoss.IsZero() || now.Sub(e.lastLoss) >= max(100*time.Millisecond, e.srtt)) {
		e.cwnd = max(1, e.cwnd/2)
		e.lastLoss = now
	}
}

func (e *Endpoint) retryTime(s source) time.Time {
	d := e.rto
	for i := 1; i < s.attempts; i++ {
		d = min(3*time.Second, 2*d)
	}
	return s.sent.Add(d)
}
func (e *Endpoint) windowRoom() bool {
	w := min(uint64(MaxWindowPackets-1), uint64(1<<e.remoteLog)-1)
	if w == 0 || len(e.pending) >= int(e.cwnd) {
		return false
	}
	low := e.txNext
	for seq := range e.pending {
		low = min(low, seq)
	}
	return e.txNext-low < w
}
func (e *Endpoint) hasRetry() bool {
	for _, s := range e.sources {
		if s.retry {
			return true
		}
	}
	return false
}
func (e *Endpoint) canSend() bool { return e.windowRoom() && (len(e.queue) > 0 || e.hasRetry()) }

func (e *Endpoint) Deadline() time.Time {
	if !e.valid() {
		return time.Time{}
	}
	d := minTime(e.lastRX.Add(idleTimeout), e.lastTX.Add(keepalive))
	if e.announce || e.windowNotice {
		d = e.last
	}
	if !e.ackDue.IsZero() {
		d = minTime(d, e.ackDue)
	}
	for _, s := range e.sources {
		if !s.retry {
			d = minTime(d, e.retryTime(s))
		}
	}
	if e.canSend() {
		d = minTime(d, maxTime(e.last, e.nextSend))
	}
	return d
}

func (e *Endpoint) Next(now time.Time) ([]byte, error) {
	if err := e.checkTime(now); err != nil {
		return nil, err
	}
	if !now.Before(e.lastRX.Add(idleTimeout)) {
		e.Close()
		return nil, ErrTimeout
	}
	e.last = now
	var expired uint64
	for _, s := range e.sources {
		if !s.retry && !now.Before(e.retryTime(s)) {
			expired = max(expired, s.coded)
		}
	}
	if expired != 0 {
		e.loseThrough(expired, now)
	}
	if e.announce || e.windowNotice || !e.ackDue.IsZero() && !now.Before(e.ackDue) || !now.Before(e.lastTX.Add(keepalive)) {
		p, err := e.control(now)
		if err != nil {
			return nil, err
		}
		out, err := p.Marshal()
		if err != nil {
			return nil, err
		}
		e.announce = false
		e.windowNotice = false
		e.lastAdvertised = p.LogWindow
		e.ackDue = time.Time{}
		e.ackCount = 0
		e.lastTX = now
		e.stats.Sent++
		return out, nil
	}
	if !e.canSend() || now.Before(e.nextSend) {
		return nil, nil
	}
	if e.txNext == math.MaxUint64 {
		return nil, ErrLimit
	}
	keys := make([]uint64, 0, len(e.sources))
	for k, s := range e.sources {
		if s.retry {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	var channel uint64
	var s source
	fresh := len(keys) == 0
	if fresh {
		channel = e.channelNext
		s = source{data: e.queue[0]}
	} else {
		channel = keys[0]
		s = e.sources[channel]
	}
	if s.attempts > e.c.Retransmits {
		e.Close()
		return nil, ErrTimeout
	}
	nextChannel, err := NextChannel(channel)
	if err != nil {
		return nil, err
	}
	p := Packet{Flags: FlagData | FlagAckOfAcks, LogWindow: e.advertisedWindow(), AckOfAcks: uint16(e.lowestPending()), DataSequence: uint16(e.txNext), ChannelSequence: uint16(channel), Data: s.data}
	out, err := p.Marshal()
	if err != nil {
		return nil, err
	}
	if fresh {
		e.stats.SourcesSent++
		e.queue[0] = nil
		e.queue = e.queue[1:]
		e.channelNext = nextChannel
	} else {
		e.stats.Retransmitted++
	}
	s.coded = e.txNext
	s.sent = now
	s.attempts++
	s.retry = false
	e.sources[channel] = s
	e.pending[s.coded] = channel
	e.txNext++
	e.lastTX = now
	e.lastAdvertised = p.LogWindow
	e.stats.Sent++
	e.nextSend = now.Add(max(time.Millisecond, max(20*time.Millisecond, e.srtt)/time.Duration(max(1, int(e.cwnd)))))
	return out, nil
}

func (e *Endpoint) lowestPending() uint64 {
	n := e.txNext
	for seq := range e.pending {
		n = min(n, seq)
	}
	return n
}

func (e *Endpoint) control(now time.Time) (Packet, error) {
	p := Packet{Flags: FlagAckOfAcks, LogWindow: e.advertisedWindow(), AckOfAcks: uint16(e.lowestPending())}
	if e.announce {
		p.Flags |= FlagDelayACK
		p.DelayACK = DelayACK{8, 25}
	}
	stamp := uint32(uint64(e.rxTime.UnixMicro()/4) & 0xffffff)
	gap := byte(255)
	if !e.rxTime.IsZero() && now.Sub(e.rxTime) < 255*time.Millisecond {
		gap = byte(max(0, now.Sub(e.rxTime).Milliseconds()))
	}
	if e.rxBase <= e.rxHigh {
		states := make([]bool, int(e.rxHigh-e.rxBase+1))
		for i := range states {
			states[i] = e.received[e.rxBase+uint64(i)]
		}
		codes, err := EncodeVector(states)
		if err != nil {
			return Packet{}, err
		}
		p.Flags |= FlagACKVector
		p.Vector = ACKVector{Base: uint16(e.rxBase), Codes: codes, TimestampPresent: true, Timestamp: stamp, SendGap: gap}
	} else {
		p.Flags |= FlagACK
		p.ACK = ACK{Sequence: uint16(e.rxHigh), Timestamp: stamp, SendGap: gap}
	}
	return p, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
