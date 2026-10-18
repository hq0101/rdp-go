package rdpudp

import "time"

func (e *Endpoint) ackPacket(now time.Time) Packet {
	floor := e.rxRead
	if serialLT(floor, e.rxReset) {
		floor = e.rxReset
	}
	if e.p.Lossy && serialLT(floor, e.rxSkipTo) {
		floor = e.rxSkipTo
	}
	states := make([]bool, int(e.rxHigh-floor)) // <= LocalWindow
	for i := range states {
		_, states[i] = e.rx[e.rxHigh-uint32(i)]
	}
	vector, _ := EncodeACK(states) // local window <= 1024, below wire limit
	p := Packet{SourceAck: e.rxHigh, ReceiveWindow: e.p.LocalWindow - uint16(e.rxCum-e.rxRead), Flags: FlagACK | FlagAckOfAcks, AckVector: vector, AckOfAcks: e.txCum}
	if e.cn {
		p.Flags |= FlagCN
	}
	if e.ackPending && !now.Before(e.ackSince.Add(e.delayedACK())) {
		p.Flags |= FlagAckDelayed
	}
	return p
}

func (e *Endpoint) inPeerWindow(seq uint32) bool {
	return serialLT(e.txCum, seq) && serialLE(seq, e.peerRight)
}

func (e *Endpoint) allAcked(b FECBlock) bool {
	for i := uint32(0); i <= uint32(b.Range); i++ {
		seq := b.First + i
		if serialLE(seq, e.txCum) {
			continue
		}
		idx := int(seq - e.txCum - 1)
		if idx >= len(e.tx) || !e.tx[idx].acked && !e.tx[idx].lost {
			return false
		}
	}
	return true
}

func (e *Endpoint) congestion(now time.Time, timeout bool) {
	e.cwr = true
	if e.stats.CongestionEvents != 0 && now.Before(e.reduced.Add(e.roundTrip())) {
		return
	}
	e.reduced = now
	e.stats.CongestionEvents++
	e.threshold = max(2, e.cwnd/2)
	e.cwnd = max(1, e.cwnd/2) // a loss must not grow a one-packet window
	if timeout {
		e.cwnd = 1
	}
}

// Next emits at most one datagram. Data/parity transmissions are paced and
// congestion-window limited; timer/fast retransmissions are paced as well.
// ACKs are scheduled immediately and piggybacked where possible, with a delayed
// flag if the caller did not service them before the protocol's ACK deadline.
func (e *Endpoint) Next(now time.Time) ([]byte, error) {
	if err := e.checkTime(now); err != nil {
		return nil, err
	}
	e.last = now
	e.expireLossy(now)
	// Retire expired parity flight slots and no-longer-useful queued parity.
	flight := e.parityFlight[:0]
	for _, until := range e.parityFlight {
		if now.Before(until) {
			flight = append(flight, until)
		}
	}
	e.parityFlight = flight
	pending := e.fecPending[:0]
	for _, b := range e.fecPending {
		if !e.allAcked(b) {
			pending = append(pending, b)
		}
	}
	clear(e.fecPending[len(pending):])
	e.fecPending = pending

	p := e.ackPacket(now)
	source := -1
	retransmit := false
	parity := false
	if !now.Before(e.sendReady) {
		for i := range e.tx {
			s := &e.tx[i]
			if e.p.Lossy || s.acked || !e.inPeerWindow(s.seq) || !s.fastDue && now.Before(s.due) {
				continue
			}
			if s.retries == e.c.Retransmits {
				e.Close()
				return nil, ErrRetransmits
			}
			source, retransmit = i, true
			break
		}
		if source < 0 && e.inFlight(now) < int(e.cwnd) {
			if len(e.fecPending) > 0 {
				parity = true
			} else if len(e.queue) > 0 && e.inPeerWindow(e.txLast+1) {
				e.txLast++
				e.tx = append(e.tx, sentSource{seq: e.txLast, payload: e.queue[0]})
				e.queue[0] = nil
				e.queue = e.queue[1:]
				source = len(e.tx) - 1
			}
		}
	}
	if source >= 0 {
		s := &e.tx[source]
		if retransmit {
			timer := !now.Before(s.due)
			e.congestion(now, timer)
			s.retries++
			s.rto = min(120*time.Second, max(e.baseRTO(), s.rto*2))
			e.stats.Retransmitted++
			if s.fastDue && !timer {
				e.stats.FastRetransmitted++
			}
			s.fastDue = false
		} else {
			s.rto = e.baseRTO()
			e.stats.SourcesSent++
		}
		s.sent, s.due = now, now.Add(s.rto)
		e.coded++
		p.Flags |= FlagData
		p.Source = Source{CodedSequence: e.coded, SourceSequence: s.seq}
		p.Payload = s.payload
		if e.cwr {
			p.Flags |= FlagCWR
			e.cwr, e.cwrSent, e.lastCWR = false, true, s.seq
		}
		if !retransmit && e.c.FECGroup > 0 {
			if len(e.fecBuild) == 0 {
				e.fecFirst = s.seq
			}
			e.fecBuild = append(e.fecBuild, s.payload)
			if len(e.fecBuild) == e.c.FECGroup {
				// Sources are already bounded/nonempty; this encoding cannot fail.
				b, _ := EncodeFEC(e.fecFirst, byte(e.fecFirst-1), e.fecBuild)
				if len(e.fecPending) < MaxQueuedPackets/2 {
					e.fecPending = append(e.fecPending, b)
				}
				e.fecBuild = nil
			}
		}
	} else if parity {
		b := e.fecPending[0]
		e.fecPending[0] = FECBlock{}
		e.fecPending = e.fecPending[1:]
		e.coded++
		p.Flags |= FlagData | FlagFEC
		p.Source = Source{CodedSequence: e.coded, SourceSequence: b.First, Range: b.Range, FECIndex: b.Index}
		p.Payload = b.Payload
		e.parityFlight = append(e.parityFlight, now.Add(e.roundTrip()))
		e.stats.ParitySent++
	} else if !e.ackPending && now.Before(e.lastSend.Add(keepalivePeriod)) {
		return nil, nil
	} else if !e.ackPending {
		e.stats.Keepalives++
	}
	if p.Flags&FlagData != 0 {
		e.sendReady = now.Add(max(time.Millisecond, time.Duration(float64(e.roundTrip())/e.cwnd)))
	}
	b, err := p.Marshal()
	if err != nil {
		// An internal invariant failure must not leave a partially sent stream.
		e.Close()
		return nil, err
	}
	e.lastSend, e.ackPending = now, false
	return b, nil
}

// Deadline returns the next time at which Next needs service. A zero value
// means closed/uninitialized. It includes idle expiry even when flow blocked.
func (e *Endpoint) Deadline() time.Time {
	if !e.ready || e.closed {
		return time.Time{}
	}
	d := e.lastReceive.Add(idleTimeout)
	consider := func(t time.Time) {
		if t.Before(e.last) {
			t = e.last
		}
		if t.Before(d) {
			d = t
		}
	}
	consider(e.lastSend.Add(keepalivePeriod))
	if e.ackPending {
		consider(e.last)
	}
	if e.p.Lossy && !e.reorderDue.IsZero() {
		consider(e.reorderDue)
	}
	for _, s := range e.tx {
		if e.p.Lossy {
			if !s.acked && !s.lost && !s.expired {
				consider(s.due)
			}
			continue
		}
		if s.acked || !e.inPeerWindow(s.seq) {
			continue
		}
		t := s.due
		if s.fastDue {
			t = e.last
		}
		if t.Before(e.sendReady) {
			t = e.sendReady
		}
		consider(t)
	}
	haveParity := false
	for _, b := range e.fecPending {
		if !e.allAcked(b) {
			haveParity = true
			break
		}
	}
	canNew := haveParity || len(e.queue) > 0 && e.inPeerWindow(e.txLast+1)
	if canNew {
		if e.inFlight(e.last) < int(e.cwnd) {
			consider(e.sendReady)
		} else {
			for _, t := range e.parityFlight {
				if t.After(e.last) {
					consider(t)
				}
			}
		}
	}
	return d
}
