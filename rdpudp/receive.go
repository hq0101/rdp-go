package rdpudp

import (
	"bytes"
	"errors"
	"time"
)

// Receive applies a complete chosen-peer datagram atomically. Invalid input
// returns an error without resetting timers or altering queued data. Outdated
// ACKs and out-of-window data are ignored; they do not close the connection.
// FEC recovery produces ordinary source ACKs, never an ACK for a parity packet.
func (e *Endpoint) Receive(datagram []byte, now time.Time) error {
	if err := e.checkTime(now); err != nil {
		return err
	}
	p, err := Parse(datagram)
	if err != nil {
		return err
	}
	if p.Flags&FlagSYN != 0 || len(p.Payload) > int(e.p.ReceiveMTU) {
		return ErrInvalid
	}
	if len(p.AckVector) > 0 && p.AckVector[0]>>6 != 0 {
		return ErrInvalid
	}
	if p.Flags&FlagAckOfAcks != 0 && !serialLE(p.AckOfAcks, e.rxCum) {
		return ErrInvalid
	}
	// Unknown/future/half-range ACKs do not keep an endpoint alive or change its
	// send window. Old ACKs can accompany useful opposite-direction data.
	if !serialLE(p.SourceAck, e.txLast) {
		return nil
	}
	n := e.clone()
	n.expireLossy(now)
	if err := n.applyACK(p, now); err != nil {
		return err
	}
	if p.Flags&FlagAckOfAcks != 0 && serialLT(n.rxReset, p.AckOfAcks) {
		n.rxReset = p.AckOfAcks
	}
	if p.Flags&FlagData != 0 {
		if p.Flags&FlagFEC != 0 {
			b := FECBlock{First: p.Source.SourceSequence, Range: p.Source.Range, Index: p.Source.FECIndex, Payload: p.Payload}
			if err := validateFEC(b); err != nil {
				return err
			}
		}
		if !n.receiveCoded(p.Source.CodedSequence, p.Flags&FlagCWR != 0) {
			n.stats.Discarded++
			if p.Flags&FlagFEC == 0 {
				n.scheduleACK(now)
			}
		} else if p.Flags&FlagFEC != 0 {
			if err := n.receiveParity(p, now); err != nil {
				return err
			}
		} else {
			if err := n.receiveSource(p.Source.SourceSequence, p.Payload, now, false); err != nil {
				return err
			}
			if err := n.recoverGroups(now, nil); err != nil {
				return err
			}
		}
	}
	if n.cn && !e.cn {
		// Congestion can be detected by coded FEC sequence gaps even when no
		// source was recovered. Notify it using the existing source ACK state;
		// do not acknowledge a parity packet as if it were a source packet.
		n.scheduleACK(now)
	}
	n.updateReorder(now)
	if n.p.Lossy && n.rxHigh-n.rxRead == uint32(n.p.LocalWindow) {
		n.skipLoss(now) // process out-of-order data at the receive window's edge
	}
	n.last, n.lastReceive = now, now
	*e = n
	return nil
}

func (e *Endpoint) applyACK(p Packet, now time.Time) error {
	if !serialLE(e.txCum, p.SourceAck) {
		return nil
	}
	ranges, _ := AckRanges(p.SourceAck, p.AckVector)
	span, _ := AckSpan(p.AckVector)
	// Positions older than the represented queue have been consumed/reset.
	// No represented position may retract a previously received source.
	ackCum := p.SourceAck
	receivedAbove := uint32(0)
	for _, r := range ranges {
		if r.Received {
			receivedAbove += r.Last - r.First + 1
		}
		if !r.Received && (!e.p.Lossy || receivedAbove < 3) {
			ackCum = r.First - 1
		}
	}
	newACKs := 0
	growthACKs := 0
	var sample time.Duration
	for i := range e.tx {
		s := &e.tx[i]
		if s.acked || s.lost || !serialLE(s.seq, p.SourceAck) {
			continue
		}
		distance := p.SourceAck - s.seq
		received := distance >= span
		if !received {
			for _, r := range ranges {
				if s.seq-r.First <= r.Last-r.First {
					received = r.Received
					break
				}
			}
		}
		if !received {
			continue
		}
		s.acked, s.payload, s.fastDue = true, nil, false
		newACKs++
		// In UDP-L, an implicit prefix can include abandoned packets. The
		// largest detected source itself was received, even with an empty
		// vector; other sources need an explicit received state for sampling.
		definite := !e.p.Lossy || (distance == 0 || distance < span) && !s.expired
		if definite {
			growthACKs++
		}
		if definite && s.retries == 0 && p.Flags&FlagAckDelayed == 0 && now.After(s.sent) {
			// One sample per ACK: newest newly acknowledged original transmission.
			sample = now.Sub(s.sent)
		}
	}
	if sample > 0 {
		if e.rtt == 0 {
			e.rtt = sample
		} else {
			e.rtt = (7*e.rtt + sample) / 8
		}
	}
	e.stats.Acknowledged += uint64(newACKs)
	for i := 0; i < growthACKs; i++ {
		if e.cwnd < e.threshold {
			e.cwnd++
		} else {
			e.cwnd += 1 / e.cwnd
		}
		e.cwnd = min(e.cwnd, float64(e.c.QueuePackets))
	}
	// Three DISTINCT higher acknowledged source positions, not three copies of
	// the same ACK, are necessary before fast retransmission is permitted.
	higher := 0
	for i := len(e.tx) - 1; i >= 0; i-- {
		s := &e.tx[i]
		if s.acked {
			higher++
		} else if !s.lost && higher >= 3 && !s.fast {
			if e.p.Lossy {
				s.lost, s.payload = true, nil
				e.stats.SendLost++
				e.congestion(now, false)
			} else {
				s.fast, s.fastDue = true, true
			}
		}
	}
	retired := 0
	for retired < len(e.tx) && (e.tx[retired].acked || e.tx[retired].lost) {
		e.txCum = e.tx[retired].seq
		retired++
	}
	clear(e.tx[:retired])
	e.tx = e.tx[retired:]
	// Couple advertised size to this ACK's own cumulative point, never to the
	// possibly newer locally remembered point. This prevents reordered ACKs
	// from accidentally extending the peer's right window edge.
	right := ackCum + uint32(p.ReceiveWindow)
	if !e.peerACK || serialLE(e.peerHigh, p.SourceAck) && serialLE(e.peerCum, ackCum) {
		if !e.peerACK || e.peerHigh != p.SourceAck || e.peerCum != ackCum || serialLT(e.peerRight, right) {
			e.peerHigh, e.peerCum, e.peerRight, e.peerACK = p.SourceAck, ackCum, right, true
		}
	}
	if p.Flags&FlagCN != 0 && (!e.cwrSent || serialLE(e.lastCWR, p.SourceAck)) {
		e.congestion(now, false)
	}
	return nil
}

func (e *Endpoint) receiveCoded(seq uint32, cwr bool) bool {
	distance := seq - e.codedBase
	if distance == 0 || int32(distance) < 0 && int32(distance) >= -maxCodedWindow || e.codedSeen[seq] {
		return true // late/duplicate source data can still fill a receive hole
	}
	if distance > maxCodedWindow {
		return false
	}
	if cwr {
		e.cn = false
	}
	e.codedSeen[seq] = true
	for {
		if e.codedSeen[e.codedBase+1] {
			e.codedBase++
			delete(e.codedSeen, e.codedBase)
			continue
		}
		if len(e.codedSeen) < 3 {
			break
		}
		// All gaps before the oldest of three distinct later datagrams are lost.
		nearest := uint32(maxCodedWindow)
		for s := range e.codedSeen {
			nearest = min(nearest, s-e.codedBase)
		}
		e.codedBase += nearest - 1
		e.cn = true
	}
	return true
}

func (e *Endpoint) receiveSource(seq uint32, data []byte, now time.Time, recovered bool) error {
	if old, ok := e.rx[seq]; ok {
		if !bytes.Equal(old, data) {
			return ErrInvalid
		}
		e.stats.Duplicates++
		e.scheduleACK(now)
		return nil
	}
	distance := seq - e.rxRead
	if distance == 0 || distance > uint32(e.p.LocalWindow) || e.p.Lossy && serialLE(seq, e.rxSkipTo) {
		e.stats.Discarded++
		e.scheduleACK(now) // re-advertise the cumulative state after a lost ACK
		return nil
	}
	e.rx[seq] = data // Parse/RecoverFEC already returned owned immutable bytes
	if serialLT(e.rxHigh, seq) {
		e.rxHigh = seq
	}
	for e.rx[e.rxCum+1] != nil {
		e.rxCum++
	}
	e.stats.SourcesReceived++
	if recovered {
		e.stats.Recovered++
	}
	e.scheduleACK(now)
	return nil
}

func (e *Endpoint) receiveParity(p Packet, now time.Time) error {
	b := FECBlock{First: p.Source.SourceSequence, Range: p.Source.Range, Index: p.Source.FECIndex, Payload: p.Payload}
	end := b.First + uint32(b.Range)
	// Retain at most 255 consumed source packets. An entirely consumed group or
	// a group reaching outside the current receive window is no longer useful.
	if int32(b.First-e.rxRead) < -(MaxFECSources-1) || !serialLT(e.rxRead, end) || end-e.rxRead > uint32(e.p.LocalWindow) {
		e.stats.Discarded++
		return nil
	}
	k := fecKey{b.First, b.Range}
	blocks := e.fec[k]
	for _, old := range blocks {
		if old.Index == b.Index {
			if !bytes.Equal(old.Payload, b.Payload) {
				return ErrInvalid
			}
			return nil
		}
		if len(old.Payload) != len(b.Payload) {
			return ErrInvalid
		}
	}
	if len(blocks) == MaxFECBlocks || len(blocks) == 0 && len(e.fec) == maxFECGroups {
		// FEC is optional: resource pressure must not break reliable delivery.
		e.stats.Discarded++
		return nil
	}
	e.fec[k] = append(blocks, b)
	e.stats.ParityReceived++
	return e.recoverGroups(now, &k)
}

func (e *Endpoint) recoverGroups(now time.Time, incoming *fecKey) error {
	// A recovered source may unlock another overlapping group. Each successful
	// pass removes a group, so this loop has at most eight productive passes.
	for {
		progress := false
		for k, blocks := range e.fec {
			sources := make([][]byte, int(k.count)+1)
			missing := 0
			for i := range sources {
				sources[i] = e.rx[k.first+uint32(i)]
				if sources[i] == nil {
					missing++
				}
			}
			if missing > len(blocks) {
				continue
			}
			decoded, err := RecoverFEC(k.first, sources, blocks)
			if errors.Is(err, ErrIncomplete) {
				continue
			}
			if err != nil {
				if incoming != nil && *incoming == k {
					return err
				}
				// A bad retained parity equation must not poison a valid later
				// ordinary source/retransmission. Drop that optional group.
				delete(e.fec, k)
				e.stats.Discarded++
				continue
			}
			for seq, data := range decoded {
				if err := e.receiveSource(seq, data, now, true); err != nil {
					return err
				}
			}
			delete(e.fec, k)
			progress = true
		}
		if !progress {
			break
		}
	}
	return nil
}
